#!/usr/bin/env python3
"""Protocol smoke gates for the feebox-bett core.

The migration moves twelve private protocol variants into this tree. Each one is
covered at a different level, and the level is the point of this script:

  local  - a package test runs here, with no server and no CI
  node   - needs a live relay; skipped unless its environment variable is set
  ci     - needs the full app build (Flutter + Rust helper), not covered here

Usage:
  python -X utf8 scripts/protocol_smoke.py           # source gates only
  python -X utf8 scripts/protocol_smoke.py --run     # plus the local test runs
  python -X utf8 scripts/protocol_smoke.py --run --verbose

GO111MODULE=on and a Go toolchain on PATH (or GO_BIN) are required for --run.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "core" / "Clash.Meta"
SS2 = ROOT / "core" / "sing-shadowsocks2"


class Protocol:
    def __init__(self, name, marker, areas, tests=(), module=KERNEL, live=None):
        self.name = name
        # The marker is matched case insensitively in the files under areas.
        self.marker = marker
        self.areas = areas
        # (package, module) pairs; an empty tuple means "source gate only".
        self.tests = tests
        self.module = module
        self.live = live


PROTOCOLS = [
    Protocol("x365", "x365", ["transport/x365", "adapter/outbound/x365.go", "common/convert"],
             tests=[("transport/x365", KERNEL), ("adapter", KERNEL)]),
    Protocol("x365-marker", "#x365", ["transport/vless", "adapter/outbound/vless.go"],
             tests=[("transport/vless", KERNEL)]),
    Protocol("miu", "miu", ["transport/miu", "adapter/outbound/miu.go"],
             tests=[("transport/miu", KERNEL)]),
    Protocol("ninja", "ninja", ["transport/ninja", "adapter/outbound/ninja.go"],
             tests=[("transport/ninja", KERNEL)]),
    Protocol("oppa", "oppa", ["transport/oppa", "adapter/outbound/oppa.go"],
             tests=[("transport/oppa", KERNEL)]),
    Protocol("fastup", "fastup", ["adapter", "transport/trojan"],
             tests=[("adapter", KERNEL)]),
    Protocol("shanlian", "shanlian", ["transport/anytls", "adapter/outbound/anytls.go"],
             tests=[("transport/anytls", KERNEL)]),
    Protocol("xhttp", "xhttp", ["adapter/outbound/xhttp.go", "transport/xhttpstream"],
             tests=[("transport/xhttpstream", KERNEL), ("adapter/outbound", KERNEL)]),
    Protocol("viewturbo", "viewturbo", ["../sing-shadowsocks2/cipher", "../viewturbo_link_contract_test.go"],
             tests=[("cipher", SS2)]),
    Protocol("blackstone-ss", "blackstone", ["../sing-shadowsocks2", "adapter/parser.go"],
             tests=[("shadowaead_2022", SS2), ("shadowstream", SS2), ("adapter", KERNEL)]),
    Protocol("oix-snell", "#oix", ["transport/snell", "adapter/outbound/snell.go"],
             tests=[("transport/snell", KERNEL)], live="MIHOMO_TEST_OIX_PSK"),
    Protocol("juzi", "juzi", ["transport/vless"],
             tests=[("transport/vless", KERNEL)]),
    Protocol("pure", "pure", ["transport/vless", "adapter/outbound/vless.go"],
             tests=[("transport/vless", KERNEL)]),
]

# The shipped library is built from core/, so its go.mod must carry both
# replaces; core/Clash.Meta carries them for kernel level runs.
REQUIRED_REPLACES = [
    (ROOT / "core" / "go.mod", "replace github.com/metacubex/sing-shadowsocks2 => ./sing-shadowsocks2"),
    (KERNEL / "go.mod", "replace github.com/metacubex/sing-shadowsocks2 => ../sing-shadowsocks2"),
    (ROOT / "core" / "go.mod", "replace github.com/metacubex/mihomo => ./Clash.Meta"),
]


def iter_files(area: Path):
    if area.is_file():
        yield area
        return
    for path in area.rglob("*"):
        if path.is_file() and path.suffix in {".go", ".mod"}:
            yield path


def marker_hits(protocol: Protocol):
    hits = []
    for raw in protocol.areas:
        area = (protocol.module / raw).resolve()
        if not area.exists():
            continue
        for path in iter_files(area):
            try:
                content = path.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            if protocol.marker.lower() in content:
                hits.append(path)
    return hits


def go_binary():
    env = os.environ.get("GO_BIN")
    if env:
        return env
    found = shutil.which("go")
    if not found:
        raise SystemExit("go toolchain not found: set GO_BIN or put go on PATH")
    return found


def run_tests(protocol: Protocol, verbose: bool) -> bool:
    go = go_binary()
    ok = True
    env = dict(os.environ)
    env.setdefault("GO111MODULE", "on")
    for pkg, module in protocol.tests:
        target = f"./{pkg}/" if pkg else "./"
        cmd = [go, "test", target, "-count=1"]
        if verbose:
            cmd.append("-v")
        try:
            result = subprocess.run(cmd, cwd=module, env=env, text=True, capture_output=True)
        except OSError as exc:
            print(f"  {protocol.name}: cannot run go: {exc}")
            return False
        if result.returncode != 0:
            ok = False
            print(f"  {protocol.name}: FAILED {target} in {module.name}")
            print("    " + (result.stdout + result.stderr).strip().replace("\n", "\n    "))
    return ok


def main() -> int:
    verbose = "--verbose" in sys.argv
    do_run = "--run" in sys.argv

    failures = []
    print(f"{'protocol':<16}{'source':<8}{'local tests':<14}{'live node'}")
    print("-" * 60)
    for protocol in PROTOCOLS:
        hits = marker_hits(protocol)
        source = "ok" if hits else "MISSING"
        if not hits:
            failures.append(f"{protocol.name}: implementation marker {protocol.marker!r} not found")
        local = "none" if not protocol.tests else ("skip" if not do_run else "run")
        live = protocol.live or "no"
        print(f"{protocol.name:<16}{source:<8}{local:<14}{live}")

    print()
    for path, needle in REQUIRED_REPLACES:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            content = ""
        status = "ok" if needle in content else "MISSING"
        if status == "MISSING":
            failures.append(f"{path}: missing {needle}")
        print(f"replace {path.relative_to(ROOT)!s:<28}{status}")

    if do_run:
        print()
        for protocol in PROTOCOLS:
            if not protocol.tests:
                continue
            if not run_tests(protocol, verbose):
                failures.append(f"{protocol.name}: local tests failed")

    if protocol_live_gated():
        print("\nlive node tests are skipped unless their env var is set: " + ", ".join(
            f"{p.name}={p.live}" for p in PROTOCOLS if p.live))

    if failures:
        print("\nfailures:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("\nall source gates passed")
    return 0


def protocol_live_gated() -> bool:
    return any(p.live for p in PROTOCOLS)


if __name__ == "__main__":
    raise SystemExit(main())

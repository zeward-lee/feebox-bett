#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""守候网络（SNTP）封端 -> Cattbox `sntp-eclipse` 节点生成器。

输入是**客户端封端档** `%AppData%/SNTP/SNTP/config.yaml`（不是订阅）：
节点自带 uuid(32 hex)、server-public-key(base64url 43)、mode、udp、sntp-report-scope。

做三件事，别的都不做：
1. 用**客户端指定的私有 DoH**（端点从源档 `dns.nameserver-policy` 读，三 IP 互为备份）
   把 server 域名解析成 IP —— 公网 DNS 对这批域名给的是诱饵/完全不相干的一组地址，
   `p-gtm-app.presntp.uk` 甚至 NXDOMAIN；每域名最多 2 次查询、进程内缓存、
   失败回退本地 DNS 并 WARN。
2. 输出 `type: sntp-eclipse` 节点，保留 uuid / server-public-key / mode /
   sntp-report-scope，`server` 写成解析到的 IP，原域名留在 `x-sntp-origin-server`。
3. 命名按统一口径：`<国旗> <缺才补的中文地区> <源名>`（站点名不进名字，重名补 #n）。

⚠ IP 会随 DoH 漂移（TTL 30s 级），`server` 只是快照：线路变了就**重跑本脚本**，
  不要手改 IP。

⚠ UDP：内核只实现 cmd=1 CONNECT（cmd=2 从未被服务端接受），所以节点一律写
  `udp: false`；源档的 `udp: true` 只是厂商标称。

用法:
  python -X utf8 sntp_extract.py --config "%AppData%/SNTP/SNTP/config.yaml" --out sntp_cattbox.yaml
  python -X utf8 sntp_extract.py --config ... --dry-run               # 不联网自检（注入假 IP）
  python -X utf8 sntp_extract.py --config ... --dry-run --resolve-doh  # 自检 + 真跑一次 DoH 解析
规格来源: scratch/flclash-ipc/report-sntp-eclipse.md §11/§13、report-sntp-dump-vs-sub.md §5。

仓库内这份是 sntp 线的独立实现（只带 sntp 需要的命名/分组工具，不引入其它机场的代码）。
日常维护位置仍是 `提取脚本/快捷提取.py` 的 `sntp` 线（`--from-raw` 喂封端 config.yaml）；
两处逻辑需同步，改一边请同步另一边。
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
import socket
import ssl
import struct
import sys
import time
from pathlib import Path
from typing import Any


def log(tag: str, msg: str) -> None:
    print(f"[{tag}] {msg}", flush=True)


# ============================================================ 节流 + token 缓存


# ============================================================ 统一命名工具 (六条私有协议线共用)
# 用户口径 (2026-11-17, 权威):
#   1. 站点名一律不进节点名 (`闪连 …` / `ViewTurbo …` / `FastUP …` / `HeySocks …` 这类前缀去掉)——
#      节点名是"给用户选线路用的", 站点名在每个档里恒等, 只会白占宽度、把地区挤出可视区;
#   2. 国旗 emoji 永远最前 (🇭🇰/🇸🇬/🇺🇸…), 判定不出地区用 🌐——先看国旗再读文字, 扫一眼就能定位, 不用逐字读;
#   3. 其次是运营商 (ViewTurbo 中继: 电信/联通/移动/广电/铁通), 再次是地区, 最后才是源原名/中继标识/序号;
#   4. 源里只有 IP:port、没有友好名的节点保留"地区 + 两位序号"(如 `🇺🇸 美国 01`), 不把 IP 塞进名字;
#   5. 重名补 `#2`、`#3`; 总长尽量 ≤ 24 (超了只告警, 不截断源信息)。
UNKNOWN_REGION = "未知"
UNKNOWN_FLAG = "🌐"
NAME_MAX_LEN = 24
SITE_NAME_TOKENS = ("闪连", "ViewTurbo", "FastUP", "HeySocks", "x365", "黑石")

# 中文地区 -> ISO-3166 两位码 (含源里出现过的别名)。覆盖现有 5 个私有档的全部地区 + 常见国家。
REGION_CC: dict[str, str] = {
    "香港": "hk", "台湾": "tw", "澳门": "mo", "中国": "cn", "蒙古": "mn",
    "日本": "jp", "韩国": "kr", "朝鲜": "kp",
    "新加坡": "sg", "马来西亚": "my", "泰国": "th", "越南": "vn", "菲律宾": "ph",
    "印度尼西亚": "id", "印尼": "id", "柬埔寨": "kh", "老挝": "la", "缅甸": "mm",
    "文莱": "bn", "孟加拉": "bd", "巴基斯坦": "pk", "斯里兰卡": "lk", "尼泊尔": "np",
    "印度": "in", "哈萨克斯坦": "kz", "乌兹别克斯坦": "uz",
    "阿联酋": "ae", "沙特阿拉伯": "sa", "沙特": "sa", "卡塔尔": "qa", "巴林": "bh",
    "科威特": "kw", "阿曼": "om", "约旦": "jo", "以色列": "il", "伊拉克": "iq",
    "伊朗": "ir", "土耳其": "tr", "塞浦路斯": "cy", "亚美尼亚": "am", "阿塞拜疆": "az",
    "格鲁吉亚": "ge",
    "美国": "us", "加拿大": "ca", "墨西哥": "mx", "巴西": "br", "阿根廷": "ar",
    "智利": "cl", "哥伦比亚": "co", "厄瓜多尔": "ec", "秘鲁": "pe", "玻利维亚": "bo",
    "巴拉圭": "py", "乌拉圭": "uy", "委内瑞拉": "ve", "巴拿马": "pa", "哥斯达黎加": "cr",
    "英国": "gb", "法国": "fr", "德国": "de", "荷兰": "nl", "比利时": "be",
    "卢森堡": "lu", "瑞士": "ch", "奥地利": "at", "意大利": "it", "西班牙": "es",
    "葡萄牙": "pt", "爱尔兰": "ie", "冰岛": "is", "丹麦": "dk", "挪威": "no",
    "瑞典": "se", "芬兰": "fi", "波兰": "pl", "捷克": "cz", "斯洛伐克": "sk",
    "匈牙利": "hu", "罗马尼亚": "ro", "保加利亚": "bg", "希腊": "gr", "克罗地亚": "hr",
    "斯洛文尼亚": "si", "塞尔维亚": "rs", "阿尔巴尼亚": "al", "马耳他": "mt",
    "摩尔多瓦": "md", "乌克兰": "ua", "白俄罗斯": "by", "俄罗斯": "ru",
    "立陶宛": "lt", "拉脱维亚": "lv", "爱沙尼亚": "ee",
    "澳大利亚": "au", "澳洲": "au", "新西兰": "nz", "南非": "za", "埃及": "eg",
    "摩洛哥": "ma", "尼日利亚": "ng", "肯尼亚": "ke", "坦桑尼亚": "tz",
}
# 反查用的规范中文名 (别名不参与; 顺序敏感, 先出现的为准)
_CANON_CN = {
    "香港": "香港", "台湾": "台湾", "澳门": "澳门", "中国": "中国", "蒙古": "蒙古",
    "日本": "日本", "韩国": "韩国", "新加坡": "新加坡", "马来西亚": "马来西亚",
    "泰国": "泰国", "越南": "越南", "菲律宾": "菲律宾", "印度尼西亚": "印度尼西亚",
    "柬埔寨": "柬埔寨", "老挝": "老挝", "缅甸": "缅甸", "文莱": "文莱", "孟加拉": "孟加拉",
    "巴基斯坦": "巴基斯坦", "斯里兰卡": "斯里兰卡", "尼泊尔": "尼泊尔", "印度": "印度",
    "哈萨克斯坦": "哈萨克斯坦", "乌兹别克斯坦": "乌兹别克斯坦", "阿联酋": "阿联酋",
    "沙特阿拉伯": "沙特阿拉伯", "卡塔尔": "卡塔尔", "巴林": "巴林", "科威特": "科威特",
    "阿曼": "阿曼", "约旦": "约旦", "以色列": "以色列", "伊拉克": "伊拉克", "伊朗": "伊朗",
    "土耳其": "土耳其", "塞浦路斯": "塞浦路斯", "亚美尼亚": "亚美尼亚",
    "阿塞拜疆": "阿塞拜疆", "格鲁吉亚": "格鲁吉亚", "美国": "美国", "加拿大": "加拿大",
    "墨西哥": "墨西哥", "巴西": "巴西", "阿根廷": "阿根廷", "智利": "智利",
    "哥伦比亚": "哥伦比亚", "厄瓜多尔": "厄瓜多尔", "秘鲁": "秘鲁", "玻利维亚": "玻利维亚",
    "巴拉圭": "巴拉圭", "乌拉圭": "乌拉圭", "委内瑞拉": "委内瑞拉", "巴拿马": "巴拿马",
    "哥斯达黎加": "哥斯达黎加", "英国": "英国", "法国": "法国", "德国": "德国",
    "荷兰": "荷兰", "比利时": "比利时", "卢森堡": "卢森堡", "瑞士": "瑞士",
    "奥地利": "奥地利", "意大利": "意大利", "西班牙": "西班牙", "葡萄牙": "葡萄牙",
    "爱尔兰": "爱尔兰", "冰岛": "冰岛", "丹麦": "丹麦", "挪威": "挪威", "瑞典": "瑞典",
    "芬兰": "芬兰", "波兰": "波兰", "捷克": "捷克", "斯洛伐克": "斯洛伐克",
    "匈牙利": "匈牙利", "罗马尼亚": "罗马尼亚", "保加利亚": "保加利亚", "希腊": "希腊",
    "克罗地亚": "克罗地亚", "斯洛文尼亚": "斯洛文尼亚", "塞尔维亚": "塞尔维亚",
    "阿尔巴尼亚": "阿尔巴尼亚", "马耳他": "马耳他", "摩尔多瓦": "摩尔多瓦",
    "乌克兰": "乌克兰", "白俄罗斯": "白俄罗斯", "俄罗斯": "俄罗斯", "立陶宛": "立陶宛",
    "拉脱维亚": "拉脱维亚", "爱沙尼亚": "爱沙尼亚", "澳大利亚": "澳大利亚",
    "新西兰": "新西兰", "南非": "南非", "埃及": "埃及", "摩洛哥": "摩洛哥",
    "尼日利亚": "尼日利亚", "肯尼亚": "肯尼亚", "坦桑尼亚": "坦桑尼亚",
}


def _flag_from_cc(cc: str) -> str:
    """两位国家码 -> 区域旗帜 emoji; 非法码返回空串。"""
    c = str(cc or "").strip().lower()
    if len(c) != 2 or not c.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("a")) for ch in c)


def _cc_of_flag(flag: str) -> str:
    """旗帜 emoji -> 两位国家码; 不是旗帜返回空串。"""
    f = str(flag or "")
    if len(f) == 2 and all(0x1F1E6 <= ord(ch) <= 0x1F1FF for ch in f):
        return "".join(chr(ord(ch) - 0x1F1E6 + ord("a")) for ch in f)
    return ""


REGION_FLAG: dict[str, str] = {
    cn: _flag_from_cc(cc) for cn, cc in REGION_CC.items() if _flag_from_cc(cc)
}
# cc -> 规范中文地区 (国旗反查地区名用)
REGION_CN_BY_CC: dict[str, str] = {
    REGION_CC[cn]: cn for cn in _CANON_CN
}
_REGION_MATCH_KEYS = sorted(set(REGION_FLAG) | set(REGION_CC), key=len, reverse=True)


def _leading_flag(text: str) -> str:
    """取字符串开头的旗帜 emoji / 🌐 (统一命名下的所有节点名都以它开头); 没有返回空串。"""
    t = str(text or "")
    if t.startswith(UNKNOWN_FLAG):
        return UNKNOWN_FLAG
    if len(t) >= 2 and all(0x1F1E6 <= ord(ch) <= 0x1F1FF for ch in t[:2]):
        return t[:2]
    return ""


def _flag_of_region(value: str, *, fallback: str = UNKNOWN_FLAG) -> str:
    """地区 (中文或两位码) / 含地区关键词的任意字符串 -> 国旗 emoji。

    顺序: 已带旗帜 -> 两位国家码 -> 中文精确匹配 -> 中文最长子串匹配 -> `fallback`。
    """
    s = str(value or "").strip()
    if not s:
        return fallback
    head = _leading_flag(s)
    if head:
        return head
    if len(s) == 2 and s.isascii() and s.isalpha():
        return _flag_from_cc(s) or fallback
    if s in REGION_FLAG:
        return REGION_FLAG[s]
    for kw in _REGION_MATCH_KEYS:
        if kw in s:
            return REGION_FLAG.get(kw) or fallback
    return fallback


def _region_of_name(name: str) -> str:
    """从节点名里取出地区 (源原名里已带的地区, 如 `香港 A区#007` -> 香港); 取不到返回空串。"""
    s = str(name or "").strip()
    if not s:
        return ""
    for kw in _REGION_MATCH_KEYS:
        if kw in s:
            return kw
    return ""


def _apply_display_name(name: str = "", *, region: str = "", carrier: str = "",
                        seq: int | None = None, relay_label: str = "",
                        region_pos: str = "before",
                        fallback_flag: str = UNKNOWN_FLAG) -> str:
    """统一拼节点显示名: `<flag> <运营商?> <地区?> <原名|中继标识|序号>`。

    - `region`: 地区 (中文或两位码); 只在 `name` 里没有该地区时才单独补一段, 免得重复。
    - `carrier`: 运营商 (ViewTurbo relay 的 电信/联通/移动/广电/铁通), 放国旗之后、地区之前。
    - `seq`: 两位序号 (01/02…); 只有源里没有友好名或同区多条时才用。
    - `relay_label`: 链式/中继入口的源标识 (如 `tx01`), 主体写 `中继 <标识>`, 地区只体现成国旗。
    - `region_pos`: `before` (默认, 地区在源原名前) / `after` (主体是"专线"这类类别词时, 地区跟在后面)。
    - `fallback_flag=""`: 判不出地区时不补国旗 (仅用于锁死历史口径的冻结档)。
    """
    core = str(name or "").strip()
    rgn = str(region or "").strip()
    # 源名已自带国旗/🌐 -> 摘下来当国旗用, 避免拼出两个 (黑石/HeySocks 的源名本来就带旗)
    head_flag = _leading_flag(core) if not relay_label else ""
    if head_flag:
        core = core[len(head_flag):].strip()
    if relay_label:
        core = f"中继 {str(relay_label).strip()}"
    flag = head_flag or _flag_of_region(rgn or core, fallback=fallback_flag)
    region_part = rgn if (rgn and not relay_label and rgn not in core) else ""
    parts: list[str] = []
    if flag:
        parts.append(flag)
    if carrier:
        parts.append(str(carrier).strip())
    if region_part:
        if region_pos == "after" and core:
            parts.extend([core, region_part])
        else:
            parts.extend([region_part, core])
    elif core:
        parts.append(core)
    if seq is not None:
        parts.append(f"{int(seq):02d}")
    out: list[str] = []
    for part in parts:
        if part and (not out or out[-1] != part):
            out.append(part)
    return " ".join(out).strip()


def _warn_name_length(proxies: list[dict[str, Any]], label: str) -> None:
    """总长告警: 口径要求尽量 ≤ NAME_MAX_LEN, 超长只提示 (不截断源信息, 免得丢可辨识度)。"""
    longs = [p["name"] for p in proxies if len(str(p["name"])) > NAME_MAX_LEN]
    if longs:
        log(label, f"WARN {len(longs)} 个节点名超过 {NAME_MAX_LEN} 字符 (未截断): {longs[:3]}")


def build_region_groups(proxies: list[dict[str, Any]], *,
                        group_type: str = "select") -> list[dict[str, Any]]:
    """按地区分组: 每个地区一个 select 组, 成员是该地区全部节点 (保持源顺序)。

    - 组名 `<国旗> <地区>` (如 `🇭🇰 香港`); 与节点名或既有组名撞名时补 ` 地区` 后缀
      —— Clash/Mihomo 里组名与节点名同命名空间, 同名会让引用产生歧义。
    - 地区优先取节点名里自带的地区; 取不到时用名字前缀旗帜反查; 都没有归 `🌐 未知`。
    - 只新增组, 不改 `🚀 节点选择` / `♻️ 自动选择` 语义, 也不改 rules。
    """
    taken = {str(p["name"]) for p in proxies}
    buckets: dict[str, list[str]] = {}
    for p in proxies:
        name = str(p["name"])
        flag = _leading_flag(name)
        region = _region_of_name(name)
        if not region and flag:
            region = REGION_CN_BY_CC.get(_cc_of_flag(flag), "")
        if not region:
            region = UNKNOWN_REGION
            flag = ""
        if not flag or flag == UNKNOWN_FLAG:
            flag = _flag_of_region(region) if region != UNKNOWN_REGION else UNKNOWN_FLAG
        key = f"{flag} {region}"
        while key in taken:
            key += " 地区"
        buckets.setdefault(key, []).append(name)
    return [
        {"name": key, "type": group_type, "proxies": members}
        for key, members in buckets.items()
    ]


_NAME_FLAG_RE = re.compile(r"^(?:[\U0001F1E6-\U0001F1FF]{2}|🌐) ")
_IP_PORT_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?")


def naming_checks(proxies: list[dict[str, Any]], label: str,
                  *, max_len: int = NAME_MAX_LEN) -> list[tuple[str, Any, bool]]:
    """命名/分组不变量 (--dry-run 各线共用): 六条线输出必须同时满足用户口径。

    - 名字唯一、以国旗或 🌐 开头、不含站点名、不含 IP:端口、长度 ≤ max_len;
    - 地区组: 每个节点恰好落在一个组里, 组名唯一且不与节点名撞名, 组名也以国旗开头。
    """
    names = [str(p["name"]) for p in proxies]
    bad_flag = [n for n in names if not _NAME_FLAG_RE.match(n)]
    bad_site = [n for n in names if any(tok in n for tok in SITE_NAME_TOKENS)]
    bad_ip = [n for n in names if _IP_PORT_RE.search(n)]
    dups = sorted({n for n in names if names.count(n) > 1})
    longs = [n for n in names if len(n) > max_len]
    groups = build_region_groups(proxies)
    group_names = [g["name"] for g in groups]
    members = [m for g in groups for m in g["proxies"]]
    covered = len(members) == len(names) and set(members) == set(names)
    group_dup = sorted({n for n in group_names if group_names.count(n) > 1})
    group_clash = [n for n in group_names if n in set(names) or n in ("🚀 节点选择", "♻️ 自动选择")]
    group_bad_flag = [n for n in group_names if not _NAME_FLAG_RE.match(n)]
    return [
        (f"{label}: 节点名唯一", f"{len(set(names))}/{len(names)}", not dups),
        (f"{label}: 节点名以国旗/🌐 开头", bad_flag[:3] or "全部合规", not bad_flag),
        (f"{label}: 节点名不含站点名", bad_site[:3] or "无", not bad_site),
        (f"{label}: 节点名不含 IP:端口", bad_ip[:3] or "无", not bad_ip),
        (f"{label}: 节点名长度 ≤ {max_len}", max((len(n) for n in names), default=0),
         not longs),
        (f"{label}: 地区组覆盖全部节点 (共 {len(groups)} 组)",
         f"{len(members)}/{len(names)}", covered),
        (f"{label}: 地区组名唯一且不与节点名撞名",
         group_dup[:3] or group_clash[:3] or "无", not group_dup and not group_clash),
        (f"{label}: 地区组名以国旗/🌐 开头", group_bad_flag[:3] or "全部合规",
         not group_bad_flag),
    ]


def _profile(proxies: list[dict[str, Any]]) -> dict[str, Any]:
    """档骨架: 节点 + 两个总入口组 + 按地区分组的 select 组 + 最小规则。

    地区组排在总入口组之后 (用户先点"节点选择/自动选择", 想按地区挑再看后面);
    `🚀 节点选择` / `♻️ 自动选择` 的成员与 rules 保持原语义, 地区组只做"新增不影响"。
    """
    names = [p["name"] for p in proxies]
    return {
        "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select", "proxies": ["♻️ 自动选择"] + names + ["DIRECT"]},
            {"name": "♻️ 自动选择", "type": "url-test", "proxies": names,
             "url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50},
        ] + build_region_groups(proxies),
        "rules": ["DOMAIN-SUFFIX,cn,DIRECT", "GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"],
    }


def write_yaml(cfg: dict[str, Any], path: Path) -> None:
    import yaml

    with path.open("w", encoding="utf-8", newline="\n") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False, default_flow_style=False, width=4096)
    back = yaml.safe_load(path.read_text(encoding="utf-8"))
    if len(back.get("proxies") or []) != len(cfg["proxies"]):
        raise RuntimeError("YAML 往返校验失败: 节点数不一致")


# ============================================================ sntp 线（守候网络封端 config.yaml）
# 输入是**封端**（客户端自己的 config.yaml），不是订阅：节点自带 uuid(32 hex)、
# server-public-key(base64url 43)、mode、udp、sntp-report-scope，且 server 是厂商域名。
# 规格: scratch/flclash-ipc/report-sntp-eclipse.md §11；节点字段与解析口径见
#       report-sntp-dump-vs-sub.md §5。
#
# 三个必须照做的点:
#   1. server 一律换成**指定 DoH** 解析出来的 IP —— 厂商域名在公网 DNS 下会拿到诱饵/
#      完全不同的一组 IP（p-gtm-app.presntp.uk 甚至 NXDOMAIN），只有客户端那条私有
#      DoH 答得对；同时把原域名写进 `x-sntp-origin-server` 备查。
#   2. DoH 端点从源档自己的 `dns.nameserver-policy` / `dns.proxy-server-nameserver`
#      里读（同路径不同 IP 互为备份），读不到才用内置三 IP + 内置 path。
#   3. IP 会随 DoH 漂移（TTL 30s），所以 `server` 是快照：换线/漂移后要重跑生成器。
#
# UDP: 内核只实现了 cmd=1 CONNECT，cmd=2 从未被服务端接受过（报告 §13.5），
#      因此这里统一写 `udp: false`（内核 SNTPEclipse.SupportUOT() == false），
#      源档的 udp:true 只作为“厂商标称”保留在 dry-run 统计里，不写进节点。
SNTP_TYPE = "sntp-eclipse"
SNTP_MODE = "sntp-eclipse-v3-native-1"
SNTP_DOH_PORT = 2443
SNTP_MAX_QUERY_PER_DOMAIN = 2
SNTP_DOH_TIMEOUT = 6.0
_SNTP_DOH_CACHE: dict[str, list[str]] = {}
_SNTP_LOCAL_CACHE: dict[str, list[str]] = {}


def _sntp_doh_endpoints(cfg: dict[str, Any]) -> list[tuple[str, int, str]]:
    """从源 config.yaml 的 dns 段取 DoH 端点 [(ip, port, path), ...]。

    客户端把封端用到的域名全写进 nameserver-policy，值就是这条私有 DoH；
    proxy-server-nameserver 里通常还有一份同样的列表。解析不到的域名走默认 DoH，
    那不是我们要的口径。
    """
    found: list[tuple[str, int, str]] = []
    dns = (cfg or {}).get("dns") or {}
    # nameserver-policy 是权威来源: 客户端只为封端域名写死了这条私有 DoH。
    # nameserver/默认 DoH(doh.pub、dns.google…) 会给出完全不同的 IP, 绝不能混进来,
    # 所以 policy 有值就只用 policy; 没有才退 proxy-server-nameserver。
    candidates: list[str] = []
    policy = dns.get("nameserver-policy") or {}
    if isinstance(policy, dict):
        for values in policy.values():
            candidates.extend(values if isinstance(values, list) else [values])
    if not candidates:
        for key in ("proxy-server-nameserver",):
            values = dns.get(key) or []
            candidates.extend(values if isinstance(values, list) else [values])
    for raw in candidates:
        text = str(raw or "").strip()
        if not text.startswith("https://") or "/dns-query" not in text:
            continue
        rest = text[len("https://"):]
        hostport, _, path = rest.partition("/")
        path = "/" + path
        host, _, port = hostport.partition(":")
        try:
            port_num = int(port) if port else SNTP_DOH_PORT
        except ValueError:
            port_num = SNTP_DOH_PORT
        item = (host, port_num, path)
        if item not in found:
            found.append(item)
    if not found:
        # 私有 DoH 的 path 里带客户端标识，不内置；只能从源档读。
        raise RuntimeError("源档 dns.nameserver-policy 里没有 https://.../dns-query/... 端点, "
                           "无法按客户端口径解析封端域名")
    return found


def _sntp_dns_query_message(host: str, qid: int = 0x5A17) -> bytes:
    parts = b"".join(bytes([len(p)]) + p.encode("ascii") for p in host.split(".") if p)
    return (struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + parts + b"\x00"
            + struct.pack(">HH", 1, 1))


def _sntp_dns_parse_a(resp: bytes) -> list[str]:
    """极简 DNS A 记录解析（只认压缩指针 + type 1），够 DoH 用。"""
    qid, flags, qd, an, _ns, _ar = struct.unpack_from(">HHHHHH", resp, 0)
    rcode = flags & 0xF
    if rcode != 0:
        raise RuntimeError(f"DoH rcode={rcode}")
    off = 12
    for _ in range(qd):
        while resp[off]:
            if resp[off] & 0xC0 == 0xC0:
                off += 2
                break
            off += resp[off] + 1
        else:
            off += 1
        off += 4
    out: list[str] = []
    for _ in range(an):
        if resp[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while resp[off]:
                off += resp[off] + 1
            off += 1
        rtype, _rclass, _ttl, rdlen = struct.unpack_from(">HHIH", resp, off)
        off += 10
        rdata = resp[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:
            out.append(socket.inet_ntoa(rdata))
    return out


def _sntp_doh_query(host: str, endpoint: tuple[str, int, str],
                    timeout: float = SNTP_DOH_TIMEOUT) -> list[str]:
    """一次 DoH 查询（TLS 不校验证书，与客户端一致）。直连被测目标，不走 7801。"""
    ip, port, path = endpoint
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = _sntp_dns_query_message(host)
    sock = socket.create_connection((ip, port), timeout)
    try:
        tls = ctx.wrap_socket(sock, server_hostname=None)
        try:
            req = (b"POST " + path.encode() + b" HTTP/1.1\r\nHost: " + ip.encode() +
                   b"\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message"
                   b"\r\nContent-Length: " + str(len(body)).encode() +
                   b"\r\nConnection: close\r\n\r\n" + body)
            tls.sendall(req)
            chunks = []
            while True:
                chunk = tls.recv(65535)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            tls.close()
    finally:
        sock.close()
    data = b"".join(chunks)
    _head, _, payload = data.partition(b"\r\n\r\n")
    if not payload:
        raise RuntimeError("DoH 响应为空")
    return _sntp_dns_parse_a(payload)


def _sntp_local_resolve(host: str) -> list[str]:
    """本地 DNS 兜底（仅当指定 DoH 两次都失败；结果会 WARN）。"""
    if host in _SNTP_LOCAL_CACHE:
        return _SNTP_LOCAL_CACHE[host]
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        ips = []
    _SNTP_LOCAL_CACHE[host] = ips
    return ips


class SntpResolver:
    """域名 -> IP，口径：指定 DoH 优先，每域名最多 2 次查询，进程内缓存，失败回退本地 DNS。"""

    def __init__(self, endpoints: list[tuple[str, int, str]], *, doh_enabled: bool = True,
                 local_fallback: list[dict[str, str]] | None = None,
                 fake_map: bool = False) -> None:
        self.endpoints = list(endpoints)
        self.doh_enabled = doh_enabled
        self.local_fallback = local_fallback or []   # 注入用（dry-run / 单测）
        # dry-run 不联网时用确定性假 IP（198.51.100.0/24 文档网段），只校验字段/命名
        self.fake_map = fake_map
        self.stats = {"domains": 0, "doh_queries": 0, "doh_hits": 0, "cache_hits": 0,
                      "local_fallbacks": 0, "failures": 0, "sources": {}}
        self._cache: dict[str, tuple[str, str]] = {}

    def resolve(self, host: str) -> tuple[str, str]:
        """返回 (ip, source)，source ∈ {doh, cache, local, injected, unresolved}。"""
        if not host:
            return "", "unresolved"
        if host in self._cache:
            self.stats["cache_hits"] += 1
            return self._cache[host]
        self.stats["domains"] += 1

        if self.fake_map:
            ip = "198.51.100.%d" % (len(self._cache) + 10)
            self._cache[host] = (ip, "fake")
            self.stats["sources"][host] = "fake"
            return self._cache[host]

        if self.local_fallback:
            for item in self.local_fallback:
                if item.get("domain") == host:
                    self._cache[host] = (item["ip"], "injected")
                    self.stats["sources"][host] = "injected"
                    return self._cache[host]

        if self.doh_enabled:
            for attempt in range(SNTP_MAX_QUERY_PER_DOMAIN):
                endpoint = self.endpoints[attempt % len(self.endpoints)]
                self.stats["doh_queries"] += 1
                try:
                    ips = _sntp_doh_query(host, endpoint)
                except Exception as e:  # noqa: BLE001 - DoH 失败一律回退, 但要 WARN
                    log("sntp", f"WARN DoH {endpoint[0]}:{endpoint[1]} 查询 {host} 失败 "
                                f"(第 {attempt + 1}/{SNTP_MAX_QUERY_PER_DOMAIN} 次): {e}")
                    continue
                if ips:
                    self.stats["doh_hits"] += 1
                    self._cache[host] = (ips[0], "doh")
                    self.stats["sources"][host] = f"doh({len(ips)} ips)"
                    return self._cache[host]
                log("sntp", f"WARN DoH {host} 返回空 A 记录")

        ips = _sntp_local_resolve(host)
        if ips:
            self.stats["local_fallbacks"] += 1
            self.stats["sources"][host] = "local"
            log("sntp", f"WARN {host} 指定 DoH 未解出, 回退本地 DNS: {ips[0]} "
                        f"(该 IP 可能不是落地线路, 仅供兜底)")
            self._cache[host] = (ips[0], "local")
            return self._cache[host]

        self.stats["failures"] += 1
        self.stats["sources"][host] = "unresolved"
        # 负结果同样入缓存: 一个域名最多查 2 次, 不给服务端制造重试风暴
        self._cache[host] = ("", "unresolved")
        return "", "unresolved"


def _sntp_region_of(name: str) -> str:
    """源名自带国旗 -> 中文地区；只有 `HK01` 这种缩写时靠国旗反查，不猜。"""
    flag = _leading_flag(name)
    if not flag:
        return ""
    cc = _cc_of_flag(flag)
    return REGION_CN_BY_CC.get(cc, "")


def _sntp_node_name(source_name: str, region: str, used: set[str]) -> str:
    """统一命名: 国旗前置 + 缺地区才补 + 保留源名；重名补 #n。"""
    name = _apply_display_name(source_name, region=region or _sntp_region_of(source_name))
    if not name:
        name = _apply_display_name("", region=region, seq=len(used) + 1)
    if name in used:
        i = 2
        while f"{name} #{i}" in used:
            i += 1
        name = f"{name} #{i}"
    used.add(name)
    return name


def build_sntp_proxies(cfg: dict[str, Any], resolver: SntpResolver | None = None, *,
                       local_fallback: list[dict[str, str]] | None = None
                       ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """封端 config.yaml -> Cattbox 节点列表 + 解析统计。"""
    raw_nodes = [p for p in (cfg.get("proxies") or []) if str(p.get("type", "")).strip() == SNTP_TYPE]
    stats: dict[str, Any] = {"source_nodes": len(raw_nodes), "skipped": [], "domains": {},
                             "udp_true_in_source": 0, "deduped": 0}
    if resolver is None:
        resolver = SntpResolver(_sntp_doh_endpoints(cfg), local_fallback=local_fallback)

    proxies: list[dict[str, Any]] = []
    used_names: set[str] = set()
    seen: dict[tuple[str, int], str] = {}

    for raw in raw_nodes:
        name = str(raw.get("name") or "").strip()
        host = str(raw.get("server") or "").strip()
        port = raw.get("port")
        uuid_hex = str(raw.get("uuid") or "").strip().lower()
        spub = str(raw.get("server-public-key") or "").strip()
        mode = str(raw.get("mode") or "").strip()
        scope = str(raw.get("sntp-report-scope") or "").strip()
        try:
            port_num = int(port)
        except (TypeError, ValueError):
            stats["skipped"].append((name, f"port 非法: {port!r}"))
            continue
        if len(uuid_hex) != 32 or any(c not in "0123456789abcdef" for c in uuid_hex):
            stats["skipped"].append((name, "uuid 不是 32 hex"))
            continue
        try:
            if len(base64.urlsafe_b64decode(spub + "=")) != 32:
                raise ValueError("长度不是 32")
        except Exception:
            stats["skipped"].append((name, "server-public-key 不是 43 位 base64url(32B)"))
            continue
        if mode and mode != SNTP_MODE:
            stats["skipped"].append((name, f"mode 未知: {mode}"))
            continue
        if not host:
            stats["skipped"].append((name, "server 为空"))
            continue
        if raw.get("udp") is True:
            stats["udp_true_in_source"] += 1

        try:
            ip = ipaddress.ip_address(host)
            server_ip, source = str(ip), "literal"
        except ValueError:
            server_ip, source = resolver.resolve(host)
        if not server_ip:
            stats["skipped"].append((name, f"域名解析失败: {host}"))
            continue
        if host not in stats["domains"]:
            stats["domains"][host] = {"ip": server_ip, "source": source}

        key = (server_ip, port_num)
        if key in seen:
            stats["deduped"] += 1
            continue
        seen[key] = name

        node: dict[str, Any] = {
            "name": _sntp_node_name(name, _sntp_region_of(name), used_names),
            "type": SNTP_TYPE,
            "server": server_ip,
            "port": port_num,
            "uuid": uuid_hex,
            "server-public-key": spub,
            "mode": mode or SNTP_MODE,
            # 内核只实现了 CONNECT(cmd=1)，UDP 未实现 -> 必须写 false，否则 UDP 会被黑洞
            "udp": False,
            # 原域名备查（IP 是 DoH 快照，会漂移）
            "x-sntp-origin-server": host,
        }
        if scope:
            node["sntp-report-scope"] = scope
        proxies.append(node)

    stats["resolver"] = resolver.stats
    return proxies, stats


def _sntp_synthetic_fixture() -> dict[str, Any]:
    """dry-run 用的合成封端档（无真实凭证，字段形态与源档一致）。"""
    def node(name: str, host: str, port: int, tag: str) -> dict[str, Any]:
        return {"name": name, "type": SNTP_TYPE, "mode": SNTP_MODE, "server": host,
                "port": port, "udp": True,
                "uuid": (tag * 8)[:32],
                "server-public-key": base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="),
                "sntp-report-scope": "ab" * 24}
    return {
        "proxies": [
            node("🇭🇰 HK01-S1 0.20x", "p-s1-hk.example", 17001, "c9d1"),
            node("🇭🇰 HK02-S1 0.20x", "p-s1-hk.example", 17002, "c9d1"),
            node("🇯🇵 JP01-GTM", "p-gtm-app.example", 17019, "c9d1"),
            node("🇸🇬 SG01-S1 0.20x", "p-s1-sg.example", 17013, "c9d1"),
            {"name": "坏节点-无uuid", "type": SNTP_TYPE, "server": "p-s1-sg.example",
             "port": 17014, "uuid": "short", "server-public-key": "x" * 43, "mode": SNTP_MODE},
        ],
        "dns": {"nameserver-policy": {
            "p-s1-hk.example": ["https://172.237.2.224:2443/dns-query/df943855-ff94-4148-8439-020928402134",
                                "https://120.25.121.157:2443/dns-query/df943855-ff94-4148-8439-020928402134"]}},
    }


def run_sntp(config_path: Path, out: Path, save_raw: bool = False,
             resolver: SntpResolver | None = None) -> int:
    import yaml

    cfg = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(cfg, dict):
        raise RuntimeError(f"封端档不是 YAML 映射: {config_path}")
    proxies, stats = build_sntp_proxies(cfg, resolver)
    if not proxies:
        raise RuntimeError("封端档里没有可用的 sntp-eclipse 节点")
    _warn_name_length(proxies, "sntp")
    write_yaml(_profile(proxies), out)
    if save_raw:
        raw_path = out.with_name(out.stem + "_raw_dump.json")
        raw_path.write_text(json.dumps({"nodes": proxies, "stats": stats},
                                       ensure_ascii=False, indent=1), encoding="utf-8")
        log("sntp", f"原始节点/统计 -> {raw_path}")
    log("sntp", f"节点 {len(proxies)} 个 (源 {stats['source_nodes']}, 跳过 {len(stats['skipped'])}, "
                f"去重 {stats['deduped']})")
    log("sntp", f"DoH: 域名 {stats['resolver']['domains']} 次查询 {stats['resolver']['doh_queries']} "
                f"命中 {stats['resolver']['doh_hits']} 缓存 {stats['resolver']['cache_hits']} "
                f"本地回退 {stats['resolver']['local_fallbacks']} 失败 {stats['resolver']['failures']}")
    for name, reason in stats["skipped"][:5]:
        log("sntp", f"WARN 跳过 {name}: {reason}")
    return len(proxies)


def sntp_dry_run(config_path: Path | None, resolve_doh: bool = False) -> int:
    """离线自检：真档(可选真解析) / 合成档，校验字段、命名、解析统计。"""
    log("sntp", "===== sntp 线离线自检 (dry-run) =====")
    checks: list[tuple[str, Any, bool]] = []

    if config_path is not None:
        import yaml
        cfg = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        endpoints = _sntp_doh_endpoints(cfg)
        log("sntp", f"源档 {config_path}; DoH 端点 {[(e[0], e[1]) for e in endpoints]}")
        if resolve_doh:
            resolver = SntpResolver(endpoints)
        else:
            # 不联网: 用固定 IP 注入, 只验证字段/命名/统计结构
            # 不联网: 确定性假 IP，只验证字段/命名/统计结构
            resolver = SntpResolver(endpoints, doh_enabled=False, fake_map=True)
        proxies, stats = build_sntp_proxies(cfg, resolver)
        label = "真档"
        checks.append((f"{label}: 节点数 = 源档 sntp-eclipse 数", f"{len(proxies)}/{stats['source_nodes']}",
                       len(proxies) == stats["source_nodes"] and len(proxies) > 0))
    else:
        cfg = _sntp_synthetic_fixture()
        resolver = SntpResolver(_sntp_doh_endpoints(cfg), doh_enabled=False, fake_map=True)
        proxies, stats = build_sntp_proxies(cfg, resolver)
        label = "合成档"
        checks.append((f"{label}: 合法节点 4 个 / 坏节点被跳过", f"{len(proxies)}/{len(stats['skipped'])}",
                       len(proxies) == 4 and len(stats["skipped"]) == 1))

    names = [p["name"] for p in proxies]
    checks += [
        (f"{label}: type 全部 sntp-eclipse", sorted({p["type"] for p in proxies}),
         {p["type"] for p in proxies} == {SNTP_TYPE}),
        (f"{label}: mode 原样保留", sorted({p["mode"] for p in proxies}),
         {p["mode"] for p in proxies} == {SNTP_MODE}),
        (f"{label}: uuid 32 hex / server-public-key 43 位",
         (len(proxies[0]["uuid"]), len(proxies[0]["server-public-key"])),
         all(len(p["uuid"]) == 32 and len(p["server-public-key"]) == 43 for p in proxies)),
        (f"{label}: server 全部是解析出的 IP (无域名残留)",
         [p["server"] for p in proxies if not _is_ip(p["server"])][:3] or "全部为 IP",
         all(_is_ip(p["server"]) for p in proxies)),
        (f"{label}: 原域名写进 x-sntp-origin-server",
         [p.get("x-sntp-origin-server") for p in proxies][:3],
         all(p.get("x-sntp-origin-server") for p in proxies)),
        (f"{label}: udp 一律 false (内核只实现 CONNECT)",
         sorted({p["udp"] for p in proxies}), all(p["udp"] is False for p in proxies)),
        (f"{label}: sntp-report-scope 原样保留", len(proxies[0].get("sntp-report-scope", "")),
         all(len(p.get("sntp-report-scope", "")) == 48 for p in proxies)),
        (f"{label}: 节点名以国旗/🌐 开头且唯一", names[:2],
         all(_NAME_FLAG_RE.match(n) for n in names) and len(set(names)) == len(names)),
        (f"{label}: 名字保留源名 (HK01-S1 这类标识在)", [n for n in names if "HK01" in n],
         any("HK01" in n for n in names)),
        (f"{label}: 名字里没有站点名 SNTP/守候", [n for n in names if "SNTP" in n or "守候" in n],
         not any("SNTP" in n or "守候" in n for n in names)),
        (f"{label}: 地区已补到名字里 (源名只有 HK01 这类缩写)", names[0],
         "香港" in names[0]),
        (f"{label}: DoH 解析统计可用",
         f"域名 {stats['resolver']['domains']} 查询 {stats['resolver']['doh_queries']} "
         f"假解 {len([s for s in stats['resolver']['sources'].values() if s in ('fake', 'injected')])}",
         stats["resolver"]["domains"] == len(stats["domains"])),
        (f"{label}: 同域名只解一次 (缓存命中)", stats["resolver"]["cache_hits"],
         stats["resolver"]["cache_hits"] >= 1),
    ]
    checks += naming_checks(proxies, label)

    ok = True
    for desc, value, passed in checks:
        log("sntp", f"[{'PASS' if passed else 'FAIL'}] {desc} -> {value}")
        ok = ok and bool(passed)
    log("sntp", f"dry-run {'全绿' if ok else '有失败项'} ({len(checks)} 项)")
    return 0 if ok else 1


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(str(text).strip())
        return True
    except ValueError:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description="守候网络(SNTP) 封端 config.yaml -> Cattbox sntp-eclipse 节点")
    ap.add_argument("--config", required=True, help="封端档路径 (%AppData%/SNTP/SNTP/config.yaml)")
    ap.add_argument("--out", default="sntp_cattbox.yaml", help="产物 YAML（默认 ./sntp_cattbox.yaml）")
    ap.add_argument("--dry-run", action="store_true", help="离线自检, 不发包")
    ap.add_argument("--resolve-doh", action="store_true",
                    help="配合 --dry-run: 真跑一次指定 DoH 解析并打印统计")
    ap.add_argument("--save-raw", action="store_true", help="额外保存节点/统计 JSON")
    args = ap.parse_args()
    config_path = Path(args.config).expanduser()
    if not config_path.exists():
        log("sntp", f"封端档不存在: {config_path}")
        return 2
    if args.dry_run:
        return sntp_dry_run(config_path, resolve_doh=args.resolve_doh)
    out = Path(args.out).expanduser()
    try:
        count = run_sntp(config_path, out, args.save_raw)
    except Exception as e:  # noqa: BLE001 - 单一出口
        log("fail", f"{type(e).__name__}: {e}")
        return 1
    log("done", f"sntp: {count} 节点 -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

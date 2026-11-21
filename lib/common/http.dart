import 'dart:io';

import 'package:bett_box/state.dart';

class BettboxHttpOverrides extends HttpOverrides {
  static bool _isLoopback(String host) {
    if (host.isEmpty || host.toLowerCase() == 'localhost') return true;
    return InternetAddress.tryParse(host)?.isLoopback ?? false;
  }

  /// 私有/内网地址判定。
  ///
  /// 内网地址必须直连，不能交给内核代理：否则请求会被内核按规则转给代理节点，
  /// 节点侧无法回源到用户局域网，最终表现为 502 / 订阅导入失败（Android 实测：
  /// 更新 http://192.168.2.1/sub/*.yaml 时报「导入失败」）。
  ///
  /// 同时供局域网权限提示（`LocalNetworkPermission`）判断失败目标是否真的在私网，
  /// 避免公网订阅超时被误诊为 ACCESS_LOCAL_NETWORK 未授予。
  static bool isPrivateHost(String host) {
    // 去掉 IPv6 方括号形式，兼容 `[::1]` 这类 host。
    var lower = host.toLowerCase().trim();
    if (lower.startsWith('[') && lower.endsWith(']')) {
      lower = lower.substring(1, lower.length - 1);
    }
    if (lower.isEmpty) return true;
    // 去掉绝对域名形式的末尾点，如 `nas.local.`。
    if (lower.endsWith('.')) lower = lower.substring(0, lower.length - 1);

    // 不带点的单段主机名（router、nas 等）只可能是局域网内目标。
    if (!lower.contains('.')) return true;

    // 常见私有域名后缀（mDNS / 家用路由器）。
    for (final suffix in const ['.local', '.lan', '.home', '.internal']) {
      if (lower.endsWith(suffix)) return true;
    }

    final address = InternetAddress.tryParse(lower);
    if (address == null) return false;

    if (address.type == InternetAddressType.IPv6) {
      // ::1 回环；fc00::/7 唯一本地地址（ULA）。
      if (address.isLoopback) return true;
      final raw = address.rawAddress;
      return raw.isNotEmpty && (raw[0] & 0xfe) == 0xfc;
    }

    final parts = lower.split('.');
    if (parts.length != 4) return false;
    final a = int.tryParse(parts[0]);
    final b = int.tryParse(parts[1]);
    if (a == null || b == null) return false;

    if (a == 127) return true; // 127.0.0.0/8
    if (a == 10) return true; // 10.0.0.0/8
    if (a == 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a == 192 && b == 168) return true; // 192.168.0.0/16
    if (a == 169 && b == 254) return true; // 169.254.0.0/16
    return false;
  }

  static String handleFindProxy(Uri url) {
    if (_isLoopback(url.host)) {
      return 'DIRECT';
    }
    // 内网/私网地址一律直连（详见 isPrivateHost 注释）。
    if (isPrivateHost(url.host)) return 'DIRECT';
    final port = globalState.config.patchClashConfig.mixedPort;
    final isStart = globalState.appState.runTime != null;
    if (!isStart || port == 0) return 'DIRECT';
    return 'PROXY localhost:$port';
  }

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    final client = super.createHttpClient(context);
    client.findProxy = handleFindProxy;
    return client;
  }
}

import 'dart:async';
import 'dart:io';

import 'package:bett_box/common/app_localizations.dart';
import 'package:bett_box/common/http.dart';
import 'package:bett_box/common/print.dart';
import 'package:bett_box/common/system.dart';
import 'package:bett_box/plugins/app.dart';
import 'package:bett_box/state.dart';
import 'package:dio/dio.dart';
import 'package:flutter/material.dart';

/// Android 16 (API 36) 引入的 `ACCESS_LOCAL_NETWORK` 运行时权限。
///
/// 未授予时系统会静默丢弃应用发往私有网段（192.168/10/172.16-31）的报文，
/// 外网正常但局域网请求（例如局域网内的订阅地址）会一直卡在 connect timeout。
/// 因此这里统一封装「检测 / 申请 / 失败提示」，供启动、设置页和订阅更新失败路径复用。
class LocalNetworkPermission {
  LocalNetworkPermission._();

  static bool? _supported;
  static bool _tipShown = false;

  /// 当前系统是否需要（且支持）该运行时权限；低版本恒为 false。
  static Future<bool> isSupported() async {
    if (!system.isAndroid) return false;
    final cached = _supported;
    if (cached != null) return cached;
    try {
      final supported = await app.isLocalNetworkPermissionSupported();
      _supported = supported;
      return supported;
    } catch (_) {
      _supported = false;
      return false;
    }
  }

  /// 低版本或非 Android 视为已授权，避免调用方到处写平台判断。
  static Future<bool> isGranted() async {
    if (!await isSupported()) return true;
    try {
      return await app.hasLocalNetworkPermission();
    } catch (_) {
      return true;
    }
  }

  /// [force] 为 true 时忽略"本次安装已询问过"的标记（设置页手动授权用）。
  static Future<bool> request({bool force = false}) async {
    if (!await isSupported()) return true;
    try {
      return await app.requestLocalNetworkPermission(force: force);
    } catch (e) {
      commonPrint.warn('[LocalNetwork] request permission failed: $e');
      return false;
    }
  }

  /// 首次进入主界面后静默申请一次：不阻塞启动，用户拒绝后不再自动弹。
  static Future<void> ensureOnStartup() async {
    if (!await isSupported()) return;
    if (await isGranted()) return;
    // 等首帧渲染和主界面初始化完成，避免启动瞬间抢焦点弹系统授权框。
    await Future<void>.delayed(const Duration(seconds: 3));
    if (await isGranted()) return;
    await request();
  }

  /// 判断异常是否属于"局域网被权限拦截"的典型表现（连接超时 / Socket 异常）。
  static bool isUnreachableError(Object error) {
    if (error is SocketException || error is TimeoutException) return true;
    if (error is DioException) {
      final inner = error.error;
      if (inner is SocketException || inner is TimeoutException) return true;
      switch (error.type) {
        case DioExceptionType.connectionTimeout:
        case DioExceptionType.connectionError:
        case DioExceptionType.sendTimeout:
        case DioExceptionType.receiveTimeout:
          return true;
        default:
          break;
      }
    }
    final text = error.toString().toLowerCase();
    return text.contains('connection timeout') ||
        text.contains('connect timeout') ||
        text.contains('sockettimeoutexception') ||
        text.contains('socketexception') ||
        text.contains('connection timed out') ||
        text.contains('连接超时');
  }

  /// 订阅地址是否指向私网（判定逻辑与 HTTP 直连判定共用，避免两处漂移）。
  static bool isPrivateUrl(String? url) {
    if (url == null) return false;
    var raw = url.trim();
    if (raw.isEmpty) return false;
    // 缺少 scheme 时补一个，保证 `192.168.1.1/sub` 这类写法也能取到 host。
    if (!raw.contains('://')) raw = 'http://$raw';
    final uri = Uri.tryParse(raw);
    if (uri == null || uri.host.isEmpty) return false;
    return BettboxHttpOverrides.isPrivateHost(uri.host);
  }

  /// 订阅更新失败后调用：仅当错误像超时、权限确实未授予、且失败目标
  /// [url] 真的在私网时提示一次。
  ///
  /// 公网订阅超时（弱网、机场限流）不是局域网权限问题，传 null 或公网 URL
  /// 一律返回 false，让调用方走通用错误提示，避免误导用户去开无关权限。
  /// 提示里提供"去设置"入口，因为被系统标记为 USER_SENSITIVE_WHEN_DENIED 后
  /// 应用再也弹不出授权框，只能由用户到系统应用详情页手动开启。
  ///
  /// 返回 true 表示已经展示了本权限专属提示（调用方可据此跳过通用网络错误提示）。
  static Future<bool> notifyUpdateFailed(Object error, {String? url}) async {
    if (_tipShown) return false;
    if (!isUnreachableError(error)) return false;
    if (!isPrivateUrl(url)) return false;
    if (!await isSupported()) return false;
    if (await isGranted()) return false;
    _tipShown = true;
    final goSettings = await globalState.showMessage(
      title: appLocalizations.tip,
      message: TextSpan(text: appLocalizations.localNetworkPermissionTip),
      confirmText: appLocalizations.localNetworkPermissionOpenSettings,
      cancelText: appLocalizations.cancel,
    );
    if (goSettings == true) {
      await app.openAppSettings();
    }
    return true;
  }
}

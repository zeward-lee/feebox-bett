/// 协议显示名映射（唯一来源）。
///
/// 配置文件里的 `type` 字符串保持英文小写（机器认的键名，内核 parser 按它
/// 分发），这里只在「给人看的显示层」把内核返回的 type 换成品牌名 / 中文名。
///
/// 匹配对大小写不敏感：内核 `AdapterType.String()` 返回的是 `X365`、`Miu`、
/// `Ninja`、`Oppa`、`XHttp` 这类首字母大写形式，而配置文件里是 `x365`、`miu`
/// 等小写形式，两种写法都能命中。
///
/// 未收录的协议（Vless / Trojan / Hysteria2 / AnyTLS …）原样返回，行为与改造
/// 前完全一致。
///
/// 借壳协议（自己借别人的线路，但有专有名词）由内核按标记自报家门：ss 的
/// `#VT` → ViewTurbo、ss 的 `#BLACKSTONE` → Blackstone、snell 的 `#oix` → OIX、
/// vless 的 `#x365` / `#juzi` / `#pure` → X365 / Juzi / Pure。内核返回的
/// `AdapterType.String()` 已是专有名词，这里只需登记它的展示写法。
const Map<String, String> proxyTypeDisplayNames = {
  'x365': 'X365',
  'miu': 'MIU',
  'ninja': 'Ninja',
  'oppa': 'OPPA',
  'fastup': 'FastUP',
  'xhttp': '黑石',
  'shanlian': '闪连',
  'viewturbo': 'ViewTurbo',
  'blackstone': '黑石',
  'oix': 'OIX',
  'juzi': 'Juzi',
  'pure': 'Pure',
};

/// 把协议 type 转成展示用名字；未收录时原样返回。
String proxyTypeDisplayName(String type) {
  if (type.isEmpty) return type;
  return proxyTypeDisplayNames[type.toLowerCase()] ?? type;
}

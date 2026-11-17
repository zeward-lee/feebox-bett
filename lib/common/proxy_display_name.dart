/// 协议显示名映射（唯一来源）。
///
/// 配置文件里的 `type` 字符串保持英文小写（机器认的键名，内核 parser 按它
/// 分发），这里只在「给人看的显示层」把内核返回的 type 换成统一的英文名。
///
/// 显示名统一为首字母大写、其余小写（X365 / Miu / Oppa / Xhttp …），且与
/// Koipy 端显示的写法完全一致——同一个协议在两条产品线上必须长得一模一样，
/// 否则用户对不上号。
///
/// 匹配对大小写不敏感：内核 `AdapterType.String()` 返回的就是 `X365`、`Miu`、
/// `Ninja`、`Oppa`、`XHttp` 这类首字母大写形式，而配置文件里是 `x365`、`miu`
/// 等小写形式，两种写法都能命中。
///
/// 未收录的协议（Vless / Trojan / Hysteria2 / AnyTLS …）原样返回，行为与改造
/// 前完全一致。
///
/// 借壳协议（自己借别人的线路，但有专有名词）由内核按标记自报家门：ss 的
/// `#VT` → Viewturbo、ss 的 `#BLACKSTONE` → Blackstone、snell 的 `#oix` → Oix、
/// vless 的 `#x365` / `#juzi` / `#pure` → X365 / Juzi / Pure、xhttp 上带
/// clover / gateway / encryption:fake-net 标记的 → Heysocks。内核返回的
/// `AdapterType.String()` 已是专有名词，这里只需登记它的展示写法。
const Map<String, String> proxyTypeDisplayNames = {
  'x365': 'X365',
  'miu': 'Miu',
  'oppa': 'Oppa',
  'fastup': 'Fastup',
  'ninja': 'Ninja',
  'viewturbo': 'Viewturbo',
  'blackstone': 'Blackstone',
  // clover / gateway / encryption:fake-net 三种 xhttp 变体，内核身份已独立枚举。
  'heysocks': 'Heysocks',
  'xhttp': 'Xhttp',
  'shanlian': 'Shanlian',
  'oix': 'Oix',
  'juzi': 'Juzi',
  'pure': 'Pure',
  // 守候网络封端：配置里的 `type: sntp-eclipse`，内核 `AdapterType.String()`
  // 报的是 `SNTP`（与 Fastup/Shanlian/Viewturbo 同一套自报家门机制）。
  'sntp-eclipse': 'Sntp',
  'sntp': 'Sntp',
};

/// 把协议 type 转成展示用名字；未收录时原样返回。
String proxyTypeDisplayName(String type) {
  if (type.isEmpty) return type;
  return proxyTypeDisplayNames[type.toLowerCase()] ?? type;
}

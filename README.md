# 邮件来源认证与防欺骗评估服务

接收方综合 SPF 发件策略、DKIM 签名证据与 DMARC 对齐策略，判定一封邮件是否可信。
DNS 查询全部通过可注入的本地解析接口完成，不发起真实网络请求。

## 接口

`POST /api/evaluate`，请求体为 JSON：

```json
{
  "heloDomain": "mail.example.com",
  "clientIp": "192.0.2.10",
  "envelopeFrom": "user@example.com",
  "rawMessage": "From: user@example.com\r\n\r\nHello\r\n"
}
```

`rawMessage` 使用 UTF-8 传输，内部按原始字节解析，兼容 8 位正文。返回结构化结果，
包含 `spf`、`dkim`（每个签名一项）、`dmarc`（处置与理由）三部分；
资源超限时以 HTTP 200 返回 `errorCode`/`errorMessage`，HTTP 层边界异常返回 413。

**任意 8 位字节原文**：当邮件正文含非 UTF-8 的 8 位字节（如二进制、ISO-8859-1 内容）
时，使用 JSON 字段 `rawMessageBase64` 提交原文的标准 Base64（可省略 `=` 填充、
允许空白）；提供该字段时优先于 `rawMessage`，服务端解码后按逐字节原文评估，
与进程内直接传入同一字节数组的结果完全一致，任何字节都不会被替换或丢弃。
原有 `rawMessage` UTF-8 文本方式保持不变，存量调用无需迁移。Base64 非法时
返回 400 与 `{"code":"INVALID_PAYLOAD", ...}`。

`POST /api/reports/{domain}/flush`：报告周期结束后取出并归档该域的聚合 XML 报告，
无到期数据时返回 204。

## 判定语义

### SPF（RFC 7208）
- 机制：`ip4`、`ip6`、`a`、`mx`、`include`、`redirect`、`all`，支持双 CIDR。
- 限定符：`+` pass、`-` fail、`~` softfail、`?` neutral。
- 结果：`pass`、`fail`、`softfail`、`neutral`、`none`、`permerror`、`temperror`。
- `mx` 判定路径：先解析目标域的 MX 记录得到交换主机列表（不带参数时目标域即当前
  评估域；`mx:domain` 带参数时目标域为参数域），再逐一解析每个交换主机名的地址记录
  ——IPv4 客户端比对交换主机的 A 记录，IPv6 客户端比对 AAAA 记录；客户端命中任一
  交换主机地址（再套用机制上的 `/cidr`、`//cidr` 前缀与限定符）才通过。参数域名
  自身的 A/AAAA 地址不是其交换主机，绝不参与匹配。MX 查询或交换主机地址查询超时
  映射为 `temperror`；NXDOMAIN/无可用地址视为该机制不匹配；MALFORMED 等语法或
  资源类故障按既有规则映射 `permerror`，不静默放行也不静默拒绝。
- `include` 递归受深度上限保护并检测环路；单次评估 DNS 查询有总次数预算。
- DNS 故障映射：NXDOMAIN→无记录（`none`）；TIMEOUT→`temperror`；
  MALFORMED/超长响应/多 SPF 记录/语法错误→`permerror`。

### DKIM（RFC 6376）
- 提取并逐个验证所有 `DKIM-Signature` 头，支持多签名。
- 头部与正文均支持 `simple`/`relaxed` 规范化，支持 `l=` 正文长度截断。
- 结果：`pass`、`fail`、`none`、`permerror`、`temperror`。
- 过期签名、未知选择器、畸形签名/公钥、算法与密钥不匹配均为 `permerror`；
  选择器查询超时为 `temperror`；正文哈希或签名不符为 `fail`。

### DMARC（RFC 7489）
- SPF 与 DKIM 各自按 `strict`（精确域）或 `relaxed`（组织域）模式与头 From 对齐。
- 策略查找先查头 From 域，再回退到组织域（内置常见多级公共后缀，如 `co.uk`）。
- 子域使用 `sp`，缺省继承主策略 `p`；支持 `pct` 采样（以发件域做稳定哈希）。
- 处置：`none`、`quarantine`、`reject`，并在 `reasons` 中给出判定理由。

## DNS 缓存与一致性
- 缓存按“版本 + 域 + 记录类型”为键。**OK 记录的过期时间来自每条记录自身的 TTL**：
  TTL 不同的记录在同一缓存内各自按自己的 TTL 到期，到期后的下一次访问重新解析并
  返回新值；TTL 为 0 的记录不缓存。同域同类型返回的多值记录整体共享一个过期时间，
  取值为该组记录 TTL 的最小值（最保守、最先生效）。底层结果未携带 TTL 时套用
  配置项 `emailauth.dns.cache-ttl-seconds`（默认 300 秒）。
- **NXDOMAIN（不存在的域名）、TIMEOUT（解析超时）、MALFORMED（格式错误）三类
  失败结果使用相互独立的缓存空间与过期时间**：任一类失败的缓存命中、更新或过期
  都不影响另外两类。三者的缓存时长分别由以下配置项控制，配置为 0 时对应失败结果
  不缓存（每次访问都重新解析）：
  - `emailauth.dns.nxdomain-cache-ttl-seconds`（默认 60）
  - `emailauth.dns.timeout-cache-ttl-seconds`（默认 5，兼顾并发去重与快速故障恢复）
  - `emailauth.dns.malformed-cache-ttl-seconds`（默认 60）
- 以键为粒度的单飞（single-flight）保证并发求值只产生一次底层解析。
- 底层记录支持整区原子替换并递增版本；每次评估打开绑定固定版本的解析会话，
  策略更新与评估并发时单次评估始终使用同一快照，不混用新旧记录，评估之间互不阻塞。
- **解析超时**：`emailauth.dns.timeout-millis`（默认 3000ms）对每次底层解析生效。
  调小该配置后，慢解析会按新配置在限定时间内被截断，SPF/DKIM/DMARC 侧得到文档
  规定的超时结果（SPF 与 DMARC 为 `temperror`，DKIM 选择器查询为 `temperror`）。
  被截断的查询立即收到线程中断并退出，不会继续在后台运行累积线程资源，也不会拖慢
  并发评估（每个查询使用独立守护工作线程，调用方只等待自己的限时结果）。
  验证方法：将配置调至远小于注入解析延迟的值（如 50ms 对 3s 延迟），评估应在
  约 50ms 内返回超时结果；恢复默认值后快路径立即恢复正常。

## 聚合反馈报告
- 仅聚合未通过 DMARC 的邮件，生成 RFC 7489 风格 XML。
- 同一 `Message-ID`（无 Message-ID 时取原文 SHA-256）在一个报告周期内只计一次。
- 聚合数据以 JSON 原子写入本地目录，进程重启后自动恢复，未提交数据不丢失。

## 资源边界与异常防护
所有上限可通过配置调整，超限返回可区分的错误码：

| 配置项 | 默认值 | 错误码 |
| --- | --- | --- |
| `emailauth.limits.max-message-bytes` | 10485760 | `MESSAGE_TOO_LARGE` |
| `emailauth.limits.max-header-bytes` | 16384 | `HEADER_TOO_LARGE` |
| `emailauth.limits.max-header-line-bytes` | 8192 | `HEADER_LINE_TOO_LONG` |
| `emailauth.limits.max-headers` | 256 | `TOO_MANY_HEADERS` |
| `emailauth.limits.max-dns-response-bytes` | 65535 | `DNS_RESPONSE_TOO_LARGE` |
| `emailauth.limits.max-include-depth` | 8 | `INCLUDE_DEPTH_EXCEEDED` |
| `emailauth.limits.max-dns-queries` | 64 | `DNS_QUERY_LIMIT_EXCEEDED` |
| `emailauth.limits.max-signatures` | 16 | `TOO_MANY_SIGNATURES` |

其他配置：`emailauth.dns.timeout-millis`（默认 3000ms，见“DNS 缓存与一致性”）、
`emailauth.dns.cache-ttl-seconds`、三类失败缓存 TTL（同上）、
`emailauth.report.storage-path`、`emailauth.report.interval-seconds`。

## 本地 DNS 注入
生产装配使用 `MapBackedDnsResolver`（内存记录）+ `CachingDnsResolver`（缓存/快照）。
测试或接入时可直接替换 `MapBackedDnsResolver` 中的记录，或整体替换 `DnsResolver` Bean；
记录缺失按 NXDOMAIN 处理，可显式放入 TIMEOUT/MALFORMED 结果做故障注入。
`putWithTtl(...)` 可放入带自身 TTL 的 OK 记录（TTL=0 表示不缓存）；慢解析注入可通过
重写解析方法并 `sleep` 实现（工作线程需响应中断），配合 `TimedDnsResolver` 验证超时。

## 构建与测试

```bash
mvn test
```

测试覆盖 SPF 机制与故障语义、DKIM 真实 RSA 签名（simple/relaxed、折行、`l=`、过期、
未知选择器、超时）、DMARC 对齐/组织域回退/子域策略/pct、DNS 缓存与并发去重、
解析边界、报告去重与重启恢复、HTTP 接口及策略热替换下的快照一致性；
另覆盖带参数/不带参数的 `mx` 机制（多 MX 主机、IPv4/IPv6、双 CIDR 与限定符、
故障映射）、每记录 TTL 的独立过期与零 TTL 不缓存、三类失败缓存空间隔离与分别
配置、含非 UTF-8 8 位字节原文经 `rawMessageBase64` 提交后的逐字节一致评估，
以及解析超时配置截断慢查询、中断后台查询与恢复默认值。

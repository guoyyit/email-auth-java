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

### 任意 8 位字节的无损提交

JSON 字符串无法无损承载任意字节序列（非 UTF-8 字节在 JSON 解码时会被替换）。
需要提交非 UTF-8 正文时使用原始字节端点：

```
POST /api/evaluate/raw?heloDomain=mail.example.com&clientIp=192.0.2.10&envelopeFrom=user@example.com
Content-Type: application/octet-stream

<请求体即 RFC 5322 邮件原文的原始字节>
```

请求体不经过任何字符集解码，按原始字节直接进入解析与评估；非 UTF-8 字节不会被替换、
丢弃或改动，评估结果与在进程内直接传入相同字节时完全一致（无 `Message-ID` 时
结果中的 `messageId` 为原文 SHA-256，可用于逐字节核对）。信封参数
（`heloDomain`、`clientIp`、`envelopeFrom`）均为 ASCII，经查询参数传递；
均可省略。原有 JSON 提交方式保持兼容，存量调用无需迁移。

`POST /api/reports/{domain}/flush`：报告周期结束后取出并归档该域的聚合 XML 报告，
无到期数据时返回 204。

## 判定语义

### SPF（RFC 7208）
- 机制：`ip4`、`ip6`、`a`、`mx`、`include`、`redirect`、`all`，支持双 CIDR。
- 限定符：`+` pass、`-` fail、`~` softfail、`?` neutral。
- 结果：`pass`、`fail`、`softfail`、`neutral`、`none`、`permerror`、`temperror`。
- `mx` 判定路径：先对目标域查询 MX 记录（`mx:example.net` 的目标域为参数域，
  不带参数时为当前评估域），得到交换主机名列表；再逐个对交换主机名查询地址记录，
  客户端为 IPv4 时查 A、为 IPv6 时查 AAAA，客户端 IP 命中任一交换主机地址
  （按机制上的 ip4/ip6 CIDR 前缀比较）才通过该机制。参数域自身的 A/AAAA 记录
  不是交换主机地址，绝不参与匹配；交换主机超过 10 个为 `permerror`；
  MX 或交换主机地址查询的 TIMEOUT 映射 `temperror`，NXDOMAIN/MALFORMED 机制不匹配，
  不静默放行也不静默拒绝。
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
- 缓存按“数据版本 + 域 + 记录类型”为键，过期时间来自每条记录自身的 TTL：
  `DnsResult` 携带的 `ttlSeconds` 即该记录 TTL，TTL 不同的记录在同一缓存内各自
  独立过期，过期后下次访问重新解析并返回新值；`ttlSeconds=0` 的记录不缓存。
  记录未携带 TTL（`-1`）时，成功结果回退到 `emailauth.dns.cache-ttl-seconds`。
- 同一次查询返回的多值记录（如多条 MX/TXT）整体封装为一个 `DnsResult`，
  共享一个 TTL 与一个过期时刻；本地注入时该 TTL 在整条结果上显式给出，
  多值整体在同一时刻过期、整体重新解析。
- OK、NXDOMAIN、TIMEOUT、MALFORMED 使用四个相互独立的缓存空间：任一种结果的
  命中、更新或过期都不影响其它空间（例如短 TTL 的 TIMEOUT 过期不会让刚缓存的
  NXDOMAIN 提前失效）。三类失败的缓存时长分别可配，配置为 0 时该类失败不缓存：
  `emailauth.dns.nxdomain-ttl-seconds`（默认 60）、
  `emailauth.dns.malformed-ttl-seconds`（默认 60）、
  `emailauth.dns.timeout-ttl-seconds`（默认 5，兼顾并发去重与快速故障恢复）。
- 以键为粒度的单飞（single-flight）保证并发求值对同一记录只产生一次底层解析，
  TTL 规则与失败隔离在并发访问下保持不变。
- 解析超时由 `emailauth.dns.timeout-millis` 控制（默认 3000，未配置时使用默认值）：
  底层解析在独立守护线程中执行，超过配置时长即被截断并映射为 TIMEOUT
  （SPF/DKIM 中为 `temperror`）；截断同时中断底层查询线程，慢查询不会在后台继续
  运行或累积线程，也不会阻塞其他键的并发解析。验证方法：向 `MapBackedDnsResolver`
  注入一个响应中断的慢解析（`Thread.sleep` 捕获 `InterruptedException`），
  调小 `timeout-millis` 后评估应在该时长附近返回 `temperror`，且慢查询线程
  收到中断信号退出；不配置时按 3000ms 截断。
- 底层记录支持整区原子替换并递增版本；每次评估打开绑定固定版本的解析会话，
  策略更新与评估并发时单次评估始终使用同一快照，不混用新旧记录，评估之间互不阻塞。

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

其他配置：`emailauth.dns.timeout-millis`、`emailauth.dns.cache-ttl-seconds`、
`emailauth.dns.nxdomain-ttl-seconds`、`emailauth.dns.malformed-ttl-seconds`、
`emailauth.dns.timeout-ttl-seconds`、`emailauth.report.storage-path`、
`emailauth.report.interval-seconds`。

## 本地 DNS 注入
生产装配使用 `MapBackedDnsResolver`（内存记录）+ `CachingDnsResolver`（缓存/快照）。
测试或接入时可直接替换 `MapBackedDnsResolver` 中的记录，或整体替换 `DnsResolver` Bean；
记录缺失按 NXDOMAIN 处理，可显式放入 TIMEOUT/MALFORMED 结果做故障注入。
构造 `DnsResult` 时可传入该记录自身的 TTL（秒），`put` 也提供带 TTL 的重载；
TTL 为 0 表示不缓存，不传 TTL 时成功结果回退到 `cache-ttl-seconds`。
自定义 `DnsResolver` 实现应及时响应线程中断，以便解析超时后释放后台线程。

## 构建与测试

```bash
mvn test
```

测试覆盖 SPF 机制与故障语义、DKIM 真实 RSA 签名（simple/relaxed、折行、`l=`、过期、
未知选择器、超时）、DMARC 对齐/组织域回退/子域策略/pct、带参数与不带参数的 mx
（多 MX 主机、IPv4/IPv6、交换主机与参数域自身地址区分、双 CIDR 与各限定符）、
DNS 记录自身 TTL 的独立过期与 TTL=0、NXDOMAIN/TIMEOUT/MALFORMED 三类失败缓存的
隔离与分别配置、解析超时配置生效（截断、中断后台线程、不阻塞并发、默认值）、
并发单飞去重、解析边界、报告去重与重启恢复、HTTP JSON 与原始字节（含非 UTF-8
8 位正文）两种提交方式及策略热替换下的快照一致性。

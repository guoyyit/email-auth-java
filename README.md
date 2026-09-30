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

`POST /api/reports/{domain}/flush`：报告周期结束后取出并归档该域的聚合 XML 报告，
无到期数据时返回 204。

## 判定语义

### SPF（RFC 7208）
- 机制：`ip4`、`ip6`、`a`、`mx`、`include`、`redirect`、`all`，支持双 CIDR。
- 限定符：`+` pass、`-` fail、`~` softfail、`?` neutral。
- 结果：`pass`、`fail`、`softfail`、`neutral`、`none`、`permerror`、`temperror`。
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
- 缓存按“域 + 记录类型”为键，按 TTL 管理；OK 与 NXDOMAIN/MALFORMED/TIMEOUT
  三类结果相互隔离（TIMEOUT 短 TTL，兼顾并发去重与快速故障恢复）。
- 以键为粒度的单飞（single-flight）保证并发求值只产生一次底层解析。
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
`emailauth.report.storage-path`、`emailauth.report.interval-seconds`。

## 本地 DNS 注入
生产装配使用 `MapBackedDnsResolver`（内存记录）+ `CachingDnsResolver`（缓存/快照）。
测试或接入时可直接替换 `MapBackedDnsResolver` 中的记录，或整体替换 `DnsResolver` Bean；
记录缺失按 NXDOMAIN 处理，可显式放入 TIMEOUT/MALFORMED 结果做故障注入。

## 构建与测试

```bash
mvn test
```

测试覆盖 SPF 机制与故障语义、DKIM 真实 RSA 签名（simple/relaxed、折行、`l=`、过期、
未知选择器、超时）、DMARC 对齐/组织域回退/子域策略/pct、DNS 缓存与并发去重、
解析边界、报告去重与重启恢复、HTTP 接口及策略热替换下的快照一致性。

# 邮件来源认证与防欺骗评估服务

接收方综合 **SPF**（RFC 7208）、**DKIM**（RFC 6376，兼容 RFC 8301/8463 算法）与
**DMARC**（RFC 7489）三要素，对提交的原始邮件给出结构化可信判定。
DNS 查询通过可注入的本地解析接口完成，**不依赖真实网络**；并支持记录缓存、
策略动态更新下的一致快照、聚合反馈报告与资源边界防护。

## 模块结构

| 包 | 职责 |
| --- | --- |
| `mail` | RFC 5322 解析：折行头部展开、8 位正文、兼容 LF/孤立 CR 等历史写法、输入上限 |
| `dns` | `DnsResolver` 接口、`InMemoryDnsResolver` 测试数据源、按类型/TTL 的 `DnsCache` |
| `spf` | SPF 策略求值、宏展开、记录解析、include 深度/环路与查询预算 |
| `dkim` | 多签名验证、simple/relaxed 规范化、`l=` 截断、RSA/Ed25519 验签 |
| `dmarc` | 策略记录解析、strict/relaxed 对齐、组织域回退、`sp` 继承、`pct` 采样 |
| `report` | 失败邮件聚合、周期去重、fsync 持久化、重启恢复、RFC 7489 XML 报告 |
| `eval` | 单次评估编排：SPF + DKIM + DMARC 共享同一 DNS 快照版本 |
| `web` | HTTP 接口（提交邮件、读取/提交聚合报告、缓存失效） |
| `config` | `AuthProperties` 配置与 Spring Bean 装配 |

## HTTP 接口

### 评估邮件

`POST /api/evaluate`

```json
{
  "rawMessageBase64": "<RFC5322 原始邮件的 base64>",
  "clientIp": "192.0.2.10",
  "heloDomain": "mail.example.com",
  "mailFrom": "<alice@example.com>"
}
```

也可用 `rawMessage` 直接传文本（按 ISO-8859-1 解码，8 位内容建议使用 base64）。
返回 `AuthResult`，包含 `fromDomain`、`sourceIp`、SPF/DKIM/DMARC 各自结果、
DMARC 处置（`NONE`/`QUARANTINE`/`REJECT`）、对齐标志与处置理由。

### 聚合报告

- `GET /api/report/{domain}`：返回当日（UTC）聚合反馈 XML。
- `POST /api/report/{domain}/commit`：生成后确认，清空该域未提交聚合数据。
- `POST /api/cache/invalidate`：推进 DNS 快照版本（策略更新后新评估使用新记录）。

解析失败返回 `400`（`malformed_message`）或 `413`（`message_too_large`）。

## 判定语义

### SPF（`spf.status`）

- `PASS` / `FAIL` / `SOFTFAIL` / `NEUTRAL`：由匹配机制的限定符 `+ - ~ ?` 决定。
- `NONE`：发件域无可用 SPF 记录。
- `PERMERROR`：记录语法错误、存在多条 SPF 记录、include/redirect 环路或超过深度上限、
  超过 DNS 查询次数或空应答（void lookup）上限、非法 CIDR/机制。
- `TEMPERROR`：求值所需 DNS 查询超时。

支持机制：`ip4`、`ip6`（CIDR）、`a`、`mx`（含 `/cidr`、`//dual-cidr`）、
`include`、`redirect=`、`all`，并容忍 `exists`。include 递归有深度上限与环路检测。

### DKIM（`dkim.status` 及逐签名 `dkim.signatures[]`）

- `PASS`：至少一个签名通过（整体取最佳结果）。
- `FAIL`：签名存在但正文哈希/签名不符、签名过期（`x=`）、或选择器不存在（NXDOMAIN/NODATA，
  原因明确标注 `unknown selector ...` / `signature expired ...`）。
- `NONE`：邮件无 `DKIM-Signature`。
- `PERMERROR`：签名标签格式错误、算法/标签缺失、From 未被 `h=` 覆盖、密钥记录畸形/吊销/类型不符。
- `TEMPERROR`：选择器 TXT 查询超时。

支持多签名；头部/正文均支持 `simple` 与 `relaxed`；支持 `l=` 正文长度截断；
`rsa-sha1`（历史）、`rsa-sha256` 与 `ed25519-sha256`。

### DMARC（`dmarc.disposition`）

- 先在 `_dmarc.<发件域>` 查找；无记录时回退到组织域的 `_dmarc.<组织域>`。
- SPF：仅 `SPF PASS` 且认证域与 From 域对齐才算通过。
- DKIM：仅 `DKIM PASS` 且签名 `d=` 域与 From 域对齐才算通过。
- 对齐模式：`strict`（完全相等）与 `relaxed`（组织域相同，默认）。
- 发件域为子域时采用 `sp`，缺省继承 `p`。
- 两者均未对齐时按策略处置；`pct` 采样未命中时降为 `NONE` 并给出理由。
- 无策略记录（或策略 `p=none`）时处置为 `NONE`，原因字段说明具体情形。

## DNS 缓存与故障语义

- 缓存按 `(名称, 记录类型, 快照版本)` 与 TTL 管理；正向 TTL 取记录 TTL 并受
  `max-positive-ttl-seconds` 限制。
- 三类故障**相互隔离**：`NXDOMAIN`、`NO_DATA`、`TIMEOUT`、`MALFORMED`，各自使用独立负缓存 TTL。
- SPF 中超时稳定映射为 `TEMPERROR`；记录畸形/语法错误稳定映射为 `PERMERROR`。
- 并发同键查询经 single-flight 合并，底层解析只发生一次。
- 一次评估固定一个快照版本；`invalidateAll` 推进当前版本，旧版本条目在 TTL 到期前保留，
  因此进行中的评估不会混用新旧记录，评估之间也互不阻塞。

## 聚合反馈与持久化

- 仅对“SPF 与 DKIM 均未对齐”的邮件聚合；同一封邮件（Message-ID + 来源 IP + 发件域）
  在一个 UTC 周期内重复评估只计一次。
- 每条事件追加写入 `store-dir` 下按 `域-日期` 命名的日志并 `fsync`；
  服务重启时自动回放恢复，未提交数据不丢失、且不重复计数。

## 默认上限与配置项

前缀 `email-auth`，均可在 `application.properties` 覆盖：

| 配置项 | 默认值 | 含义 |
| --- | --- | --- |
| `limits.max-message-bytes` | 2097152 (2 MiB) | 原始邮件最大字节，超限 413 |
| `limits.max-header-line-bytes` | 65536 | 单个折行展开头部最大字节 |
| `limits.max-header-bytes` | 524288 | 头部区最大字节 |
| `limits.max-headers` | 1000 | 头部数量上限 |
| `limits.max-dns-response-bytes` | 16384 | 单条 DNS/SPF/DMARC 文本最大字节 |
| `limits.max-signed-headers` | 256 | DKIM `h=` 头部数量上限 |
| `spf.max-include-depth` | 10 | include/redirect 递归深度 |
| `spf.max-dns-queries` | 30 | 单次 SPF 求值 DNS 查询次数 |
| `spf.max-void-lookups` | 2 | NXDOMAIN/NODATA 次数上限 |
| `dkim.max-signatures` | 10 | 单次验证处理签名数 |
| `dkim.expiry-skew-seconds` | 0 | `x=` 过期判定时钟偏移 |
| `cache.max-positive-ttl-seconds` | 86400 | 正向记录 TTL 上限 |
| `cache.nxdomain-ttl-seconds` | 300 | NXDOMAIN/NODATA 负缓存 |
| `cache.malformed-ttl-seconds` | 60 | 畸形应答负缓存 |
| `cache.timeout-ttl-seconds` | 0 | 超时不缓存 |
| `dmarc.private-suffixes` | 空 | 额外多标签私有后缀（组织域判定） |
| `report.enabled` | true | 是否持久化聚合事件 |
| `report.store-dir` | `data/aggregate` | 聚合日志目录 |
| `report.report-receiver` | `receiver.example` | 报告中的接收方标识 |

## 注入自定义 DNS 数据

默认装配空的 `InMemoryDnsResolver`。接入方提供自己的 `DnsResolver` Bean 即可覆盖：

```java
@Bean
public DnsResolver dnsResolver() {
    InMemoryDnsResolver resolver = new InMemoryDnsResolver();
    resolver.putTxt("example.com", "v=spf1 -all");
    resolver.putFailure("slow.example", RecordType.TXT, DnsStatus.TIMEOUT); // 故障注入
    return resolver;
}
```

## 测试

```bash
mvn test
```

覆盖 SPF 机制/限定符/include 环路与深度/查询预算/故障映射，DKIM RSA/relaxed/多签名/
过期/未知选择器/规范化，DMARC 对齐/组织域/子域/pct，DNS TTL/故障隔离/并发去重/版本快照，
聚合去重/XML/崩溃恢复，资源边界与异常输入，以及端到端 HTTP 编排。

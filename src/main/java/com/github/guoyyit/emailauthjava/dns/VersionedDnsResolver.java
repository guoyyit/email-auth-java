package com.github.guoyyit.emailauthjava.dns;

/**
 * 支持数据版本的本地解析器：策略数据整体替换时版本递增，
 * 旧版本查询用于让进行中的评估保持快照一致性。
 */
public interface VersionedDnsResolver extends DnsResolver {
    long version();

    DnsResult resolveAt(String domain, RecordType type, long version);
}

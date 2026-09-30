package com.github.guoyyit.emailauthjava.dns;

import java.util.List;

/**
 * 一次 DNS 查询的稳定结果：状态 + 记录集（OK 时）+ 记录自身 TTL。
 * 故障状态（NXDOMAIN/NO_DATA/TIMEOUT/MALFORMED）彼此隔离，记录集为空。
 */
public final class DnsAnswer {
    private final DnsStatus status;
    private final List<DnsRecord> records;

    public DnsAnswer(DnsStatus status, List<DnsRecord> records) {
        this.status = status;
        this.records = records;
    }

    public static DnsAnswer ok(List<DnsRecord> records) {
        return new DnsAnswer(DnsStatus.OK, List.copyOf(records));
    }

    public static DnsAnswer failure(DnsStatus status) {
        return new DnsAnswer(status, List.of());
    }

    public DnsStatus getStatus() { return status; }
    public List<DnsRecord> getRecords() { return records; }

    /** 应答中所有记录的最小 TTL；空记录集返回 0。 */
    public long minTtl() {
        long min = Long.MAX_VALUE;
        for (DnsRecord record : records) {
            min = Math.min(min, record.getTtlSeconds());
        }
        return min == Long.MAX_VALUE ? 0 : min;
    }
}

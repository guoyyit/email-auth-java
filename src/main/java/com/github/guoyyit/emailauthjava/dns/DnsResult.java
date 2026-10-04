package com.github.guoyyit.emailauthjava.dns;

import java.util.List;

public class DnsResult {
    /**
     * 未显式携带 TTL 的结果使用该哨兵值，缓存层回退到配置的默认成功 TTL。
     */
    public static final long TTL_FROM_CONFIG = -1L;

    private final DnsStatus status;
    private final List<String> records;
    private final List<String> exchangeNames;
    private final long ttlSeconds;

    public DnsResult(DnsStatus status, List<String> records, List<String> exchangeNames) {
        this(status, records, exchangeNames, TTL_FROM_CONFIG);
    }

    public DnsResult(DnsStatus status, List<String> records, List<String> exchangeNames,
                     long ttlSeconds) {
        this.status = status;
        this.records = records;
        this.exchangeNames = exchangeNames;
        this.ttlSeconds = ttlSeconds;
    }

    public DnsStatus getStatus() { return status; }
    public List<String> getRecords() { return records; }
    public List<String> getExchangeNames() { return exchangeNames; }
    public long getTtlSeconds() { return ttlSeconds; }
}

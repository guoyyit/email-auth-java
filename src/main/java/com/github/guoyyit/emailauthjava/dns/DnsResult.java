package com.github.guoyyit.emailauthjava.dns;

import java.util.List;

public class DnsResult {
    private final DnsStatus status;
    private final List<String> records;
    private final List<String> exchangeNames;
    /**
     * 本条结果自身的 TTL（秒）。同域同类型的多值记录整体共享一个 TTL，
     * 以该组记录中的最小 TTL 为准；null 表示底层未提供，套用配置的默认缓存时长。
     * 仅对 OK 结果生效。
     */
    private final Long ttlSeconds;

    public DnsResult(DnsStatus status, List<String> records, List<String> exchangeNames) {
        this(status, records, exchangeNames, null);
    }

    public DnsResult(DnsStatus status, List<String> records, List<String> exchangeNames,
                     Long ttlSeconds) {
        this.status = status;
        this.records = records;
        this.exchangeNames = exchangeNames;
        this.ttlSeconds = ttlSeconds;
    }

    public DnsStatus getStatus() { return status; }
    public List<String> getRecords() { return records; }
    public List<String> getExchangeNames() { return exchangeNames; }
    public Long getTtlSeconds() { return ttlSeconds; }
}

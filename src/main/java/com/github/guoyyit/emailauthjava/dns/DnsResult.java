package com.github.guoyyit.emailauthjava.dns;

import java.util.List;

public class DnsResult {
    private final DnsStatus status;
    private final List<String> records;
    private final List<String> exchangeNames;

    public DnsResult(DnsStatus status, List<String> records, List<String> exchangeNames) {
        this.status = status;
        this.records = records;
        this.exchangeNames = exchangeNames;
    }

    public DnsStatus getStatus() { return status; }
    public List<String> getRecords() { return records; }
    public List<String> getExchangeNames() { return exchangeNames; }
}

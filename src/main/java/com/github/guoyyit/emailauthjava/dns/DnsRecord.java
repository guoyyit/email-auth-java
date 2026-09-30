package com.github.guoyyit.emailauthjava.dns;

/**
 * 单条 DNS 资源记录。{@code text} 用于 TXT（已将多个字符串片段拼接），
 * {@code address} 用于 A/AAAA（字面量 IP），{@code exchange}/{@code preference} 用于 MX。
 */
public final class DnsRecord {
    private final String name;
    private final RecordType type;
    private final String text;
    private final String address;
    private final String exchange;
    private final int preference;
    private final long ttlSeconds;

    public DnsRecord(String name, RecordType type, String text, String address,
                     String exchange, int preference, long ttlSeconds) {
        this.name = name;
        this.type = type;
        this.text = text;
        this.address = address;
        this.exchange = exchange;
        this.preference = preference;
        this.ttlSeconds = ttlSeconds;
    }

    public String getName() { return name; }
    public RecordType getType() { return type; }
    public String getText() { return text; }
    public String getAddress() { return address; }
    public String getExchange() { return exchange; }
    public int getPreference() { return preference; }
    public long getTtlSeconds() { return ttlSeconds; }

    public static DnsRecord txt(String name, String text, long ttlSeconds) {
        return new DnsRecord(name, RecordType.TXT, text, null, null, 0, ttlSeconds);
    }

    public static DnsRecord address(String name, RecordType type, String address, long ttlSeconds) {
        return new DnsRecord(name, type, null, address, null, 0, ttlSeconds);
    }

    public static DnsRecord mx(String name, String exchange, int preference, long ttlSeconds) {
        return new DnsRecord(name, RecordType.MX, null, null, exchange, preference, ttlSeconds);
    }
}

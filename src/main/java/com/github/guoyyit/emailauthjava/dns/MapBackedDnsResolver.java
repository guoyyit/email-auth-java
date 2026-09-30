package com.github.guoyyit.emailauthjava.dns;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 本地可注入的 DNS 解析实现：所有记录预先放入内存映射，不发起任何网络请求。
 * Key 形如 {@code domain#TYPE}，域名大小写不敏感。映射中缺失的键解析为 NXDOMAIN。
 * 支持以 {@link #replaceAll} 做整区原子替换并递增版本；保留上一个版本，
 * 以便进行中的评估仍能读取旧快照（会话之间互不阻塞）。
 */
public class MapBackedDnsResolver implements VersionedDnsResolver {
    private volatile Zone current = new Zone(new ConcurrentHashMap<>(), 0L);
    private volatile Zone previous;
    private final AtomicLong versionSequence = new AtomicLong();

    public MapBackedDnsResolver(Map<String, DnsResult> initialRecords) {
        this.current = new Zone(new ConcurrentHashMap<>(initialRecords), 0L);
    }

    public void put(String domain, RecordType type, DnsResult result) {
        current.records.put(key(domain, type), result);
    }

    public void put(String domain, RecordType type, DnsStatus status, java.util.List<String> records) {
        put(domain, type, new DnsResult(status, records, java.util.List.of()));
    }

    public void put(String domain, RecordType type, DnsStatus status,
                    java.util.List<String> records, java.util.List<String> exchanges) {
        put(domain, type, new DnsResult(status, records, exchanges));
    }

    public void replaceAll(Map<String, DnsResult> nextRecords) {
        Zone zone = new Zone(new ConcurrentHashMap<>(nextRecords),
                versionSequence.incrementAndGet());
        this.previous = this.current;
        this.current = zone;
    }

    @Override
    public DnsResult resolve(String domain, RecordType type) {
        return resolveAt(domain, type, current.version);
    }

    @Override
    public long version() {
        return current.version;
    }

    @Override
    public DnsResult resolveAt(String domain, RecordType type, long version) {
        if (domain == null || type == null) {
            return new DnsResult(DnsStatus.MALFORMED, java.util.List.of(), java.util.List.of());
        }
        Zone zone = selectZone(version);
        DnsResult result = zone.records.get(key(domain, type));
        if (result == null) {
            return new DnsResult(DnsStatus.NXDOMAIN, java.util.List.of(), java.util.List.of());
        }
        return result;
    }

    private Zone selectZone(long version) {
        if (previous != null && previous.version == version) {
            return previous;
        }
        return current;
    }

    public static String key(String domain, RecordType type) {
        return domain.toLowerCase(java.util.Locale.ROOT) + "#" + type.name();
    }

    private record Zone(Map<String, DnsResult> records, long version) {
    }
}

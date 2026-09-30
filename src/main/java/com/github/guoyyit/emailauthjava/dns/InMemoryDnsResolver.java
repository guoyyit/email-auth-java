package com.github.guoyyit.emailauthjava.dns;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

import java.util.ArrayList;

/**
 * 测试/本地用的内存解析器：按 (name,type) 提供应答，也可注入固定故障。
 */
public class InMemoryDnsResolver implements DnsResolver {

    private record Key(String name, RecordType type) {
    }

    private final ConcurrentMap<Key, List<DnsRecord>> records = new ConcurrentHashMap<>();
    private final ConcurrentMap<Key, DnsStatus> failures = new ConcurrentHashMap<>();
    private final ConcurrentMap<Key, AtomicInteger> queryCounts = new ConcurrentHashMap<>();

    public InMemoryDnsResolver() {
    }

    public void put(DnsRecord record) {
        Key key = new Key(normalize(record.getName()), record.getType());
        records.computeIfAbsent(key, k -> new ArrayList<>()).add(record);
    }

    public void putTxt(String name, String text) {
        put(DnsRecord.txt(normalize(name), text, 3600));
    }

    public void putFailure(String name, RecordType type, DnsStatus status) {
        failures.put(new Key(normalize(name), type), status);
    }

    public void remove(String name, RecordType type) {
        Key key = new Key(normalize(name), type);
        records.remove(key);
        failures.remove(key);
    }

    @Override
    public DnsAnswer query(String name, RecordType type) {
        Key key = new Key(normalize(name), type);
        queryCounts.computeIfAbsent(key, k -> new AtomicInteger()).incrementAndGet();
        DnsStatus injected = failures.get(key);
        if (injected != null) {
            return DnsAnswer.failure(injected);
        }
        List<DnsRecord> found = records.get(key);
        if (found != null) {
            synchronized (found) {
                return DnsAnswer.ok(found);
            }
        }
        boolean nameExists = records.keySet().stream().anyMatch(k -> k.name().equals(key.name()));
        return DnsAnswer.failure(nameExists ? DnsStatus.NO_DATA : DnsStatus.NXDOMAIN);
    }

    public Map<String, List<DnsRecord>> getRecordsView() {
        Map<String, List<DnsRecord>> view = new java.util.TreeMap<>();
        records.forEach((key, list) -> {
            synchronized (list) {
                view.put(key.name() + "/" + key.type(), List.copyOf(list));
            }
        });
        return Map.copyOf(view);
    }

    /** 底层解析器被调用的次数（用于验证缓存去重）。 */
    public int underlyingQueryCount(String name, RecordType type) {
        AtomicInteger counter = queryCounts.get(new Key(normalize(name), type));
        return counter == null ? 0 : counter.get();
    }

    private static String normalize(String name) {
        if (name == null) {
            return "";
        }
        String trimmed = name.trim().toLowerCase(java.util.Locale.ROOT);
        while (trimmed.endsWith(".")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }
}

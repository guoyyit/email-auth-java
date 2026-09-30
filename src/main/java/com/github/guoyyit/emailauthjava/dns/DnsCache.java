package com.github.guoyyit.emailauthjava.dns;

import com.github.guoyyit.emailauthjava.config.AuthProperties;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 按记录类型与 TTL 管理的 DNS 应答缓存。
 * <ul>
 *   <li>NXDOMAIN/NO_DATA/TIMEOUT/MALFORMED 使用各自独立的负缓存 TTL。</li>
 *   <li>并发查询去重（single-flight），同一 key 不产生重复解析。</li>
 *   <li>策略动态更新时按版本整体失效，单次评估拿到一致快照。</li>
 * </ul>
 */
public class DnsCache {

    private static final class Entry {
        private final DnsAnswer answer;
        private final long expireAtMillis;

        private Entry(DnsAnswer answer, long expireAtMillis) {
            this.answer = answer;
            this.expireAtMillis = expireAtMillis;
        }

        private boolean fresh(long now) {
            return now < expireAtMillis;
        }
    }

    private record Key(String name, RecordType type, long version) {
    }

    private final DnsResolver resolver;
    private final AuthProperties properties;
    private final ConcurrentMap<Key, Optional<Entry>> entries = new ConcurrentHashMap<>();
    private final ConcurrentMap<Key, CompletableFuture<DnsAnswer>> inflight = new ConcurrentHashMap<>();
    private volatile long version = 1;

    public DnsCache(DnsResolver resolver, AuthProperties properties) {
        this.resolver = resolver;
        this.properties = properties;
    }

    /** 查询（命中缓存则不触发底层解析），并发同 key 请求合并。 */
    public DnsAnswer query(String name, RecordType type) {
        return queryAtVersion(version, name, type);
    }

    /** 进入一个一致性快照，返回快照版本号。 */
    public long beginSnapshot() {
        return version;
    }

    /** 指定版本查询（供一次评估内固定版本使用）。 */
    public DnsAnswer queryAtVersion(long snapshotVersion, String name, RecordType type) {
        long now = System.currentTimeMillis();
        Key key = new Key(normalize(name), type, snapshotVersion);
        Optional<Entry> cached = entries.get(key);
        if (cached != null) {
            Entry entry = cached.orElse(null);
            if (entry != null && entry.fresh(now)) {
                return entry.answer;
            }
            entries.remove(key, cached);
        }

        CompletableFuture<DnsAnswer> future = new CompletableFuture<>();
        CompletableFuture<DnsAnswer> existing = inflight.putIfAbsent(key, future);
        if (existing != null) {
            return existing.join();
        }
        try {
            DnsAnswer answer = resolver.query(key.name(), type);
            store(key, answer);
            future.complete(answer);
            return answer;
        } catch (RuntimeException ex) {
            DnsAnswer answer = DnsAnswer.failure(DnsStatus.TIMEOUT);
            store(key, answer);
            future.complete(answer);
            return answer;
        } finally {
            inflight.remove(key, future);
        }
    }

    /**
     * 推进当前快照版本（策略更新后调用）。旧版本条目在 TTL 到期前保留，
     * 保证进行中的评估仍读到一致的旧记录；新查询落到新版本。
     */
    public synchronized void invalidateAll() {
        version++;
    }

    /** 当前缓存条目数（监控/测试用）。 */
    public int size() {
        return entries.size();
    }

    private void store(Key key, DnsAnswer answer) {
        long ttlSeconds = ttlFor(answer);
        if (ttlSeconds < 0) {
            entries.put(key, Optional.empty());
            return;
        }
        long expireAt = System.currentTimeMillis() + ttlSeconds * 1000L;
        entries.put(key, Optional.of(new Entry(answer, expireAt)));
    }

    private long ttlFor(DnsAnswer answer) {
        AuthProperties.Cache cacheProps = properties.getCache();
        switch (answer.getStatus()) {
            case OK:
                long recordTtl = answer.minTtl();
                long effective = recordTtl <= 0 ? 60 : recordTtl;
                return Math.max(Math.min(effective, cacheProps.getMaxPositiveTtlSeconds()), 1);
            case NXDOMAIN:
            case NO_DATA:
                return cacheProps.getNxdomainTtlSeconds();
            case MALFORMED:
                return cacheProps.getMalformedTtlSeconds();
            case TIMEOUT:
            default:
                return cacheProps.getTimeoutTtlSeconds();
        }
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

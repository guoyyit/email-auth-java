package com.github.guoyyit.emailauthjava.dns;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.error.AuthError;
import com.github.guoyyit.emailauthjava.error.ResourceLimitException;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class CachingDnsResolver implements DnsResolver {
    private final DnsResolver delegate;
    private final AuthProperties properties;
    // 缓存键含结果类别（OK/NXDOMAIN/TIMEOUT/MALFORMED）：三类失败与 OK 分属
    // 相互独立的缓存空间，任一类的命中、更新或过期都不影响其它类别。
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();
    // 每个“版本 + 域 + 类型”当前指向的结果类别；指向为空表示未缓存或已过期。
    private final ConcurrentHashMap<String, DnsStatus> categoryPointers =
            new ConcurrentHashMap<>();
    // 以“版本 + 域 + 类型”为粒度的单飞锁。
    private final ConcurrentHashMap<String, Object> flightLocks = new ConcurrentHashMap<>();

    public CachingDnsResolver(DnsResolver delegate, AuthProperties properties) {
        this.delegate = delegate;
        this.properties = properties;
    }

    @Override
    public DnsResult resolve(String domain, RecordType type) {
        long version = currentVersion();
        return resolveForVersion(domain, type, version);
    }

    /**
     * 打开一个绑定固定数据版本的解析会话：会话内所有查询都基于同一版本快照，
     * 即使后台策略数据被替换也不会混用新旧记录。会话之间互不阻塞，共享全局缓存。
     */
    public DnsResolver openSession() {
        return new SessionResolver(this, currentVersion());
    }

    public void invalidate() {
        cache.clear();
        categoryPointers.clear();
    }

    private long currentVersion() {
        return delegate instanceof VersionedDnsResolver versioned ? versioned.version() : 0L;
    }

    DnsResult resolveForVersion(String domain, RecordType type, long version) {
        String baseKey = version + "|" + MapBackedDnsResolver.key(domain, type);
        long now = System.currentTimeMillis();
        DnsStatus category = categoryPointers.get(baseKey);
        if (category != null) {
            CacheEntry cached = cache.get(entryKey(baseKey, category));
            if (cached != null && cached.expiresAtMillis > now) {
                return cached.result;
            }
        }
        // 以“版本 + 键”为粒度的单飞（single-flight）：并发求值只产生一次底层解析。
        Object lock = flightLocks.computeIfAbsent(baseKey, k -> new Object());
        try {
            synchronized (lock) {
                DnsStatus current = categoryPointers.get(baseKey);
                if (current != null) {
                    CacheEntry cached = cache.get(entryKey(baseKey, current));
                    if (cached != null && cached.expiresAtMillis > System.currentTimeMillis()) {
                        return cached.result;
                    }
                }
                DnsResult result = queryDelegate(domain, type, version);
                checkSize(domain, type, result);
                long ttlSeconds = ttlFor(result);
                publish(baseKey, result, ttlSeconds);
                return result;
            }
        } finally {
            flightLocks.remove(baseKey, lock);
        }
    }

    private void publish(String baseKey, DnsResult result, long ttlSeconds) {
        DnsStatus newCategory = result.getStatus() == DnsStatus.OK ? DnsStatus.OK
                : result.getStatus();
        if (ttlSeconds <= 0) {
            // TTL 为 0：不写入缓存，并清掉该键此前指向的任何类别空间。
            categoryPointers.remove(baseKey);
            for (DnsStatus status : DnsStatus.values()) {
                cache.remove(entryKey(baseKey, status));
            }
            return;
        }
        DnsStatus previous = categoryPointers.put(baseKey, newCategory);
        if (previous != null && previous != newCategory) {
            // 结果类别切换：旧类别空间立即失效，两类空间互不沿用过期时间。
            cache.remove(entryKey(baseKey, previous));
        }
        cache.put(entryKey(baseKey, newCategory),
                new CacheEntry(result, System.currentTimeMillis() + ttlSeconds * 1000L));
    }

    private static String entryKey(String baseKey, DnsStatus category) {
        return baseKey + "|" + category.name();
    }

    private DnsResult queryDelegate(String domain, RecordType type, long wantedVersion) {
        if (delegate instanceof VersionedDnsResolver versioned) {
            return versioned.resolveAt(domain, type, wantedVersion);
        }
        return delegate.resolve(domain, type);
    }

    private long ttlFor(DnsResult result) {
        AuthProperties.Dns dns = properties.getDns();
        if (result.getStatus() != DnsStatus.OK) {
            return switch (result.getStatus()) {
                case NXDOMAIN -> dns.getNxdomainCacheTtlSeconds();
                case TIMEOUT -> dns.getTimeoutCacheTtlSeconds();
                case MALFORMED -> dns.getMalformedCacheTtlSeconds();
                default -> 0;
            };
        }
        // OK 结果的过期时间来自记录自身的 TTL；底层未提供时套用配置默认值。
        Long recordTtl = result.getTtlSeconds();
        if (recordTtl == null || recordTtl < 0) {
            return dns.getCacheTtlSeconds();
        }
        return recordTtl;
    }

    private void checkSize(String domain, RecordType type, DnsResult result) {
        int total = 0;
        if (result.getRecords() != null) {
            for (String record : result.getRecords()) {
                total += record.length();
            }
        }
        if (result.getExchangeNames() != null) {
            for (String exchange : result.getExchangeNames()) {
                total += exchange.length();
            }
        }
        if (total > properties.getLimits().getMaxDnsResponseBytes()) {
            throw new ResourceLimitException(AuthError.DNS_RESPONSE_TOO_LARGE,
                    "DNS response for " + domain + " " + type + " exceeds "
                            + properties.getLimits().getMaxDnsResponseBytes() + " bytes");
        }
    }

    private record CacheEntry(DnsResult result, long expiresAtMillis) {
    }

    private static final class SessionResolver implements DnsResolver {
        private final CachingDnsResolver owner;
        private final long version;
        private final ConcurrentHashMap<String, DnsResult> pinned = new ConcurrentHashMap<>();

        private SessionResolver(CachingDnsResolver owner, long version) {
            this.owner = owner;
            this.version = version;
        }

        @Override
        public DnsResult resolve(String domain, RecordType type) {
            String key = MapBackedDnsResolver.key(domain, type);
            DnsResult existing = pinned.get(key);
            if (existing != null) {
                return existing;
            }
            DnsResult result = owner.resolveForVersion(domain, type, version);
            DnsResult winner = pinned.putIfAbsent(key, result);
            return winner != null ? winner : result;
        }
    }
}

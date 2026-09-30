package com.github.guoyyit.emailauthjava.dns;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.error.AuthError;
import com.github.guoyyit.emailauthjava.error.ResourceLimitException;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class CachingDnsResolver implements DnsResolver {
    private static final long NEGATIVE_TTL_SECONDS = 60L;
    private static final long TIMEOUT_TTL_SECONDS = 5L;

    private final DnsResolver delegate;
    private final AuthProperties properties;
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

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
    }

    private long currentVersion() {
        return delegate instanceof VersionedDnsResolver versioned ? versioned.version() : 0L;
    }

    DnsResult resolveForVersion(String domain, RecordType type, long version) {
        String key = MapBackedDnsResolver.key(domain, type);
        long now = System.currentTimeMillis();
        CacheEntry cached = cache.get(key);
        if (cached != null && cached.version == version && cached.expiresAtMillis > now) {
            return cached.result;
        }
        // 以键为粒度的单飞（single-flight）：并发求值只产生一次底层解析。
        CacheEntry fetched = cache.compute(key, (k, existing) -> {
            if (existing != null && existing.version == version
                    && existing.expiresAtMillis > System.currentTimeMillis()) {
                return existing;
            }
            DnsResult result = queryDelegate(domain, type, version);
            checkSize(domain, type, result);
            long ttlSeconds = ttlFor(result);
            return new CacheEntry(result, version, System.currentTimeMillis() + ttlSeconds * 1000L);
        });
        return fetched.result;
    }

    private DnsResult queryDelegate(String domain, RecordType type, long wantedVersion) {
        if (delegate instanceof VersionedDnsResolver versioned) {
            return versioned.resolveAt(domain, type, wantedVersion);
        }
        return delegate.resolve(domain, type);
    }

    private long ttlFor(DnsResult result) {
        long configured = properties.getDns().getCacheTtlSeconds();
        return switch (result.getStatus()) {
            case OK -> configured;
            // 三类失败结果彼此独立缓存；TIMEOUT 使用极短 TTL，兼顾并发去重与快速故障恢复。
            case TIMEOUT -> Math.min(TIMEOUT_TTL_SECONDS, configured);
            default -> Math.min(NEGATIVE_TTL_SECONDS, configured);
        };
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

    private record CacheEntry(DnsResult result, long version, long expiresAtMillis) {
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

package com.github.guoyyit.emailauthjava.dns;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.error.AuthError;
import com.github.guoyyit.emailauthjava.error.ResourceLimitException;

import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.LongSupplier;

/**
 * 带缓存的解析器包装：
 * <ul>
 *   <li>成功结果按记录自身 TTL 过期（结果未携带 TTL 时回退到配置值，TTL 为 0 不缓存）；
 *       NXDOMAIN、TIMEOUT、MALFORMED 三类失败各自使用独立缓存空间与独立 TTL。</li>
 *   <li>以“版本 + 域 + 记录类型”为粒度单飞（single-flight），并发评估只触发一次底层解析。</li>
 *   <li>底层解析在独立线程执行并受 {@code emailauth.dns.timeout-millis} 约束；超时后
 *       中断底层查询线程、映射为 {@link DnsStatus#TIMEOUT}，不保留后台任务。</li>
 * </ul>
 * 被包装的 {@link DnsResolver#resolve} 实现应及时响应线程中断（抛出异常或返回
 * TIMEOUT 结果），以便超时后释放解析线程。
 */
public class CachingDnsResolver implements DnsResolver {
    private final DnsResolver delegate;
    private final AuthProperties properties;
    private final LongSupplier nowMillis;
    private final ExecutorService resolveExecutor;

    private final ConcurrentHashMap<String, CacheEntry> okCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CacheEntry> nxdomainCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CacheEntry> timeoutCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, CacheEntry> malformedCache =
            new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Flight> inflight =
            new ConcurrentHashMap<>();

    public CachingDnsResolver(DnsResolver delegate, AuthProperties properties) {
        this(delegate, properties, System::currentTimeMillis,
                Executors.newCachedThreadPool(runnable -> {
                    Thread thread = new Thread(runnable, "dns-resolve");
                    thread.setDaemon(true);
                    return thread;
                }));
    }

    public CachingDnsResolver(DnsResolver delegate, AuthProperties properties,
                              LongSupplier nowMillis) {
        this(delegate, properties, nowMillis,
                Executors.newCachedThreadPool(runnable -> {
                    Thread thread = new Thread(runnable, "dns-resolve");
                    thread.setDaemon(true);
                    return thread;
                }));
    }

    public CachingDnsResolver(DnsResolver delegate, AuthProperties properties,
                              LongSupplier nowMillis, ExecutorService resolveExecutor) {
        this.delegate = delegate;
        this.properties = properties;
        this.nowMillis = nowMillis;
        this.resolveExecutor = resolveExecutor;
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
        okCache.clear();
        nxdomainCache.clear();
        timeoutCache.clear();
        malformedCache.clear();
    }

    private long currentVersion() {
        return delegate instanceof VersionedDnsResolver versioned ? versioned.version() : 0L;
    }

    DnsResult resolveForVersion(String domain, RecordType type, long version) {
        String cacheKey = MapBackedDnsResolver.key(domain, type);
        long now = nowMillis.getAsLong();
        DnsResult cached = readCache(cacheKey, version, now);
        if (cached != null) {
            return cached;
        }
        // 以“版本 + 域 + 类型”为粒度的单飞：并发命中同一记录只产生一次底层解析。
        String flightKey = version + "#" + cacheKey;
        Flight flight = joinFlight(flightKey, domain, type, version, cacheKey);
        long timeoutMillis = Math.max(0L, properties.getDns().getTimeoutMillis());
        try {
            return flight.task.get(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (CancellationException e) {
            // 首个超时者取消了共享任务：所有并发等待方统一得到 TIMEOUT 结果。
            return new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
        } catch (TimeoutException e) {
            // 截断底层查询：中断解析线程，避免慢查询在后台继续运行并累积资源。
            flight.task.cancel(true);
            inflight.remove(flightKey, flight);
            DnsResult timeoutResult = new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
            storeFailure(cacheKey, version, timeoutResult);
            return timeoutResult;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("DNS resolution interrupted for " + cacheKey, e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            throw new IllegalStateException(cause);
        }
    }

    private Flight joinFlight(String flightKey, String domain, RecordType type, long version,
                              String cacheKey) {
        while (true) {
            Flight[] holder = new Flight[1];
            Flight created = new Flight(version, cacheKey,
                    new FutureTask<>(() -> {
                        try {
                            return resolveAndStore(domain, type, version, cacheKey);
                        } finally {
                            inflight.remove(flightKey, holder[0]);
                        }
                    }));
            holder[0] = created;
            Flight existing = inflight.putIfAbsent(flightKey, created);
            if (existing == null) {
                resolveExecutor.execute(created.task);
                return created;
            }
            if (!existing.task.isCancelled()) {
                return existing;
            }
            // 其他调用方刚刚触发超时取消，等条目被移除后加入新的单飞，
            // 避免加入一个注定收到 CancellationException 的任务。
            if (inflight.remove(flightKey, existing)) {
                continue;
            }
            return existing;
        }
    }

    private DnsResult resolveAndStore(String domain, RecordType type, long version,
                                      String cacheKey) {
        DnsResult result = queryDelegate(domain, type, version);
        if (Thread.currentThread().isInterrupted()) {
            return result;
        }
        checkSize(domain, type, result);
        if (result.getStatus() == DnsStatus.OK) {
            storeOk(cacheKey, version, result);
        } else {
            storeFailure(cacheKey, version, result);
        }
        return result;
    }

    private DnsResult readCache(String cacheKey, long version, long now) {
        // 四个空间互不共享条目：任一种结果的命中、更新、过期都不触碰其它空间。
        CacheEntry entry = okCache.get(cacheKey);
        if (entry == null) {
            entry = nxdomainCache.get(cacheKey);
        }
        if (entry == null) {
            entry = timeoutCache.get(cacheKey);
        }
        if (entry == null) {
            entry = malformedCache.get(cacheKey);
        }
        if (entry != null && entry.version == version && entry.expiresAtMillis > now) {
            return entry.result;
        }
        return null;
    }

    private void storeOk(String cacheKey, long version, DnsResult result) {
        long ttlSeconds = result.getTtlSeconds() == DnsResult.TTL_FROM_CONFIG
                ? properties.getDns().getCacheTtlSeconds() : result.getTtlSeconds();
        if (ttlSeconds <= 0) {
            return;
        }
        okCache.put(cacheKey,
                new CacheEntry(result, version, nowMillis.getAsLong() + ttlSeconds * 1000L));
    }

    private void storeFailure(String cacheKey, long version, DnsResult result) {
        long ttlSeconds = switch (result.getStatus()) {
            case NXDOMAIN -> properties.getDns().getNxdomainTtlSeconds();
            case TIMEOUT -> properties.getDns().getTimeoutTtlSeconds();
            case MALFORMED -> properties.getDns().getMalformedTtlSeconds();
            case OK -> 0L;
        };
        if (ttlSeconds <= 0) {
            return;
        }
        CacheEntry entry =
                new CacheEntry(result, version, nowMillis.getAsLong() + ttlSeconds * 1000L);
        switch (result.getStatus()) {
            case NXDOMAIN -> nxdomainCache.put(cacheKey, entry);
            case TIMEOUT -> timeoutCache.put(cacheKey, entry);
            case MALFORMED -> malformedCache.put(cacheKey, entry);
            default -> {
            }
        }
    }

    private DnsResult queryDelegate(String domain, RecordType type, long wantedVersion) {
        if (delegate instanceof VersionedDnsResolver versioned) {
            return versioned.resolveAt(domain, type, wantedVersion);
        }
        return delegate.resolve(domain, type);
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

    private record Flight(long version, String cacheKey, FutureTask<DnsResult> task) {
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

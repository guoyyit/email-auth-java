package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dns.CachingDnsResolver;
import com.github.guoyyit.emailauthjava.dns.DnsResolver;
import com.github.guoyyit.emailauthjava.dns.DnsResult;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.MapBackedDnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.error.ResourceLimitException;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CachingDnsResolverTest {

    @Test
    void cachesOkResultsAndCountsUnderlyingCalls() {
        AtomicInteger calls = new AtomicInteger();
        CachingDnsResolver caching = caching(new AuthProperties(), calls);
        for (int i = 0; i < 5; i++) {
            assertThat(caching.resolve("example.com", RecordType.TXT).getStatus())
                    .isEqualTo(DnsStatus.OK);
        }
        assertThat(calls).hasValue(1);
    }

    @Test
    void failureKindsAreKeptDistinct() {
        AtomicInteger calls = new AtomicInteger();
        AuthProperties properties = new AuthProperties();
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolve(String domain, RecordType type) {
                calls.incrementAndGet();
                return new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
            }
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                return resolve(domain, type);
            }
        };
        CachingDnsResolver caching = new CachingDnsResolver(backend, properties);
        assertThat(caching.resolve("x.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.TIMEOUT);
        assertThat(caching.resolve("x.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.TIMEOUT);
        assertThat(calls.get()).isGreaterThanOrEqualTo(1);
    }

    @Test
    void eachRecordUsesItsOwnTtlAndRefetchesAfterExpiry() throws Exception {
        AuthProperties properties = new AuthProperties();
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>());
        AtomicInteger calls = new AtomicInteger();
        backend.putWithTtl("fast.example", RecordType.TXT, List.of("v=spf1 -all"), 1L);
        backend.putWithTtl("slow.example", RecordType.TXT, List.of("v=spf1 -all"), 30L);
        CachingDnsResolver caching = new CachingDnsResolver(new MapBackedDnsResolver(
                new HashMap<>()) {
            @Override
            public DnsResult resolve(String domain, RecordType type) {
                calls.incrementAndGet();
                return backend.resolve(domain, type);
            }
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                calls.incrementAndGet();
                return backend.resolveAt(domain, type, version);
            }
        }, properties);

        assertThat(caching.resolve("fast.example", RecordType.TXT).getStatus()).isEqualTo(DnsStatus.OK);
        assertThat(caching.resolve("slow.example", RecordType.TXT).getStatus()).isEqualTo(DnsStatus.OK);
        assertThat(calls).hasValue(2);

        caching.resolve("fast.example", RecordType.TXT);
        caching.resolve("slow.example", RecordType.TXT);
        assertThat(calls).hasValue(2);

        Thread.sleep(1200);
        // fast（TTL 1s）必须重新解析；slow（TTL 30s）仍命中自己的缓存。
        caching.resolve("fast.example", RecordType.TXT);
        caching.resolve("slow.example", RecordType.TXT);
        assertThat(calls).hasValue(3);
    }

    @Test
    void zeroTtlRecordIsNeverCached() {
        AuthProperties properties = new AuthProperties();
        AtomicInteger calls = new AtomicInteger();
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolve(String domain, RecordType type) {
                calls.incrementAndGet();
                return super.resolve(domain, type);
            }
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                calls.incrementAndGet();
                return super.resolveAt(domain, type, version);
            }
        };
        backend.putWithTtl("volatile.example", RecordType.TXT,
                List.of("v=spf1 -all"), 0L);
        CachingDnsResolver caching = new CachingDnsResolver(backend, properties);
        caching.resolve("volatile.example", RecordType.TXT);
        caching.resolve("volatile.example", RecordType.TXT);
        assertThat(calls).hasValue(2);
    }

    @Test
    void failureCategoriesHaveIndependentSpacesAndTtls() throws Exception {
        AuthProperties properties = new AuthProperties();
        properties.getDns().setNxdomainCacheTtlSeconds(1L);
        properties.getDns().setTimeoutCacheTtlSeconds(30L);
        properties.getDns().setMalformedCacheTtlSeconds(30L);
        AtomicInteger nxCalls = new AtomicInteger();
        AtomicInteger timeoutCalls = new AtomicInteger();
        AtomicInteger malformedCalls = new AtomicInteger();
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolve(String domain, RecordType type) {
                switch (domain) {
                    case "nx.example":
                        nxCalls.incrementAndGet();
                        return new DnsResult(DnsStatus.NXDOMAIN, List.of(), List.of());
                    case "to.example":
                        timeoutCalls.incrementAndGet();
                        return new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
                    default:
                        malformedCalls.incrementAndGet();
                        return new DnsResult(DnsStatus.MALFORMED, List.of(), List.of());
                }
            }
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                return resolve(domain, type);
            }
        };
        CachingDnsResolver caching = new CachingDnsResolver(backend, properties);

        caching.resolve("nx.example", RecordType.TXT);
        caching.resolve("to.example", RecordType.TXT);
        caching.resolve("mf.example", RecordType.TXT);
        caching.resolve("nx.example", RecordType.TXT);
        caching.resolve("to.example", RecordType.TXT);
        caching.resolve("mf.example", RecordType.TXT);
        assertThat(nxCalls).hasValue(1);
        assertThat(timeoutCalls).hasValue(1);
        assertThat(malformedCalls).hasValue(1);

        Thread.sleep(1200);
        // NXDOMAIN（1s）到期重查；TIMEOUT/MALFORMED（30s）各自命中不受影响。
        caching.resolve("nx.example", RecordType.TXT);
        caching.resolve("to.example", RecordType.TXT);
        caching.resolve("mf.example", RecordType.TXT);
        assertThat(nxCalls).hasValue(2);
        assertThat(timeoutCalls).hasValue(1);
        assertThat(malformedCalls).hasValue(1);
    }

    @Test
    void failureCategoryChangeDoesNotReuseOtherSpace() throws Exception {
        AuthProperties properties = new AuthProperties();
        properties.getDns().setTimeoutCacheTtlSeconds(1L);
        java.util.concurrent.atomic.AtomicBoolean timedOut =
                new java.util.concurrent.atomic.AtomicBoolean(true);
        AtomicInteger calls = new AtomicInteger();
        MapBackedDnsResolver timed = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolve(String domain, RecordType type) {
                calls.incrementAndGet();
                return timedOut.get()
                        ? new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of())
                        : new DnsResult(DnsStatus.OK, List.of("v=spf1 -all"), List.of(), 30L);
            }
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                return resolve(domain, type);
            }
        };
        CachingDnsResolver caching = new CachingDnsResolver(timed, properties);
        assertThat(caching.resolve("flip.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.TIMEOUT);
        int afterFirst = calls.get();
        Thread.sleep(1200);
        timedOut.set(false);
        // TIMEOUT 空间过期后重新解析得到 OK：立即生效，之后命中新的 OK 空间，
        // 不沿用 TIMEOUT 空间的过期时间。
        assertThat(caching.resolve("flip.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.OK);
        assertThat(caching.resolve("flip.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.OK);
        assertThat(calls.get()).isEqualTo(afterFirst + 1);
    }

    @Test
    void zeroTtlFailureIsNotCached() {
        AuthProperties properties = new AuthProperties();
        properties.getDns().setTimeoutCacheTtlSeconds(0L);
        AtomicInteger calls = new AtomicInteger();
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolve(String domain, RecordType type) {
                calls.incrementAndGet();
                return new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
            }
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                return resolve(domain, type);
            }
        };
        CachingDnsResolver caching = new CachingDnsResolver(backend, properties);
        caching.resolve("nocache.example", RecordType.TXT);
        caching.resolve("nocache.example", RecordType.TXT);
        assertThat(calls).hasValue(2);
    }

    @Test
    void concurrentResolutionHappensOnce() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolve(String domain, RecordType type) {
                calls.incrementAndGet();
                inside.countDown();
                try {
                    release.await(2, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
                }
                return new DnsResult(DnsStatus.OK, List.of("v=spf1 -all"), List.of());
            }
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                return resolve(domain, type);
            }
        };
        CachingDnsResolver caching = new CachingDnsResolver(backend, new AuthProperties());
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch done = new CountDownLatch(8);
        for (int i = 0; i < 8; i++) {
            pool.submit(() -> {
                caching.resolve("hot.example", RecordType.TXT);
                done.countDown();
            });
        }
        assertThat(inside.await(2, TimeUnit.SECONDS)).isTrue();
        release.countDown();
        assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
        pool.shutdown();
        assertThat(calls).hasValue(1);
    }

    @Test
    void sessionPinsSnapshotAcrossPolicyReplacement() {
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>());
        backend.put("example.com", RecordType.TXT, DnsStatus.OK, List.of("v=spf1 -all"));
        CachingDnsResolver caching = new CachingDnsResolver(backend, new AuthProperties());

        DnsResolver session = caching.openSession();
        assertThat(session.resolve("example.com", RecordType.TXT).getRecords())
                .containsExactly("v=spf1 -all");

        backend.replaceAll(new HashMap<>());
        backend.put("example.com", RecordType.TXT, DnsStatus.OK, List.of("v=spf1 +all"));

        // 旧会话仍看到旧记录，新会话看到新记录。
        assertThat(session.resolve("example.com", RecordType.TXT).getRecords())
                .containsExactly("v=spf1 -all");
        assertThat(caching.resolve("example.com", RecordType.TXT).getRecords())
                .containsExactly("v=spf1 +all");
    }

    @Test
    void oversizedResponseIsRejected() {
        AuthProperties properties = new AuthProperties();
        properties.getLimits().setMaxDnsResponseBytes(16);
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>());
        backend.put("big.example", RecordType.TXT, DnsStatus.OK,
                List.of("x".repeat(100)));
        CachingDnsResolver caching = new CachingDnsResolver(backend, properties);
        assertThatThrownBy(() -> caching.resolve("big.example", RecordType.TXT))
                .isInstanceOf(ResourceLimitException.class);
    }

    private CachingDnsResolver caching(AuthProperties properties, AtomicInteger calls) {
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolve(String domain, RecordType type) {
                calls.incrementAndGet();
                return super.resolve(domain, type);
            }
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                calls.incrementAndGet();
                return super.resolveAt(domain, type, version);
            }
        };
        backend.put("example.com", RecordType.TXT, DnsStatus.OK, List.of("v=spf1 -all"));
        return new CachingDnsResolver(backend, properties);
    }
}

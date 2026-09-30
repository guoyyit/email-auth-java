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

package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dns.CachingDnsResolver;
import com.github.guoyyit.emailauthjava.dns.DnsResult;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.MapBackedDnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

class DnsCacheBehaviorTest {

    private static final class CountingBackend extends MapBackedDnsResolver {
        private final AtomicInteger calls = new AtomicInteger();

        private CountingBackend(Map<String, DnsResult> records) {
            super(records);
        }

        @Override
        public DnsResult resolveAt(String domain, RecordType type, long version) {
            calls.incrementAndGet();
            return super.resolveAt(domain, type, version);
        }
    }

    private AuthProperties props() {
        AuthProperties properties = new AuthProperties();
        properties.getDns().setTimeoutMillis(5_000);
        return properties;
    }

    @Test
    void eachRecordUsesItsOwnTtl() {
        CountingBackend backend = new CountingBackend(new HashMap<>());
        backend.put("short.example", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 -all"), List.of(), 2);
        backend.put("long.example", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 -all"), List.of(), 100);
        AtomicLong clock = new AtomicLong(1_000_000);
        CachingDnsResolver resolver =
                new CachingDnsResolver(backend, props(), clock::get);

        resolver.resolve("short.example", RecordType.TXT);
        resolver.resolve("long.example", RecordType.TXT);

        // 仅推进 3 秒：短 TTL 记录过期重新解析，长 TTL 记录仍命中缓存。
        clock.set(1_003_000);
        resolver.resolve("short.example", RecordType.TXT);
        resolver.resolve("long.example", RecordType.TXT);
        assertThat(backend.calls.get()).isEqualTo(3);

        // 推进到 101 秒：长 TTL 记录也过期，两条都重新解析。
        clock.set(1_101_000);
        resolver.resolve("short.example", RecordType.TXT);
        resolver.resolve("long.example", RecordType.TXT);
        assertThat(backend.calls.get()).isEqualTo(5);
    }

    @Test
    void zeroTtlRecordIsNeverCachedAndRefetched() {
        CountingBackend backend = new CountingBackend(new HashMap<>());
        backend.put("nocache.example", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 -all"), List.of(), 0);
        CachingDnsResolver resolver =
                new CachingDnsResolver(backend, props(), new AtomicLong()::get);

        for (int i = 0; i < 3; i++) {
            assertThat(resolver.resolve("nocache.example", RecordType.TXT).getStatus())
                    .isEqualTo(DnsStatus.OK);
        }
        assertThat(backend.calls.get()).isEqualTo(3);
    }

    @Test
    void multiValueAnswerSharesSingleTtlAndExpiresAsWhole() {
        CountingBackend backend = new CountingBackend(new HashMap<>());
        backend.put("mx.example", RecordType.MX, DnsStatus.OK,
                List.of("10 m1.example", "20 m2.example"), List.of(), 4);
        AtomicLong clock = new AtomicLong(0);
        CachingDnsResolver resolver =
                new CachingDnsResolver(backend, props(), clock::get);

        assertThat(resolver.resolve("mx.example", RecordType.MX).getRecords()).hasSize(2);
        clock.set(3_999);
        assertThat(resolver.resolve("mx.example", RecordType.MX).getRecords()).hasSize(2);
        assertThat(backend.calls.get()).isEqualTo(1);
        clock.set(4_001);
        assertThat(resolver.resolve("mx.example", RecordType.MX).getStatus())
                .isEqualTo(DnsStatus.OK);
        assertThat(backend.calls.get()).isEqualTo(2);
    }

    @Test
    void resultWithoutTtlFallsBackToConfiguredTtl() {
        CountingBackend backend = new CountingBackend(new HashMap<>());
        backend.put("example.com", RecordType.TXT, DnsStatus.OK, List.of("v=spf1 -all"));
        AuthProperties properties = props();
        properties.getDns().setCacheTtlSeconds(10);
        AtomicLong clock = new AtomicLong(0);
        CachingDnsResolver resolver =
                new CachingDnsResolver(backend, properties, clock::get);

        resolver.resolve("example.com", RecordType.TXT);
        clock.set(9_999);
        resolver.resolve("example.com", RecordType.TXT);
        assertThat(backend.calls.get()).isEqualTo(1);
        clock.set(10_001);
        resolver.resolve("example.com", RecordType.TXT);
        assertThat(backend.calls.get()).isEqualTo(2);
    }

    @Test
    void failureKindsUseIndependentSpacesAndTtls() {
        CountingBackend backend = new CountingBackend(new HashMap<>());
        AuthProperties properties = props();
        properties.getDns().setNxdomainTtlSeconds(60);
        properties.getDns().setTimeoutTtlSeconds(2);
        properties.getDns().setMalformedTtlSeconds(30);
        AtomicLong clock = new AtomicLong(0);
        CachingDnsResolver resolver =
                new CachingDnsResolver(backend, properties, clock::get);

        backend.put("nx.example", RecordType.TXT,
                new DnsResult(DnsStatus.NXDOMAIN, List.of(), List.of()));
        backend.put("to.example", RecordType.TXT,
                new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of()));
        backend.put("mf.example", RecordType.TXT,
                new DnsResult(DnsStatus.MALFORMED, List.of(), List.of()));

        assertThat(resolver.resolve("nx.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.NXDOMAIN);
        assertThat(resolver.resolve("to.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.TIMEOUT);
        assertThat(resolver.resolve("mf.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.MALFORMED);

        // 推进 3 秒：TIMEOUT 过期重新解析（底层恢复为 NXDOMAIN），
        // NXDOMAIN 与 MALFORMED 仍各自命中、互不影响。
        clock.set(3_000);
        backend.put("to.example", RecordType.TXT,
                new DnsResult(DnsStatus.NXDOMAIN, List.of(), List.of()));
        assertThat(resolver.resolve("to.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.NXDOMAIN);
        assertThat(resolver.resolve("nx.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.NXDOMAIN);
        assertThat(resolver.resolve("mf.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.MALFORMED);

        // 再推进到 31 秒：MALFORMED 过期，NXDOMAIN（60 秒）仍然命中。
        clock.set(31_000);
        backend.put("mf.example", RecordType.TXT,
                new DnsResult(DnsStatus.NXDOMAIN, List.of(), List.of()));
        assertThat(resolver.resolve("mf.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.NXDOMAIN);
        assertThat(resolver.resolve("nx.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.NXDOMAIN);

        // 61 秒：NXDOMAIN 也过期，底层改为 OK。
        clock.set(61_000);
        backend.put("nx.example", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 -all"));
        assertThat(resolver.resolve("nx.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.OK);
    }

    @Test
    void failureTtlZeroDisablesCachingForThatKindOnly() {
        CountingBackend backend = new CountingBackend(new HashMap<>());
        backend.put("to.example", RecordType.TXT,
                new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of()));
        backend.put("nx.example", RecordType.TXT,
                new DnsResult(DnsStatus.NXDOMAIN, List.of(), List.of()));
        AuthProperties properties = props();
        properties.getDns().setTimeoutTtlSeconds(0);
        CachingDnsResolver resolver =
                new CachingDnsResolver(backend, properties, new AtomicLong()::get);

        for (int i = 0; i < 3; i++) {
            assertThat(resolver.resolve("to.example", RecordType.TXT).getStatus())
                    .isEqualTo(DnsStatus.TIMEOUT);
        }
        assertThat(backend.calls.get()).isEqualTo(3);

        // 其它失败种类的缓存不受影响：NXDOMAIN 仍被缓存。
        for (int i = 0; i < 3; i++) {
            assertThat(resolver.resolve("nx.example", RecordType.TXT).getStatus())
                    .isEqualTo(DnsStatus.NXDOMAIN);
        }
        assertThat(backend.calls.get()).isEqualTo(4);
    }

    @Test
    void slowResolutionIsCutOffByConfiguredTimeoutAndThreadIsInterrupted()
            throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch interrupted = new CountDownLatch(1);
        MapBackedDnsResolver slow = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                entered.countDown();
                try {
                    Thread.sleep(30_000);
                } catch (InterruptedException e) {
                    interrupted.countDown();
                    Thread.currentThread().interrupt();
                    return new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
                }
                return new DnsResult(DnsStatus.OK, List.of("v=spf1 -all"), List.of());
            }
        };
        AuthProperties properties = props();
        properties.getDns().setTimeoutMillis(80);
        CachingDnsResolver resolver =
                new CachingDnsResolver(slow, properties, new AtomicLong()::get);

        long start = System.nanoTime();
        assertThat(resolver.resolve("slow.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.TIMEOUT);
        assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start))
                .isLessThan(2_000);
        assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
        // 被截断的查询不得继续在后台运行：底层线程必须收到中断并退出。
        assertThat(interrupted.await(2, TimeUnit.SECONDS)).isTrue();
    }

    @Test
    void timedOutResultIsRefetchedImmediatelyWhenTimeoutTtlZero() throws Exception {
        AtomicInteger attempts = new AtomicInteger();
        MapBackedDnsResolver flapping = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                if ("f.example".equals(domain) && attempts.getAndIncrement() == 0) {
                    try {
                        Thread.sleep(30_000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                return new DnsResult(DnsStatus.OK, List.of("v=spf1 -all"), List.of());
            }
        };
        AuthProperties properties = props();
        properties.getDns().setTimeoutMillis(50);
        properties.getDns().setTimeoutTtlSeconds(0);
        CachingDnsResolver resolver =
                new CachingDnsResolver(flapping, properties, new AtomicLong()::get);

        assertThat(resolver.resolve("f.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.TIMEOUT);
        // TIMEOUT 失败 TTL 为 0：再次请求立即重新解析，底层已恢复，返回新值。
        assertThat(resolver.resolve("f.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.OK);
        assertThat(attempts.get()).isEqualTo(2);
    }

    @Test
    void defaultTimeoutIsUsedWhenUnconfigured() {
        AuthProperties properties = new AuthProperties();
        // 未设置时使用文档声明的默认值 3000ms。
        assertThat(properties.getDns().getTimeoutMillis()).isEqualTo(3_000);

        MapBackedDnsResolver fast = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                return new DnsResult(DnsStatus.OK, List.of("v=spf1 -all"), List.of());
            }
        };
        CachingDnsResolver resolver =
                new CachingDnsResolver(fast, properties, new AtomicLong()::get);
        assertThat(resolver.resolve("ok.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.OK);

        // 慢于默认值的解析在默认配置下也会被截断。
        MapBackedDnsResolver slow = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                try {
                    Thread.sleep(5_000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
            }
        };
        CachingDnsResolver slowResolver =
                new CachingDnsResolver(slow, properties, new AtomicLong()::get);
        long start = System.nanoTime();
        assertThat(slowResolver.resolve("slow.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.TIMEOUT);
        assertThat(TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - start))
                .isLessThan(4);
    }

    @Test
    void slowKeyDoesNotBlockConcurrentOtherKeys() throws Exception {
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                if ("slow.example".equals(domain)) {
                    try {
                        Thread.sleep(30_000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
                }
                return new DnsResult(DnsStatus.OK, List.of("v=spf1 -all"), List.of());
            }
        };
        AuthProperties properties = props();
        properties.getDns().setTimeoutMillis(100);
        CachingDnsResolver resolver =
                new CachingDnsResolver(backend, properties, new AtomicLong()::get);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            long start = System.nanoTime();
            Future<DnsResult> slowCall = pool.submit(
                    () -> resolver.resolve("slow.example", RecordType.TXT));
            Future<DnsResult> fastCall = pool.submit(
                    () -> resolver.resolve("fast.example", RecordType.TXT));
            assertThat(fastCall.get(2, TimeUnit.SECONDS).getStatus())
                    .isEqualTo(DnsStatus.OK);
            assertThat(slowCall.get(2, TimeUnit.SECONDS).getStatus())
                    .isEqualTo(DnsStatus.TIMEOUT);
            assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start))
                    .isLessThan(1_500);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void concurrentHitOfSameSlowRecordTriggersOneUnderlyingCall() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(1);
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                calls.incrementAndGet();
                entered.countDown();
                try {
                    Thread.sleep(30_000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
            }
        };
        AuthProperties properties = props();
        properties.getDns().setTimeoutMillis(100);
        CachingDnsResolver resolver =
                new CachingDnsResolver(backend, properties, new AtomicLong()::get);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<DnsStatus>> results = new java.util.ArrayList<>();
            for (int i = 0; i < 8; i++) {
                results.add(pool.submit(
                        () -> resolver.resolve("hot.example", RecordType.TXT).getStatus()));
            }
            assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
            for (Future<DnsStatus> result : results) {
                assertThat(result.get(2, TimeUnit.SECONDS)).isEqualTo(DnsStatus.TIMEOUT);
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(calls.get()).isEqualTo(1);
    }
}

package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dns.DnsResult;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.MapBackedDnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.dns.TimedDnsResolver;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class TimedDnsResolverTest {

    @Test
    void slowQueryIsTruncatedByConfiguredTimeout() throws Exception {
        AuthProperties properties = new AuthProperties();
        properties.getDns().setTimeoutMillis(100);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch interrupted = new CountDownLatch(1);
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                started.countDown();
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    interrupted.countDown();
                    Thread.currentThread().interrupt();
                }
                return new DnsResult(DnsStatus.OK, List.of("v=spf1 -all"), List.of());
            }
        };
        TimedDnsResolver timed = new TimedDnsResolver(backend, properties);

        long begin = System.nanoTime();
        DnsResult result = timed.resolve("slow.example", RecordType.TXT);
        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - begin);

        assertThat(result.getStatus()).isEqualTo(DnsStatus.TIMEOUT);
        assertThat(elapsedMillis).isLessThan(1000);
        assertThat(started.await(1, TimeUnit.SECONDS)).isTrue();
        // 被截断的查询不得继续在后台运行：工作线程必须收到中断。
        assertThat(interrupted.await(2, TimeUnit.SECONDS)).isTrue();
        timed.close();
    }

    @Test
    void defaultTimeoutAllowsFastQueries() {
        AuthProperties properties = new AuthProperties();
        assertThat(properties.getDns().getTimeoutMillis()).isEqualTo(3000);
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>());
        backend.put("fast.example", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 -all"));
        TimedDnsResolver timed = new TimedDnsResolver(backend, properties);
        assertThat(timed.resolve("fast.example", RecordType.TXT).getStatus())
                .isEqualTo(DnsStatus.OK);
        timed.close();
    }

    @Test
    void slowQueriesDoNotBlockConcurrentEvaluations() throws Exception {
        AuthProperties properties = new AuthProperties();
        properties.getDns().setTimeoutMillis(80);
        AtomicInteger active = new AtomicInteger();
        CountDownLatch started = new CountDownLatch(5);
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                active.incrementAndGet();
                started.countDown();
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    active.decrementAndGet();
                }
                return new DnsResult(DnsStatus.OK, List.of(), List.of());
            }
        };
        TimedDnsResolver timed = new TimedDnsResolver(backend, properties);
        List<Thread> callers = new java.util.ArrayList<>();
        AtomicInteger timeouts = new AtomicInteger();
        for (int i = 0; i < 5; i++) {
            Thread thread = new Thread(() -> {
                if (timed.resolve("slow" + System.nanoTime(), RecordType.TXT).getStatus()
                        == DnsStatus.TIMEOUT) {
                    timeouts.incrementAndGet();
                }
            });
            callers.add(thread);
            thread.start();
        }
        for (Thread thread : callers) {
            thread.join(3000);
            assertThat(thread.isAlive()).isFalse();
        }
        assertThat(timeouts).hasValue(5);
        assertThat(started.getCount()).isZero();
        // 后台查询被中断后必须真正退出，不能累积活动线程。
        long deadline = System.currentTimeMillis() + 2000;
        while (active.get() > 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
        assertThat(active.get()).isZero();
        timed.close();
    }
}

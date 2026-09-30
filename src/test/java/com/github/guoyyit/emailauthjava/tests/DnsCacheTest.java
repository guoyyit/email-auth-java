package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dns.DnsAnswer;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.InMemoryDnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class DnsCacheTest {

    @Test
    void cachesPositiveAnswersByTypeAndTtl() {
        AuthProperties properties = new AuthProperties();
        properties.getCache().setMaxPositiveTtlSeconds(60);
        InMemoryDnsResolver resolver = new InMemoryDnsResolver();
        resolver.putTxt("example.com", "v=spf1 -all");
        DnsCache cache = new DnsCache(resolver, properties);

        DnsAnswer first = cache.query("example.com", RecordType.TXT);
        DnsAnswer second = cache.query("example.com", RecordType.TXT);
        assertEquals(DnsStatus.OK, first.getStatus());
        assertEquals(1, resolver.underlyingQueryCount("example.com", RecordType.TXT));
        assertEquals(1, resolver.underlyingQueryCount("example.com", RecordType.TXT));
        assertEquals(DnsStatus.OK, second.getStatus());
    }

    @Test
    void failureClassesAreIsolated() {
        AuthProperties properties = new AuthProperties();
        InMemoryDnsResolver resolver = new InMemoryDnsResolver();
        DnsCache cache = new DnsCache(resolver, properties);
        assertEquals(DnsStatus.NXDOMAIN,
                cache.query("nx.example", RecordType.TXT).getStatus());

        resolver.putFailure("slow.example", RecordType.TXT, DnsStatus.TIMEOUT);
        assertEquals(DnsStatus.TIMEOUT,
                cache.query("slow.example", RecordType.TXT).getStatus());

        resolver.putFailure("bad.example", RecordType.TXT, DnsStatus.MALFORMED);
        assertEquals(DnsStatus.MALFORMED,
                cache.query("bad.example", RecordType.TXT).getStatus());
    }

    @Test
    void concurrentSameKeyResolvesOnce() throws Exception {
        AuthProperties properties = new AuthProperties();
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        DnsCache cache = new DnsCache((name, type) -> {
            calls.incrementAndGet();
            entered.countDown();
            try {
                release.await(2, TimeUnit.SECONDS);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
            return DnsAnswer.failure(DnsStatus.NXDOMAIN);
        }, properties);

        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch done = new CountDownLatch(8);
        for (int i = 0; i < 8; i++) {
            pool.submit(() -> {
                cache.query("hot.example", RecordType.TXT);
                done.countDown();
            });
        }
        entered.await(2, TimeUnit.SECONDS);
        release.countDown();
        done.await(5, TimeUnit.SECONDS);
        pool.shutdown();
        assertEquals(1, calls.get());
    }

    @Test
    void invalidationAdvancesSnapshotVersion() {
        AuthProperties properties = new AuthProperties();
        InMemoryDnsResolver resolver = new InMemoryDnsResolver();
        DnsCache cache = new DnsCache(resolver, properties);
        resolver.putTxt("dyn.example", "v=spf1 -all");

        long version = cache.beginSnapshot();
        assertEquals(DnsStatus.OK,
                cache.queryAtVersion(version, "dyn.example", RecordType.TXT).getStatus());
        cache.invalidateAll();
        long newVersion = cache.beginSnapshot();
        assertNotEquals(version, newVersion);
    }
}

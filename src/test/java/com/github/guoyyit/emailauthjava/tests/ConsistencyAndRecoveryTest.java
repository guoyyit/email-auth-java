package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.DmarcEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.DmarcPolicyAction;
import com.github.guoyyit.emailauthjava.dmarc.OrganizationalDomain;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.dns.InMemoryDnsResolver;
import com.github.guoyyit.emailauthjava.eval.AuthResult;
import com.github.guoyyit.emailauthjava.eval.AuthService;
import com.github.guoyyit.emailauthjava.mail.MailParser;
import com.github.guoyyit.emailauthjava.report.AggregateBucket;
import com.github.guoyyit.emailauthjava.report.AggregateKey;
import com.github.guoyyit.emailauthjava.report.AggregateStore;
import com.github.guoyyit.emailauthjava.spf.SpfEvaluator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConsistencyAndRecoveryTest {

    @Test
    void singleEvaluationUsesConsistentSnapshot(@TempDir Path dir) throws Exception {
        AuthProperties properties = new AuthProperties();
        properties.getReport().setStoreDir(dir.resolve("agg").toString());
        InMemoryDnsResolver resolver = new InMemoryDnsResolver();
        DnsCache cache = new DnsCache(resolver, properties);
        MailParser parser = new MailParser(properties);
        SpfEvaluator spf = new SpfEvaluator(cache, properties);
        DkimEvaluator dkim = new DkimEvaluator(cache, properties);
        DmarcEvaluator dmarc = new DmarcEvaluator(cache, properties,
                new OrganizationalDomain(properties));
        AggregateStore store = new AggregateStore(properties);
        AuthService service = new AuthService(parser, spf, dkim, dmarc, store, cache);

        resolver.putTxt("example.com", "v=spf1 ip4:192.0.2.1 -all");
        resolver.putTxt("_dmarc.example.com", "v=DMARC1; p=none");
        byte[] message = ("From: a@example.com\r\n\r\nb\r\n").getBytes(StandardCharsets.UTF_8);

        long oldVersion = cache.beginSnapshot();
        assertEquals(com.github.guoyyit.emailauthjava.spf.SpfStatus.PASS,
                spf.evaluate(oldVersion, "192.0.2.1", "example.com", "<a@example.com>").getStatus());

        resolver.remove("example.com", com.github.guoyyit.emailauthjava.dns.RecordType.TXT);
        resolver.putTxt("example.com", "v=spf1 -all");
        cache.invalidateAll();

        assertEquals(com.github.guoyyit.emailauthjava.spf.SpfStatus.PASS,
                spf.evaluate(oldVersion, "192.0.2.1", "example.com", "<a@example.com>").getStatus());

        long newVersion = cache.beginSnapshot();
        assertEquals(com.github.guoyyit.emailauthjava.spf.SpfStatus.FAIL,
                spf.evaluate(newVersion, "192.0.2.1", "example.com", "<a@example.com>").getStatus());
    }

    @Test
    void concurrentEvaluationsDoNotBlockAndShareResults(@TempDir Path dir) throws Exception {
        AuthProperties properties = new AuthProperties();
        properties.getReport().setStoreDir(dir.resolve("agg").toString());
        InMemoryDnsResolver resolver = new InMemoryDnsResolver();
        DnsCache cache = new DnsCache(resolver, properties);
        MailParser parser = new MailParser(properties);
        SpfEvaluator spf = new SpfEvaluator(cache, properties);
        DkimEvaluator dkim = new DkimEvaluator(cache, properties);
        DmarcEvaluator dmarc = new DmarcEvaluator(cache, properties,
                new OrganizationalDomain(properties));
        AggregateStore store = new AggregateStore(properties);
        AuthService service = new AuthService(parser, spf, dkim, dmarc, store, cache);

        resolver.putTxt("example.com", "v=spf1 ip4:192.0.2.0/24 -all");
        resolver.putTxt("_dmarc.example.com", "v=DMARC1; p=reject");
        byte[] message = ("From: a@example.com\r\n\r\nb\r\n").getBytes(StandardCharsets.UTF_8);

        int threads = 15;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentHashMap<String, AtomicInteger> results = new ConcurrentHashMap<>();
        for (int i = 0; i < threads; i++) {
            int index = i;
            pool.submit(() -> {
                try {
                    start.await();
                    AuthResult result = service.evaluate(message,
                            "192.0.2." + (index + 1), "example.com", "<a@example.com>");
                    results.computeIfAbsent(
                                    result.getDmarc().getDisposition().name(),
                                    key -> new AtomicInteger())
                            .incrementAndGet();
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(15, TimeUnit.SECONDS));
        pool.shutdown();
        assertEquals(threads, results.get("NONE").get());
    }

    @Test
    void aggregateDataSurvivesCrashAndRecovery(@TempDir Path dir) {
        AuthProperties properties = new AuthProperties();
        properties.getReport().setStoreDir(dir.resolve("crash").toString());
        AggregateStore first = new AggregateStore(properties);
        first.record(new AggregateKey("<crash@x>", "203.0.113.9", "example.com", Instant.now()),
                Instant.now(), "fail", "example.com", "fail", "example.com", "reject");

        assertTrue(Files.exists(dir.resolve("crash")));

        AggregateStore recovered = new AggregateStore(properties);
        List<AggregateBucket> buckets = recovered.bucketsFor("example.com");
        assertEquals(1, buckets.size());
        assertEquals("reject", buckets.get(0).getDisposition());
    }
}

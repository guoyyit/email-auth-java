package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimStatus;
import com.github.guoyyit.emailauthjava.dmarc.DmarcDisposition;
import com.github.guoyyit.emailauthjava.dns.CachingDnsResolver;
import com.github.guoyyit.emailauthjava.dns.DnsResult;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dkim.DkimEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.DmarcEvaluator;
import com.github.guoyyit.emailauthjava.dns.MapBackedDnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.message.MessageParser;
import com.github.guoyyit.emailauthjava.report.ReportStore;
import com.github.guoyyit.emailauthjava.service.AuthenticationService;
import com.github.guoyyit.emailauthjava.service.EvaluationResult;
import com.github.guoyyit.emailauthjava.spf.SpfEvaluator;
import com.github.guoyyit.emailauthjava.spf.SpfStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationServiceIntegrationTest {
    private MapBackedDnsResolver backend;
    private CachingDnsResolver caching;
    private AuthenticationService service;
    private AuthProperties properties;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        backend = new MapBackedDnsResolver(new HashMap<>());
        properties = new AuthProperties();
        properties.getReport().setStoragePath(tempDir.resolve("r").toString());
        caching = new CachingDnsResolver(backend, properties);
        SpfEvaluator spf = new SpfEvaluator(caching, properties);
        DkimEvaluator dkim = new DkimEvaluator(caching, properties);
        DmarcEvaluator dmarc = new DmarcEvaluator(caching, properties);
        service = new AuthenticationService(spf, dkim, dmarc,
                new MessageParser(properties), new ReportStore(properties), properties);
    }

    @Test
    void spfPassDmarcNoneWithoutDkimPolicy() {
        backend.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ip4:192.0.2.10 -all"));
        byte[] message = ("From: user@example.com\r\n\r\nHi\r\n")
                .getBytes(StandardCharsets.UTF_8);

        EvaluationResult result = service.evaluate("mail.example.com", "192.0.2.10",
                "user@example.com", message);

        assertThat(result.getSpf().getStatus()).isEqualTo(SpfStatus.PASS);
        assertThat(result.getDkim().get(0).getStatus()).isEqualTo(DkimStatus.NONE);
    }

    @Test
    void fullDkimPassChainWithRejectPolicy() throws Exception {
        KeyPair keyPair = DkimTestKeys.generateRsa();
        backend.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 -all"));
        backend.put("sel._domainkey.example.com", RecordType.TXT, DnsStatus.OK,
                List.of(DkimTestKeys.publicKeyTxt(keyPair)));
        backend.put("_dmarc.example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=DMARC1; p=reject"));

        byte[] message = signedRelaxed(keyPair, "Hi\r\n");
        EvaluationResult result = service.evaluate("mail.example.com", "10.0.0.1",
                "user@example.com", message);

        assertThat(result.getDkim().get(0).getStatus()).isEqualTo(DkimStatus.PASS);
        assertThat(result.getDmarc().getDisposition()).isEqualTo(DmarcDisposition.NONE);
        assertThat(result.getDmarc().isDkimAligned()).isTrue();
    }

    @Test
    void unauthenticatedMailIsRejectedAndReported() throws Exception {
        backend.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 -all"));
        backend.put("_dmarc.example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=DMARC1; p=reject"));
        byte[] message = ("From: user@example.com\r\nMessage-ID: <fixed@example.com>\r\n\r\nHi\r\n")
                .getBytes(StandardCharsets.UTF_8);

        service.evaluate("mail.attacker.net", "203.0.113.9",
                "user@example.com", message);
        service.evaluate("mail.attacker.net", "203.0.113.9",
                "user@example.com", message);

        EvaluationResult result = service.evaluate("mail.attacker.net", "203.0.113.9",
                "user@example.com", message);
        assertThat(result.getDmarc().getDisposition()).isEqualTo(DmarcDisposition.REJECT);

        ReportStore store = new ReportStore(properties);
        assertThat(store.peek("example.com").entryList()).hasSize(1);
    }

    @Test
    void policyReplacementDoesNotMixVersionsAcrossConcurrentEvaluations() throws Exception {
        backend.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ip4:192.0.2.10 -all"));
        backend.put("_dmarc.example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=DMARC1; p=none"));

        byte[] message = ("From: user@example.com\r\n\r\nHi\r\n")
                .getBytes(StandardCharsets.UTF_8);
        EvaluationResult first = service.evaluate("mail.example.com", "192.0.2.10",
                "user@example.com", message);
        assertThat(first.getSpf().getStatus()).isEqualTo(SpfStatus.PASS);

        HashMap<String, DnsResult> next = new HashMap<>();
        next.put(MapBackedDnsResolver.key("example.com", RecordType.TXT),
                new DnsResult(DnsStatus.OK, List.of("v=spf1 -all"), List.of()));
        next.put(MapBackedDnsResolver.key("_dmarc.example.com", RecordType.TXT),
                new DnsResult(DnsStatus.OK,
                        List.of("v=DMARC1; p=reject"), List.of()));

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger pass = new AtomicInteger();
        AtomicInteger reject = new AtomicInteger();
        AtomicInteger none = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                start.await();
                EvaluationResult result = service.evaluate("mail.example.com", "192.0.2.10",
                        "user@example.com", message);
                if (result.getSpf().getStatus() == SpfStatus.PASS) {
                    pass.incrementAndGet();
                }
                if (result.getDmarc().getDisposition() == DmarcDisposition.REJECT) {
                    reject.incrementAndGet();
                }
                if (result.getDmarc().getDisposition() == DmarcDisposition.NONE) {
                    none.incrementAndGet();
                }
                return null;
            });
        }
        start.countDown();
        backend.replaceAll(next);
        pool.shutdown();
        assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

        assertThat(pass.get() + reject.get() + none.get()).isEqualTo(threads);
        // 每次评估要么完全旧（pass + dmarc none），要么完全新（spf fail + reject）。
        assertThat(pass.get()).isEqualTo(none.get());
        assertThat(reject.get()).isEqualTo(threads - pass.get());
    }

    private byte[] signedRelaxed(KeyPair keyPair, String body) throws Exception {
        return new DkimMessageSigner(keyPair).relaxed(body);
    }
}

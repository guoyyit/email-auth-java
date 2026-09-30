package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dkim.DkimStatus;
import com.github.guoyyit.emailauthjava.dmarc.DmarcDisposition;
import com.github.guoyyit.emailauthjava.dmarc.DmarcEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.DmarcResult;
import com.github.guoyyit.emailauthjava.dns.DnsResult;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.MapBackedDnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.spf.SpfResult;
import com.github.guoyyit.emailauthjava.spf.SpfStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DmarcEvaluatorTest {
    private MapBackedDnsResolver dns;
    private DmarcEvaluator evaluator;

    @BeforeEach
    void setUp() {
        dns = new MapBackedDnsResolver(new java.util.HashMap<>());
        evaluator = new DmarcEvaluator(dns, new AuthProperties());
    }

    @Test
    void noPolicyIsNone() {
        DmarcResult result = evaluator.evaluate("plain.example",
                spf(SpfStatus.FAIL, "other.example"),
                List.of(), 1L);
        assertThat(result.getDisposition()).isEqualTo(DmarcDisposition.NONE);
    }

    @Test
    void relaxedSpfAlignmentPasses() {
        policy("example.com", "v=DMARC1; p=reject; sp=reject");
        DmarcResult result = evaluator.evaluate("news.example.com",
                spf(SpfStatus.PASS, "mail.example.com"), List.of(), 1L);
        assertThat(result.isSpfAligned()).isTrue();
        assertThat(result.getDisposition()).isEqualTo(DmarcDisposition.NONE);
    }

    @Test
    void strictSpfAlignmentRequiresExactDomain() {
        policy("example.com", "v=DMARC1; p=reject; aspf=s");
        DmarcResult result = evaluator.evaluate("news.example.com",
                spf(SpfStatus.PASS, "mail.example.com"), List.of(), 1L);
        assertThat(result.isSpfAligned()).isFalse();
        assertThat(result.getDisposition()).isEqualTo(DmarcDisposition.REJECT);
    }

    @Test
    void dkimRelaxedAlignmentPasses() {
        policy("example.com", "v=DMARC1; p=quarantine");
        DmarcResult result = evaluator.evaluate("example.com",
                spf(SpfStatus.FAIL, "other.net"),
                List.of(new DkimResult(DkimStatus.PASS, "sel", "mail.example.com", "ok")),
                1L);
        assertThat(result.isDkimAligned()).isTrue();
        assertThat(result.getDisposition()).isEqualTo(DmarcDisposition.NONE);
    }

    @Test
    void rejectWhenNothingAligns() {
        policy("example.com", "v=DMARC1; p=reject");
        DmarcResult result = evaluator.evaluate("example.com",
                spf(SpfStatus.FAIL, "attacker.net"),
                List.of(new DkimResult(DkimStatus.FAIL, "sel", "attacker.net", "bad")),
                1L);
        assertThat(result.getDisposition()).isEqualTo(DmarcDisposition.REJECT);
        assertThat(result.getReasons()).anyMatch(reason -> reason.contains("reject"));
    }

    @Test
    void subdomainInheritsSpPolicy() {
        policy("example.com", "v=DMARC1; p=none; sp=quarantine");
        DmarcResult result = evaluator.evaluate("child.example.com",
                spf(SpfStatus.FAIL, "other.net"), List.of(), 1L);
        assertThat(result.getDisposition()).isEqualTo(DmarcDisposition.QUARANTINE);
    }

    @Test
    void orgDomainFallback() {
        policy("example.co.uk", "v=DMARC1; p=reject");
        DmarcResult result = evaluator.evaluate("deep.child.example.co.uk",
                spf(SpfStatus.FAIL, "other.net"), List.of(), 1L);
        assertThat(result.getPolicyDomain()).isEqualTo("example.co.uk");
        assertThat(result.getDisposition()).isEqualTo(DmarcDisposition.REJECT);
    }

    @Test
    void pctSamplingCanDowngradeToNone() {
        policy("example.com", "v=DMARC1; p=reject; pct=0");
        DmarcResult sampledOut = evaluator.evaluate("example.com",
                spf(SpfStatus.FAIL, "other.net"), List.of(), 1L);
        assertThat(sampledOut.getDisposition()).isEqualTo(DmarcDisposition.NONE);

        policy("example.com", "v=DMARC1; p=reject; pct=100");
        DmarcResult sampledIn = evaluator.evaluate("example.com",
                spf(SpfStatus.FAIL, "other.net"), List.of(), 1L);
        assertThat(sampledIn.getDisposition()).isEqualTo(DmarcDisposition.REJECT);
    }

    @Test
    void dnsTimeoutKeepsNoneAndReportsReason() {
        dns.put("_dmarc.example.com", RecordType.TXT,
                new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of()));
        DmarcResult result = evaluator.evaluate("example.com",
                spf(SpfStatus.FAIL, "other.net"), List.of(), 1L);
        assertThat(result.getDisposition()).isEqualTo(DmarcDisposition.NONE);
        assertThat(String.join(";", result.getReasons())).contains("timeout");
    }

    private void policy(String domain, String txt) {
        dns.put("_dmarc." + domain, RecordType.TXT, DnsStatus.OK, List.of(txt));
    }

    private SpfResult spf(SpfStatus status, String domain) {
        return new SpfResult(status, status.name().toLowerCase(), domain);
    }
}

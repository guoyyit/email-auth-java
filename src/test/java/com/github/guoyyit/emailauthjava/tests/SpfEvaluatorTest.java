package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.InMemoryDnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.spf.SpfEvaluator;
import com.github.guoyyit.emailauthjava.spf.SpfResult;
import com.github.guoyyit.emailauthjava.spf.SpfStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SpfEvaluatorTest {

    private InMemoryDnsResolver resolver;
    private SpfEvaluator evaluator;

    @BeforeEach
    void setUp() {
        resolver = new InMemoryDnsResolver();
        AuthProperties properties = new AuthProperties();
        evaluator = new SpfEvaluator(new DnsCache(resolver, properties), properties);
    }

    @Test
    void ip4PassFailNeutral() {
        resolver.putTxt("example.com", "v=spf1 ip4:192.0.2.10 -all");
        assertEquals(SpfStatus.PASS,
                evaluator.evaluate("192.0.2.10", "mail.example.com", "<a@example.com>").getStatus());
        assertEquals(SpfStatus.FAIL,
                evaluator.evaluate("192.0.2.99", "mail.example.com", "<a@example.com>").getStatus());
    }

    @Test
    void softfailAndNeutralQualifiers() {
        resolver.putTxt("soft.example", "v=spf1 ~all");
        assertEquals(SpfStatus.SOFTFAIL,
                evaluator.evaluate("10.0.0.1", "soft.example", "<a@soft.example>").getStatus());
        resolver.putTxt("neutral.example", "v=spf1 ?all");
        assertEquals(SpfStatus.NEUTRAL,
                evaluator.evaluate("10.0.0.1", "neutral.example", "<a@neutral.example>").getStatus());
    }

    @Test
    void noneWhenNoRecord() {
        SpfResult result = evaluator.evaluate("1.2.3.4", "missing.example", "<a@missing.example>");
        assertEquals(SpfStatus.NONE, result.getStatus());
    }

    @Test
    void ip6CidrMatch() {
        resolver.putTxt("v6.example", "v=spf1 ip6:2001:db8::/32 -all");
        assertEquals(SpfStatus.PASS,
                evaluator.evaluate("2001:db8:1::1", "v6.example", "<a@v6.example>").getStatus());
        assertEquals(SpfStatus.FAIL,
                evaluator.evaluate("2001:db9:1::1", "v6.example", "<a@v6.example>").getStatus());
    }

    @Test
    void aAndMxMechanisms() {
        resolver.putTxt("a.example", "v=spf1 a -all");
        resolver.put(com.github.guoyyit.emailauthjava.dns.DnsRecord.address(
                "a.example", RecordType.A, "198.51.100.7", 60));
        assertEquals(SpfStatus.PASS,
                evaluator.evaluate("198.51.100.7", "a.example", "<a@a.example>").getStatus());

        resolver.putTxt("mx.example", "v=spf1 mx -all");
        resolver.put(com.github.guoyyit.emailauthjava.dns.DnsRecord.mx(
                "mx.example", "mail.mx.example", 10, 60));
        resolver.put(com.github.guoyyit.emailauthjava.dns.DnsRecord.address(
                "mail.mx.example", RecordType.A, "198.51.100.20", 60));
        assertEquals(SpfStatus.PASS,
                evaluator.evaluate("198.51.100.20", "mx.example", "<a@mx.example>").getStatus());
    }

    @Test
    void includePropagatesPass() {
        resolver.putTxt("parent.example", "v=spf1 include:vendor.example -all");
        resolver.putTxt("vendor.example", "v=spf1 ip4:203.0.113.0/24 -all");
        assertEquals(SpfStatus.PASS, evaluator.evaluate(
                "203.0.113.55", "parent.example", "<a@parent.example>").getStatus());
        assertEquals(SpfStatus.FAIL, evaluator.evaluate(
                "203.0.114.55", "parent.example", "<a@parent.example>").getStatus());
    }

    @Test
    void includeLoopIsPermerror() {
        resolver.putTxt("loop1.example", "v=spf1 include:loop2.example -all");
        resolver.putTxt("loop2.example", "v=spf1 include:loop1.example -all");
        SpfResult result = evaluator.evaluate(
                "1.1.1.1", "loop1.example", "<a@loop1.example>");
        assertEquals(SpfStatus.PERMERROR, result.getStatus());
    }

    @Test
    void includeDepthExceededIsPermerror() {
        AuthProperties properties = new AuthProperties();
        properties.getSpf().setMaxIncludeDepth(2);
        InMemoryDnsResolver customResolver = new InMemoryDnsResolver();
        SpfEvaluator custom = new SpfEvaluator(
                new DnsCache(customResolver, properties), properties);
        customResolver.putTxt("d0", "v=spf1 include:d1 -all");
        customResolver.putTxt("d1", "v=spf1 include:d2 -all");
        customResolver.putTxt("d2", "v=spf1 include:d3 -all");
        customResolver.putTxt("d3", "v=spf1 +all");
        SpfResult result = custom.evaluate("5.5.5.5", "d0", "<a@d0>");
        assertEquals(SpfStatus.PERMERROR, result.getStatus());
    }

    @Test
    void redirectIsFollowed() {
        resolver.putTxt("old.example", "v=spf1 redirect=new.example");
        resolver.putTxt("new.example", "v=spf1 ip4:192.0.2.55 -all");
        assertEquals(SpfStatus.PASS, evaluator.evaluate(
                "192.0.2.55", "old.example", "<a@old.example>").getStatus());
    }

    @Test
    void timeoutMapsToTemperror() {
        resolver.putFailure("slow.example", RecordType.TXT, DnsStatus.TIMEOUT);
        SpfResult result = evaluator.evaluate(
                "1.2.3.4", "slow.example", "<a@slow.example>");
        assertEquals(SpfStatus.TEMPERROR, result.getStatus());
    }

    @Test
    void malformedRecordMapsToPermerror() {
        resolver.putFailure("bad.example", RecordType.TXT, DnsStatus.MALFORMED);
        SpfResult result = evaluator.evaluate(
                "1.2.3.4", "bad.example", "<a@bad.example>");
        assertEquals(SpfStatus.PERMERROR, result.getStatus());
    }

    @Test
    void dnsQueryBudgetIsEnforced() {
        AuthProperties properties = new AuthProperties();
        properties.getSpf().setMaxDnsQueries(3);
        InMemoryDnsResolver customResolver = new InMemoryDnsResolver();
        SpfEvaluator custom = new SpfEvaluator(
                new DnsCache(customResolver, properties), properties);
        customResolver.putTxt("chain.example",
                "v=spf1 include:a include:b include:c include:d -all");
        customResolver.putTxt("a", "v=spf1 ip4:1.1.1.1 -all");
        customResolver.putTxt("b", "v=spf1 ip4:2.2.2.2 -all");
        customResolver.putTxt("c", "v=spf1 ip4:3.3.3.3 -all");
        customResolver.putTxt("d", "v=spf1 ip4:4.4.4.4 -all");
        SpfResult result = custom.evaluate(
                "9.9.9.9", "chain.example", "<a@chain.example>");
        assertEquals(SpfStatus.PERMERROR, result.getStatus());
    }
}

package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dns.DnsResult;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.MapBackedDnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.spf.SpfEvaluator;
import com.github.guoyyit.emailauthjava.spf.SpfResult;
import com.github.guoyyit.emailauthjava.spf.SpfStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SpfEvaluatorTest {
    private MapBackedDnsResolver dns;
    private SpfEvaluator evaluator;

    @BeforeEach
    void setUp() {
        dns = new MapBackedDnsResolver(new java.util.HashMap<>());
        evaluator = new SpfEvaluator(dns, new AuthProperties());
    }

    @Test
    void ip4PassAndFail() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ip4:192.0.2.10 -all"));
        assertThat(evaluator.evaluate("mail.example.com", "192.0.2.10",
                "user@example.com").getStatus()).isEqualTo(SpfStatus.PASS);
        assertThat(evaluator.evaluate("mail.example.com", "198.51.100.7",
                "user@example.com").getStatus()).isEqualTo(SpfStatus.FAIL);
    }

    @Test
    void ip4CidrSoftfailNeutral() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ip4:10.0.0.0/8 ~all"));
        assertThat(evaluator.evaluate("h", "11.1.2.3", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.SOFTFAIL);
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ip4:10.0.0.0/8 ?all"));
        assertThat(evaluator.evaluate("h", "11.0.0.1", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.NEUTRAL);
    }

    @Test
    void ip6Mechanism() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ip6:2001:db8::/32 -all"));
        assertThat(evaluator.evaluate("h", "2001:db8::1", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PASS);
        assertThat(evaluator.evaluate("h", "2001:db9::1", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);
    }

    @Test
    void aAndMxMechanisms() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 a mx -all"));
        dns.put("example.com", RecordType.A, DnsStatus.OK, List.of("192.0.2.55"));
        dns.put("example.com", RecordType.MX, DnsStatus.OK,
                List.of(), List.of("mx.example.net"));
        dns.put("mx.example.net", RecordType.A, DnsStatus.OK, List.of("192.0.2.66"));

        assertThat(evaluator.evaluate("h", "192.0.2.55", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PASS);
        dns.put("example.com", RecordType.A, DnsStatus.NXDOMAIN, List.of());
        assertThat(evaluator.evaluate("h", "192.0.2.66", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PASS);
    }

    @Test
    void includeRecursionAndRedirect() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 include:partner.example.com -all"));
        dns.put("partner.example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 redirect=backend.example.org"));
        dns.put("backend.example.org", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ip4:203.0.113.7 -all"));

        assertThat(evaluator.evaluate("h", "203.0.113.7", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PASS);
        assertThat(evaluator.evaluate("h", "203.0.113.8", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);
    }

    @Test
    void includeLoopIsPermerror() {
        dns.put("a.example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 include:b.example.com -all"));
        dns.put("b.example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 include:c.example.com -all"));
        dns.put("c.example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 include:a.example.com -all"));

        SpfResult result = evaluator.evaluate("h", "1.2.3.4", "x@a.example.com");
        assertThat(result.getStatus()).isEqualTo(SpfStatus.PERMERROR);
        assertThat(result.getExplanation()).containsAnyOf("loop", "PERMERROR");
    }

    @Test
    void includeDepthCapIsPermerror() {
        AuthProperties props = new AuthProperties();
        props.getLimits().setMaxIncludeDepth(3);
        SpfEvaluator limited = new SpfEvaluator(dns, props);
        for (int i = 0; i < 6; i++) {
            String domain = "d" + i + ".example.com";
            String next = "d" + (i + 1) + ".example.com";
            dns.put(domain, RecordType.TXT, DnsStatus.OK,
                    List.of("v=spf1 include:" + next + " -all"));
        }
        dns.put("d6.example.com", RecordType.TXT, DnsStatus.OK, List.of("v=spf1 -all"));
        SpfResult result = limited.evaluate("h", "1.2.3.4", "x@d0.example.com");
        assertThat(result.getStatus()).isEqualTo(SpfStatus.PERMERROR);
        assertThat(result.getExplanation()).contains("depth");
    }

    @Test
    void noneWhenNoRecord() {
        assertThat(evaluator.evaluate("h", "1.2.3.4", "a@no-record.example").getStatus())
                .isEqualTo(SpfStatus.NONE);
    }

    @Test
    void dnsTimeoutMapsTemperror() {
        dns.put("bad.example.com", RecordType.TXT,
                new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of()));
        assertThat(evaluator.evaluate("h", "1.2.3.4", "a@bad.example.com").getStatus())
                .isEqualTo(SpfStatus.TEMPERROR);
    }

    @Test
    void dnsMalformedMapsPermerror() {
        dns.put("bad.example.com", RecordType.TXT,
                new DnsResult(DnsStatus.MALFORMED, List.of(), List.of()));
        assertThat(evaluator.evaluate("h", "1.2.3.4", "a@bad.example.com").getStatus())
                .isEqualTo(SpfStatus.PERMERROR);
    }

    @Test
    void multipleSpfRecordsIsPermerror() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 -all", "v=spf1 +all"));
        assertThat(evaluator.evaluate("h", "1.2.3.4", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PERMERROR);
    }
}

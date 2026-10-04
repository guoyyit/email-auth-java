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
    void mxWithParameterDomainMatchesOnlyExchangeAddressesV4() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 mx:relay.example.net -all"));
        dns.put("relay.example.net", RecordType.MX, DnsStatus.OK,
                List.of(), List.of("mx1.relay.example.net", "mx2.relay.example.net"));
        dns.put("mx1.relay.example.net", RecordType.A, DnsStatus.OK,
                List.of("192.0.2.10"));
        dns.put("mx2.relay.example.net", RecordType.A, DnsStatus.OK,
                List.of("192.0.2.11"));
        // 参数域名自身的 A 记录地址不是其 MX 交换主机，不得通过。
        dns.put("relay.example.net", RecordType.A, DnsStatus.OK,
                List.of("198.51.100.77"));

        assertThat(evaluator.evaluate("h", "192.0.2.10", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PASS);
        assertThat(evaluator.evaluate("h", "192.0.2.11", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PASS);
        assertThat(evaluator.evaluate("h", "198.51.100.77", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);
        assertThat(evaluator.evaluate("h", "203.0.113.9", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);
    }

    @Test
    void mxWithParameterDomainV6UsesExchangeAAAA() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 mx:relay6.example.net -all"));
        dns.put("relay6.example.net", RecordType.MX, DnsStatus.OK,
                List.of(), List.of("mx.relay6.example.net"));
        dns.put("mx.relay6.example.net", RecordType.AAAA, DnsStatus.OK,
                List.of("2001:db8::10"));
        dns.put("relay6.example.net", RecordType.AAAA, DnsStatus.OK,
                List.of("2001:db8::dead"));

        assertThat(evaluator.evaluate("h", "2001:db8::10", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PASS);
        assertThat(evaluator.evaluate("h", "2001:db8::dead", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);
    }

    @Test
    void mxWithoutParameterUsesCurrentDomainExchanges() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 mx -all"));
        dns.put("example.com", RecordType.MX, DnsStatus.OK,
                List.of(), List.of("mx.example.net"));
        dns.put("mx.example.net", RecordType.A, DnsStatus.OK, List.of("192.0.2.20"));

        assertThat(evaluator.evaluate("h", "192.0.2.20", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PASS);
        assertThat(evaluator.evaluate("h", "192.0.2.21", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);
    }

    @Test
    void mxWithParameterAndCidrQualifiers() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ~mx:relay.example.net/24 ?all"));
        dns.put("relay.example.net", RecordType.MX, DnsStatus.OK,
                List.of(), List.of("mx.relay.example.net"));
        dns.put("mx.relay.example.net", RecordType.A, DnsStatus.OK,
                List.of("192.0.2.1"));

        assertThat(evaluator.evaluate("h", "192.0.2.200", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.SOFTFAIL);
        assertThat(evaluator.evaluate("h", "198.51.100.1", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.NEUTRAL);
    }

    @Test
    void mxFailuresFollowExistingMapping() {
        dns.put("t.example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 mx:relay.t.example.com -all"));
        dns.put("relay.t.example.com", RecordType.MX,
                new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of()));
        assertThat(evaluator.evaluate("h", "1.2.3.4", "a@t.example.com").getStatus())
                .isEqualTo(SpfStatus.TEMPERROR);

        dns.put("p.example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 mx:relay.p.example.com -all"));
        dns.put("relay.p.example.com", RecordType.MX,
                new DnsResult(DnsStatus.MALFORMED, List.of(), List.of()));
        assertThat(evaluator.evaluate("h", "1.2.3.4", "a@p.example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);

        dns.put("a.example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 mx:relay.a.example.com -all"));
        dns.put("relay.a.example.com", RecordType.MX, DnsStatus.OK,
                List.of(), List.of("slow.relay.a.example.com"));
        dns.put("slow.relay.a.example.com", RecordType.A,
                new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of()));
        assertThat(evaluator.evaluate("h", "1.2.3.4", "a@a.example.com").getStatus())
                .isEqualTo(SpfStatus.TEMPERROR);
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

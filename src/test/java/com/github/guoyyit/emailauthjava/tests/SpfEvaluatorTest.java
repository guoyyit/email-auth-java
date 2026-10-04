package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dns.CachingDnsResolver;
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
    void mxWithDomainArgMatchesExchangeHostsOnly() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 mx:relay.example.net -all"));
        dns.put("relay.example.net", RecordType.MX, DnsStatus.OK,
                List.of(), List.of("mxa.relay.example.net", "mxb.relay.example.net"));
        dns.put("mxa.relay.example.net", RecordType.A, DnsStatus.OK,
                List.of("192.0.2.70"));
        dns.put("mxb.relay.example.net", RecordType.A, DnsStatus.OK,
                List.of("192.0.2.71"));
        // 参数域自身的 A 记录不是交换主机地址，不得通过。
        dns.put("relay.example.net", RecordType.A, DnsStatus.OK,
                List.of("203.0.113.99"));

        assertThat(evaluator.evaluate("h", "192.0.2.70", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PASS);
        assertThat(evaluator.evaluate("h", "192.0.2.71", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PASS);
        assertThat(evaluator.evaluate("h", "203.0.113.99", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);
        assertThat(evaluator.evaluate("h", "198.51.100.5", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);
    }

    @Test
    void mxWithDomainArgHonoursQualifierAndCidr() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ~mx:relay.example.net/24 ?all"));
        dns.put("relay.example.net", RecordType.MX, DnsStatus.OK,
                List.of(), List.of("m.relay.example.net"));
        dns.put("m.relay.example.net", RecordType.A, DnsStatus.OK,
                List.of("192.0.2.70"));

        assertThat(evaluator.evaluate("h", "192.0.2.200", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.SOFTFAIL);
    }

    @Test
    void mxWithoutArgUsesCurrentDomainExchanges() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 mx -all"));
        dns.put("example.com", RecordType.MX, DnsStatus.OK,
                List.of(), List.of("mx1.example.com", "mx2.example.com"));
        dns.put("mx1.example.com", RecordType.A, DnsStatus.OK, List.of("192.0.2.80"));
        dns.put("mx2.example.com", RecordType.A, DnsStatus.OK, List.of("192.0.2.81"));

        assertThat(evaluator.evaluate("h", "192.0.2.80", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PASS);
        // 交换主机没有 AAAA 记录，IPv6 客户端不匹配。
        assertThat(evaluator.evaluate("h", "2001:db8::80", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);
        assertThat(evaluator.evaluate("h", "10.0.0.1", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);
    }

    @Test
    void mxWithDomainArgUsesAaaaForV6Clients() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 mx:relay.example.net -all"));
        dns.put("relay.example.net", RecordType.MX, DnsStatus.OK,
                List.of(), List.of("v6.relay.example.net"));
        dns.put("v6.relay.example.net", RecordType.AAAA, DnsStatus.OK,
                List.of("2001:db8:1::1"));
        // 交换主机仅有 IPv6 地址，IPv4 客户端不应通过。
        assertThat(evaluator.evaluate("h", "2001:db8:1::1", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.PASS);
        assertThat(evaluator.evaluate("h", "192.0.2.90", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);
    }

    @Test
    void mxWithDomainArgFailuresKeepExistingMapping() {
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 mx:relay.example.net -all"));
        dns.put("relay.example.net", RecordType.MX, DnsStatus.NXDOMAIN, List.of());
        // MX 查询 NXDOMAIN：该机制不匹配，落到 -all。
        assertThat(evaluator.evaluate("h", "192.0.2.1", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);

        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 mx:slow.example.net -all"));
        dns.put("slow.example.net", RecordType.MX,
                new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of()));
        assertThat(evaluator.evaluate("h", "192.0.2.1", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.TEMPERROR);

        // MX 正常但交换主机地址查询 MALFORMED：按既有映射不静默放行。
        dns.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 mx:broken.example.net -all"));
        dns.put("broken.example.net", RecordType.MX, DnsStatus.OK,
                List.of(), List.of("x.broken.example.net"));
        dns.put("x.broken.example.net", RecordType.A,
                new DnsResult(DnsStatus.MALFORMED, List.of(), List.of()));
        assertThat(evaluator.evaluate("h", "192.0.2.1", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);
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
    void slowTxtLookupIsCutOffByConfiguredTimeoutAndMapsTemperror() {
        AuthProperties properties = new AuthProperties();
        properties.getDns().setTimeoutMillis(50);
        MapBackedDnsResolver slow = new MapBackedDnsResolver(new java.util.HashMap<>()) {
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                try {
                    Thread.sleep(30_000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of());
            }
        };
        SpfEvaluator slowEvaluator = new SpfEvaluator(
                new CachingDnsResolver(slow, properties), properties);
        long start = System.nanoTime();
        assertThat(slowEvaluator.evaluate("h", "1.2.3.4", "a@slow.example.com").getStatus())
                .isEqualTo(SpfStatus.TEMPERROR);
        assertThat(java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(
                System.nanoTime() - start)).isLessThan(2_000);
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

package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dkim.DkimStatus;
import com.github.guoyyit.emailauthjava.dkim.SignatureOutcome;
import com.github.guoyyit.emailauthjava.dmarc.DmarcEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.DmarcPolicyAction;
import com.github.guoyyit.emailauthjava.dmarc.OrganizationalDomain;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.dns.InMemoryDnsResolver;
import com.github.guoyyit.emailauthjava.spf.SpfResult;
import com.github.guoyyit.emailauthjava.spf.SpfStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DmarcEvaluatorTest {

    private InMemoryDnsResolver resolver;
    private DmarcEvaluator evaluator;

    @BeforeEach
    void setUp() {
        resolver = new InMemoryDnsResolver();
        AuthProperties properties = new AuthProperties();
        evaluator = new DmarcEvaluator(new DnsCache(resolver, properties), properties,
                new OrganizationalDomain(properties));
    }

    private SpfResult spf(SpfStatus status) {
        return SpfResult.of(status, status.name());
    }

    private DkimResult dkim(DkimStatus status, String domain) {
        return new DkimResult(status,
                List.of(new SignatureOutcome("sel", domain, status, "r")));
    }

    @Test
    void noPolicyYieldsNone() {
        DmarcResultLike result = evaluate("example.com",
                spf(SpfStatus.PASS), "example.com",
                dkim(DkimStatus.NONE, null));
        assertEquals(DmarcPolicyAction.NONE, result.action);
    }

    @Test
    void strictSpfAlignment() {
        resolver.putTxt("_dmarc.example.com",
                "v=DMARC1; p=reject; aspf=s");
        DmarcResultLike pass = evaluate("example.com",
                spf(SpfStatus.PASS), "example.com", dkim(DkimStatus.NONE, null));
        assertEquals(DmarcPolicyAction.NONE, pass.action);
        assertTrue(pass.spfAligned);

        DmarcResultLike sub = evaluate("example.com",
                spf(SpfStatus.PASS), "mail.example.com", dkim(DkimStatus.NONE, null));
        assertEquals(DmarcPolicyAction.REJECT, sub.action);
        assertFalse(sub.spfAligned);
    }

    @Test
    void relaxedDkimAlignmentAcrossSubdomains() {
        resolver.putTxt("_dmarc.example.com", "v=DMARC1; p=quarantine; adkim=r");
        DmarcResultLike result = evaluate("news.example.com",
                spf(SpfStatus.FAIL), "other.example",
                dkim(DkimStatus.PASS, "example.com"));
        assertEquals(DmarcPolicyAction.NONE, result.action);
        assertTrue(result.dkimAligned);
    }

    @Test
    void rejectsWhenNeitherAligns() {
        resolver.putTxt("_dmarc.example.com", "v=DMARC1; p=reject");
        DmarcResultLike result = evaluate("example.com",
                spf(SpfStatus.PASS), "attacker.net",
                dkim(DkimStatus.PASS, "attacker.net"));
        assertEquals(DmarcPolicyAction.REJECT, result.action);
    }

    @Test
    void organizationalDomainFallback() {
        resolver.putTxt("_dmarc.example.com", "v=DMARC1; p=quarantine");
        DmarcResultLike result = evaluate("shop.example.com",
                spf(SpfStatus.FAIL), "other.net", dkim(DkimStatus.FAIL, "other.net"));
        assertEquals(DmarcPolicyAction.QUARANTINE, result.action);
        assertEquals("example.com", result.policyDomain);
    }

    @Test
    void subdomainPolicyInheritsSp() {
        resolver.putTxt("_dmarc.example.com",
                "v=DMARC1; p=none; sp=reject");
        DmarcResultLike result = evaluate("sub.example.com",
                spf(SpfStatus.FAIL), "x.net", dkim(DkimStatus.FAIL, "x.net"));
        assertEquals(DmarcPolicyAction.REJECT, result.action);
    }

    @Test
    void pctZeroNeverAppliesPolicy() {
        resolver.putTxt("_dmarc.example.com", "v=DMARC1; p=reject; pct=0");
        DmarcResultLike result = evaluate("example.com",
                spf(SpfStatus.FAIL), "x.net", dkim(DkimStatus.FAIL, "x.net"));
        assertEquals(DmarcPolicyAction.NONE, result.action);
    }

    @Test
    void privateSuffixAffectsOrganizationalDomain() {
        AuthProperties properties = new AuthProperties();
        properties.getDmarc().getPrivateSuffixes().add("co.jp");
        OrganizationalDomain orgDomain = new OrganizationalDomain(properties);
        assertEquals("example.co.jp", orgDomain.of("shop.example.co.jp"));
        assertEquals("foo.co.jp", orgDomain.of("foo.co.jp"));
    }

    private DmarcResultLike evaluate(String from, SpfResult spfResult, String spfDomain,
                                     DkimResult dkimResult) {
        var result = evaluator.evaluate(from, spfResult, spfDomain, dkimResult);
        return new DmarcResultLike(result.getDisposition(), result.isSpfAligned(),
                result.isDkimAligned(), result.getPolicyDomain());
    }

    private record DmarcResultLike(DmarcPolicyAction action, boolean spfAligned,
                                  boolean dkimAligned, String policyDomain) {
    }
}

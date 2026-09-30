package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimEvaluator;
import com.github.guoyyit.emailauthjava.dkim.DkimStatus;
import com.github.guoyyit.emailauthjava.dmarc.DmarcEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.DmarcPolicyAction;
import com.github.guoyyit.emailauthjava.dmarc.OrganizationalDomain;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.InMemoryDnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.eval.AuthResult;
import com.github.guoyyit.emailauthjava.eval.AuthService;
import com.github.guoyyit.emailauthjava.mail.MailParser;
import com.github.guoyyit.emailauthjava.report.AggregateStore;
import com.github.guoyyit.emailauthjava.spf.SpfEvaluator;
import com.github.guoyyit.emailauthjava.spf.SpfStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthServiceIntegrationTest {

    private Harness harness(Path dir) {
        AuthProperties properties = new AuthProperties();
        if (dir != null) {
            properties.getReport().setStoreDir(dir.resolve("agg").toString());
        }
        InMemoryDnsResolver resolver = new InMemoryDnsResolver();
        DnsCache cache = new DnsCache(resolver, properties);
        MailParser parser = new MailParser(properties);
        SpfEvaluator spf = new SpfEvaluator(cache, properties);
        DkimEvaluator dkim = new DkimEvaluator(cache, properties);
        OrganizationalDomain org = new OrganizationalDomain(properties);
        DmarcEvaluator dmarc = new DmarcEvaluator(cache, properties, org);
        AggregateStore store = new AggregateStore(properties);
        AuthService service = new AuthService(parser, spf, dkim, dmarc, store, cache);
        return new Harness(resolver, cache, service, store);
    }

    private record Harness(InMemoryDnsResolver resolver, DnsCache cache, AuthService service,
                           AggregateStore store) {
    }

    @Test
    void spfAlignedMessagePasses(@TempDir Path dir) {
        Harness harness = harness(dir);
        harness.resolver().putTxt("example.com", "v=spf1 ip4:192.0.2.10 -all");
        harness.resolver().putTxt("_dmarc.example.com", "v=DMARC1; p=reject");
        byte[] message = ("From: alice@example.com\r\nSubject: s\r\n\r\nhi\r\n")
                .getBytes(StandardCharsets.UTF_8);

        AuthResult result = harness.service().evaluate(
                message, "192.0.2.10", "example.com", "<alice@example.com>");
        assertEquals(SpfStatus.PASS, result.getSpf().getStatus());
        assertEquals(DkimStatus.NONE, result.getDkim().getStatus());
        assertEquals(DmarcPolicyAction.NONE, result.getDmarc().getDisposition());
        assertTrue(result.getDmarc().isSpfAligned());
    }

    @Test
    void spoofedMessageIsRejected(@TempDir Path dir) {
        Harness harness = harness(dir);
        harness.resolver().putTxt("example.com", "v=spf1 -all");
        harness.resolver().putTxt("_dmarc.example.com", "v=DMARC1; p=reject");
        byte[] message = ("From: alice@example.com\r\nSubject: s\r\n\r\nhi\r\n")
                .getBytes(StandardCharsets.UTF_8);

        AuthResult result = harness.service().evaluate(
                message, "203.0.113.66", "attacker.net", "<alice@example.com>");
        assertEquals(DmarcPolicyAction.REJECT, result.getDmarc().getDisposition());
        assertEquals(1, harness.store().bucketsFor("example.com").size());
    }

    @Test
    void dnsTimeoutOnDmarcYieldsNoneDisposition(@TempDir Path dir) {
        Harness harness = harness(dir);
        harness.resolver().putTxt("example.com", "v=spf1 -all");
        harness.resolver().putFailure("_dmarc.example.com", RecordType.TXT, DnsStatus.TIMEOUT);
        byte[] message = ("From: alice@example.com\r\nSubject: s\r\n\r\nhi\r\n")
                .getBytes(StandardCharsets.UTF_8);

        AuthResult result = harness.service().evaluate(
                message, "10.0.0.1", "example.com", "<alice@example.com>");
        assertEquals(DmarcPolicyAction.NONE, result.getDmarc().getDisposition());
    }

    @Test
    void dkimSignedMessagePassesEndToEnd(@TempDir Path dir) throws Exception {
        Harness harness = harness(dir);
        TestFixtures.DkimKeyPair pair = TestFixtures.generateRsaKey();
        byte[] message = TestFixtures.message("alice@dmarc.example", "signed", "ok\r\n")
                .getBytes(StandardCharsets.UTF_8);
        byte[] signed = TestFixtures.signMessage(message, pair.keyPair(),
                "dmarc.example", "sel", "simple", "simple",
                "from", "to", "subject", "message-id", "date");
        harness.resolver().putTxt("sel._domainkey.dmarc.example",
                "v=DKIM1; k=rsa; p=" + pair.publicBase64());
        harness.resolver().putTxt("_dmarc.dmarc.example", "v=DMARC1; p=quarantine");

        AuthResult result = harness.service().evaluate(
                signed, "8.8.8.8", "other.example", "<x@other.example>");
        assertEquals(DkimStatus.PASS, result.getDkim().getStatus());
        assertEquals(DmarcPolicyAction.NONE, result.getDmarc().getDisposition());
    }

}

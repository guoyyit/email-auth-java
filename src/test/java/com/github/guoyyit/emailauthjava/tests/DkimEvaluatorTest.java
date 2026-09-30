package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.Canonicalizer;
import com.github.guoyyit.emailauthjava.dkim.DkimEvaluator;
import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dkim.DkimStatus;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.InMemoryDnsResolver;
import com.github.guoyyit.emailauthjava.mail.MailParser;
import com.github.guoyyit.emailauthjava.mail.ParsedMail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DkimEvaluatorTest {

    private InMemoryDnsResolver resolver;
    private AuthProperties properties;
    private DkimEvaluator evaluator;
    private MailParser parser;

    @BeforeEach
    void setUp() {
        resolver = new InMemoryDnsResolver();
        properties = new AuthProperties();
        evaluator = new DkimEvaluator(new DnsCache(resolver, properties), properties);
        parser = new MailParser(properties);
    }

    @Test
    void validSimpleSignaturePasses() throws Exception {
        TestFixtures.DkimKeyPair pair = TestFixtures.generateRsaKey();
        byte[] raw = TestFixtures.signMessage(
                TestFixtures.message("alice@example.com", "hello", "body line\r\n")
                        .getBytes(StandardCharsets.UTF_8),
                pair.keyPair(), "example.com", "sel", "simple", "simple",
                "from", "to", "subject", "message-id", "date");
        resolver.putTxt("sel._domainkey.example.com",
                "v=DKIM1; k=rsa; p=" + pair.publicBase64());

        ParsedMail mail = parser.parse(raw);
        DkimResult result = evaluator.verify(mail);
        assertEquals(DkimStatus.PASS, result.getStatus());
        assertEquals("example.com", result.getAuthenticatedDomain());
    }

    @Test
    void validRelaxedSignaturePasses() throws Exception {
        TestFixtures.DkimKeyPair pair = TestFixtures.generateRsaKey();
        byte[] raw = TestFixtures.signMessage(
                TestFixtures.message("  Alice <alice@example.com>  ", "Relaxed",
                        "line   with   spaces\r\n\r\n")
                        .getBytes(StandardCharsets.UTF_8),
                pair.keyPair(), "example.com", "sel2", "relaxed", "relaxed",
                "from", "to", "subject", "message-id", "date");
        resolver.putTxt("sel2._domainkey.example.com",
                "v=DKIM1; k=rsa; p=" + pair.publicBase64());

        ParsedMail mail = parser.parse(raw);
        assertEquals(DkimStatus.PASS, evaluator.verify(mail).getStatus());
    }

    @Test
    void tamperedBodyFails() throws Exception {
        TestFixtures.DkimKeyPair pair = TestFixtures.generateRsaKey();
        byte[] raw = TestFixtures.signMessage(
                TestFixtures.message("alice@example.com", "s", "original\r\n")
                        .getBytes(StandardCharsets.UTF_8),
                pair.keyPair(), "example.com", "sel3", "simple", "simple",
                "from", "to", "subject", "message-id", "date");
        String text = new String(raw, StandardCharsets.ISO_8859_1).replace("original", "tampered");
        resolver.putTxt("sel3._domainkey.example.com",
                "v=DKIM1; k=rsa; p=" + pair.publicBase64());

        DkimResult result = evaluator.verify(parser.parse(text.getBytes(StandardCharsets.ISO_8859_1)));
        assertEquals(DkimStatus.FAIL, result.getStatus());
    }

    @Test
    void unknownSelectorIsFail() throws Exception {
        TestFixtures.DkimKeyPair pair = TestFixtures.generateRsaKey();
        byte[] raw = TestFixtures.signMessage(
                TestFixtures.message("alice@example.com", "s", "b\r\n")
                        .getBytes(StandardCharsets.UTF_8),
                pair.keyPair(), "example.com", "missing", "simple", "simple",
                "from", "to", "subject", "message-id", "date");
        DkimResult result = evaluator.verify(parser.parse(raw));
        assertEquals(DkimStatus.FAIL, result.getStatus());
        assertEquals("unknown selector missing",
                result.getSignatures().get(0).getReason());
    }

    @Test
    void keyLookupTimeoutIsTemperror() throws Exception {
        TestFixtures.DkimKeyPair pair = TestFixtures.generateRsaKey();
        byte[] raw = TestFixtures.signMessage(
                TestFixtures.message("alice@slow.example", "s", "b\r\n")
                        .getBytes(StandardCharsets.UTF_8),
                pair.keyPair(), "slow.example", "sel", "simple", "simple",
                "from", "to", "subject", "message-id", "date");
        resolver.putFailure("sel._domainkey.slow.example",
                com.github.guoyyit.emailauthjava.dns.RecordType.TXT, DnsStatus.TIMEOUT);
        DkimResult result = evaluator.verify(parser.parse(raw));
        assertEquals(DkimStatus.TEMPERROR, result.getStatus());
    }

    @Test
    void noSignatureIsNone() {
        ParsedMail mail = parser.parse(
                TestFixtures.message("a@b.example", "s", "b\r\n").getBytes(StandardCharsets.UTF_8));
        assertEquals(DkimStatus.NONE, evaluator.verify(mail).getStatus());
    }

    @Test
    void expiredSignatureIsFailWithExplicitReason() {
        long past = System.currentTimeMillis() / 1000L - 3600;
        String header = "v=1; a=rsa-sha256; d=example.com; s=sel; h=from; "
                + "x=" + past + "; bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; "
                + "b=" + "Q".repeat(100);
        byte[] raw = ("From: a@example.com\r\nDKIM-Signature: " + header + "\r\n\r\nx\r\n")
                .getBytes(StandardCharsets.UTF_8);
        DkimResult result = evaluator.verify(parser.parse(raw));
        assertEquals(DkimStatus.FAIL, result.getStatus());
        assertTrue(result.getSignatures().get(0).getReason().contains("expired"));
    }

    @Test
    void onePassAmongMultipleSignaturesYieldsPass() throws Exception {
        TestFixtures.DkimKeyPair good = TestFixtures.generateRsaKey();
        TestFixtures.DkimKeyPair other = TestFixtures.generateRsaKey();
        byte[] first = TestFixtures.signMessage(
                TestFixtures.message("alice@multi.example", "s", "b\r\n")
                        .getBytes(StandardCharsets.UTF_8),
                good.keyPair(), "multi.example", "good", "simple", "simple",
                "from", "to", "subject", "message-id", "date");
        byte[] twice = TestFixtures.signMessage(first, other.keyPair(), "multi.example",
                "bad", "simple", "simple",
                "from", "to", "subject", "message-id", "date");
        resolver.putTxt("good._domainkey.multi.example",
                "v=DKIM1; k=rsa; p=" + good.publicBase64());

        DkimResult result = evaluator.verify(parser.parse(twice));
        assertEquals(DkimStatus.PASS, result.getStatus());
        assertEquals(2, result.getSignatures().size());
    }

    @Test
    void relaxedBodyCanonicalizationCollapsesWhitespace() {
        byte[] canonical = Canonicalizer.canonicalizeBody(
                "a   b\tc  \r\n\r\n".getBytes(StandardCharsets.UTF_8),
                Canonicalizer.BodyMode.RELAXED, null);
        assertEquals("a b c\r\n", new String(canonical, StandardCharsets.UTF_8));
    }

    @Test
    void simpleBodyCanonicalizationKeepsSingleTrailingCrlf() {
        byte[] canonical = Canonicalizer.canonicalizeBody(
                "x\r\n\r\n\r\n".getBytes(StandardCharsets.UTF_8),
                Canonicalizer.BodyMode.SIMPLE, null);
        assertArrayEquals("x\r\n".getBytes(StandardCharsets.UTF_8), canonical);
    }
}

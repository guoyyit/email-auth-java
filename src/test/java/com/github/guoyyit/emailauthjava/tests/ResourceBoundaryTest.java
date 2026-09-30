package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimEvaluator;
import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dkim.DkimStatus;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.dns.InMemoryDnsResolver;
import com.github.guoyyit.emailauthjava.mail.MailParseException;
import com.github.guoyyit.emailauthjava.mail.MailParser;
import com.github.guoyyit.emailauthjava.mail.ParsedMail;
import com.github.guoyyit.emailauthjava.spf.SpfEvaluator;
import com.github.guoyyit.emailauthjava.spf.SpfResult;
import com.github.guoyyit.emailauthjava.spf.SpfStatus;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResourceBoundaryTest {

    @Test
    void oversizedMessageIsRejected() {
        AuthProperties properties = new AuthProperties();
        properties.getLimits().setMaxMessageBytes(128);
        MailParser parser = new MailParser(properties);
        byte[] huge = new byte[4096];
        java.util.Arrays.fill(huge, (byte) 'a');
        MailParseException ex = assertThrows(MailParseException.class, () -> parser.parse(huge));
        assertTrue(ex.isSizeLimit());
    }

    @Test
    void oversizedDnsResponseYieldsPermerror() {
        AuthProperties properties = new AuthProperties();
        properties.getLimits().setMaxDnsResponseBytes(64);
        InMemoryDnsResolver resolver = new InMemoryDnsResolver();
        String giant = "v=spf1 " + "a".repeat(200) + " -all";
        resolver.putTxt("huge.example", giant);
        SpfEvaluator evaluator = new SpfEvaluator(
                new DnsCache(resolver, properties), properties);
        SpfResult result = evaluator.evaluate("1.2.3.4", "huge.example", "<a@huge.example>");
        assertEquals(SpfStatus.PERMERROR, result.getStatus());
    }

    @Test
    void recursiveIncludeExplosionDoesNotCrash() {
        AuthProperties properties = new AuthProperties();
        properties.getSpf().setMaxIncludeDepth(5);
        InMemoryDnsResolver resolver = new InMemoryDnsResolver();
        for (int i = 0; i < 50; i++) {
            resolver.putTxt("chain" + i + ".example",
                    "v=spf1 include:chain" + (i + 1) + ".example -all");
        }
        resolver.putTxt("chain50.example", "v=spf1 +all");
        SpfEvaluator evaluator = new SpfEvaluator(
                new DnsCache(resolver, properties), properties);
        SpfResult result = evaluator.evaluate(
                "9.9.9.9", "chain0.example", "<a@chain0.example>");
        assertEquals(SpfStatus.PERMERROR, result.getStatus());
    }

    @Test
    void oversizedDkimKeyRecordYieldsPermerror() {
        AuthProperties properties = new AuthProperties();
        properties.getLimits().setMaxDnsResponseBytes(32);
        InMemoryDnsResolver resolver = new InMemoryDnsResolver();
        resolver.putTxt("sel._domainkey.example.com",
                "v=DKIM1; k=rsa; p=" + "A".repeat(500));
        String signatureHeader = "v=1; a=rsa-sha256; d=example.com; s=sel; "
                + "h=from; bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; "
                + "b=" + "B".repeat(100);
        byte[] raw = ("From: a@example.com\r\nDKIM-Signature: " + signatureHeader
                + "\r\n\r\nbody\r\n").getBytes(StandardCharsets.UTF_8);
        ParsedMail mail = new MailParser(new AuthProperties()).parse(raw);
        DkimResult result = new DkimEvaluator(
                new DnsCache(resolver, properties), properties).verify(mail);
        assertEquals(DkimStatus.PERMERROR, result.getStatus());
    }

    @Test
    void malformedHeaderDoesNotCrashParser() {
        AuthProperties properties = new AuthProperties();
        MailParser parser = new MailParser(properties);
        byte[] raw = "Subject: ok\r\nBROKEN\r\n\r\nx".getBytes(StandardCharsets.UTF_8);
        assertThrows(MailParseException.class, () -> parser.parse(raw));
    }
}

package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.DmarcEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.OrganizationalDomain;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.dns.InMemoryDnsResolver;
import com.github.guoyyit.emailauthjava.eval.AuthService;
import com.github.guoyyit.emailauthjava.mail.MailParser;
import com.github.guoyyit.emailauthjava.report.AggregateStore;
import com.github.guoyyit.emailauthjava.spf.SpfEvaluator;
import com.github.guoyyit.emailauthjava.web.AuthController;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthControllerTest {

    @Test
    void evaluateEndpointReturnsStructuredResult(@TempDir Path dir) {
        AuthProperties properties = new AuthProperties();
        properties.getReport().setStoreDir(dir.resolve("agg").toString());
        InMemoryDnsResolver resolver = new InMemoryDnsResolver();
        DnsCache cache = new DnsCache(resolver, properties);
        MailParser parser = new MailParser(properties);
        SpfEvaluator spf = new SpfEvaluator(cache, properties);
        DkimEvaluator dkim = new DkimEvaluator(cache, properties);
        DmarcEvaluator dmarc = new DmarcEvaluator(cache, properties,
                new OrganizationalDomain(properties));
        AggregateStore store = new AggregateStore(properties);
        AuthService service = new AuthService(parser, spf, dkim, dmarc, store, cache);
        AuthController controller = new AuthController(
                service, store,
                new com.github.guoyyit.emailauthjava.report.ReportGenerator("receiver"), cache);

        resolver.putTxt("example.com", "v=spf1 ip4:192.0.2.10 -all");
        resolver.putTxt("_dmarc.example.com", "v=DMARC1; p=reject");

        AuthController.EvaluationRequest request = new AuthController.EvaluationRequest();
        String raw = "From: alice@example.com\r\nSubject: s\r\n\r\nhi\r\n";
        request.setRawMessageBase64(Base64.getEncoder().encodeToString(
                raw.getBytes(StandardCharsets.ISO_8859_1)));
        request.setClientIp("192.0.2.10");
        request.setHeloDomain("example.com");
        request.setMailFrom("<alice@example.com>");

        var result = controller.evaluate(request);
        assertEquals("example.com", result.getFromDomain());
        assertEquals("NONE", result.getDmarc().getDisposition().name());
    }
}

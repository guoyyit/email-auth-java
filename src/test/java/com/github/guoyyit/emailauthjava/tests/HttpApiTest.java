package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.DmarcEvaluator;
import com.github.guoyyit.emailauthjava.dns.CachingDnsResolver;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.MapBackedDnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.message.MessageParser;
import com.github.guoyyit.emailauthjava.report.ReportStore;
import com.github.guoyyit.emailauthjava.service.AuthenticationService;
import com.github.guoyyit.emailauthjava.spf.SpfEvaluator;
import com.github.guoyyit.emailauthjava.web.EvaluationController;
import com.github.guoyyit.emailauthjava.web.WebExceptionHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class HttpApiTest {
    private MockMvc mockMvc;
    private MapBackedDnsResolver backend;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        backend = new MapBackedDnsResolver(new HashMap<>());
        AuthProperties properties = new AuthProperties();
        properties.getReport().setStoragePath(tempDir.resolve("r").toString());
        CachingDnsResolver caching = new CachingDnsResolver(backend, properties);
        AuthenticationService service = new AuthenticationService(
                new SpfEvaluator(caching, properties),
                new DkimEvaluator(caching, properties),
                new DmarcEvaluator(caching, properties),
                new MessageParser(properties),
                new ReportStore(properties), properties);
        mockMvc = MockMvcBuilders.standaloneSetup(new EvaluationController(service))
                .setControllerAdvice(new WebExceptionHandler()).build();
    }

    @Test
    void returnsStructuredResult() throws Exception {
        backend.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ip4:192.0.2.1 -all"));
        String request = """
                {
                  "heloDomain": "mail.example.com",
                  "clientIp": "192.0.2.1",
                  "envelopeFrom": "user@example.com",
                  "rawMessage": "From: user@example.com\\r\\n\\r\\nHi\\r\\n"
                }
                """;
        mockMvc.perform(post("/api/evaluate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.spf.status").value("PASS"))
                .andExpect(jsonPath("$.dmarc.disposition").value("NONE"));
    }

    @Test
    void oversizedMessageReturnsStructuredError() throws Exception {
        String huge = "x".repeat(20_000_000);
        String request = "{\"clientIp\":\"1.1.1.1\",\"rawMessage\":\"" + huge + "\"}";
        mockMvc.perform(post("/api/evaluate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.errorCode").value("MESSAGE_TOO_LARGE"));
    }
}

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

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class HttpApiTest {
    private MockMvc mockMvc;
    private MapBackedDnsResolver backend;
    private AuthenticationService service;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        backend = new MapBackedDnsResolver(new HashMap<>());
        AuthProperties properties = new AuthProperties();
        properties.getReport().setStoragePath(tempDir.resolve("r").toString());
        CachingDnsResolver caching = new CachingDnsResolver(backend, properties);
        this.service = new AuthenticationService(
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

    @Test
    void nonUtf8BodyIsEvaluatedByteForByte() throws Exception {
        backend.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 -all"));
        // 0xFF/0xFE/0x80 不是合法 UTF-8 序列：经 UTF-8 字符串传输会被替换。
        byte[] raw = ("From: user@example.com\r\nSubject: binary\r\n\r\nbody:"
                + "\u0000\u00ff\u00fe\u0080\u00c0\r\n").getBytes(StandardCharsets.ISO_8859_1);
        String encoded = Base64.getEncoder().encodeToString(raw);

        String inProcessMessageId = service.evaluate("mail.example.com", "192.0.2.2",
                "user@example.com", raw).getMessageId();

        String request = "{\"clientIp\":\"192.0.2.2\","
                + "\"envelopeFrom\":\"user@example.com\","
                + "\"rawMessageBase64\":\"" + encoded + "\"}";
        mockMvc.perform(post("/api/evaluate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.spf.status").value("FAIL"))
                // 无 Message-ID 时以原文 SHA-256 为标识：与进程内字节完全一致才会相等。
                .andExpect(jsonPath("$.messageId").value(inProcessMessageId));
    }

    @Test
    void utf8RawMessageRemainsBackwardCompatible() throws Exception {
        backend.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ip4:192.0.2.1 -all"));
        String request = """
                {
                  "clientIp": "192.0.2.1",
                  "envelopeFrom": "user@example.com",
                  "rawMessage": "From: user@example.com\\r\\nSubject: \\u4f60\\u597d\\r\\n\\r\\nHi\\r\\n"
                }
                """;
        mockMvc.perform(post("/api/evaluate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.spf.status").value("PASS"));
    }

    @Test
    void invalidBase64Returns400() throws Exception {
        String request = "{\"clientIp\":\"1.1.1.1\",\"rawMessageBase64\":\"@@@@\"}";
        mockMvc.perform(post("/api/evaluate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_PAYLOAD"));
    }
}

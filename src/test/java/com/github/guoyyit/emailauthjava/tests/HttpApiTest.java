package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimStatus;
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
import com.github.guoyyit.emailauthjava.spf.SpfStatus;
import com.github.guoyyit.emailauthjava.web.EvaluationController;
import com.github.guoyyit.emailauthjava.web.WebExceptionHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.file.Path;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.List;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class HttpApiTest {
    private MockMvc mockMvc;
    private MapBackedDnsResolver backend;
    private AuthenticationService service;
    private AuthProperties properties;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        backend = new MapBackedDnsResolver(new HashMap<>());
        properties = new AuthProperties();
        properties.getReport().setStoragePath(tempDir.resolve("r").toString());
        CachingDnsResolver caching = new CachingDnsResolver(backend, properties);
        service = new AuthenticationService(
                new SpfEvaluator(caching, properties),
                new DkimEvaluator(caching, properties),
                new DmarcEvaluator(caching, properties),
                new MessageParser(properties),
                new ReportStore(properties), properties);
        mockMvc = MockMvcBuilders.standaloneSetup(
                        new EvaluationController(service, properties))
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
    void rawEndpointEvaluatesNonUtf8BytesByteForByte() throws Exception {
        KeyPair keyPair = DkimTestKeys.generateRsa();
        backend.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ip4:192.0.2.10 -all"));
        backend.put("sel._domainkey.example.com", RecordType.TXT, DnsStatus.OK,
                List.of(DkimTestKeys.publicKeyTxt(keyPair)));

        // 正文包含非 UTF-8 的任意 8 位字节序列（如 0xFF 0xFE 0x80 等孤立首字节）。
        byte[] rawMessage = new DkimMessageSigner(keyPair).relaxed(
                new byte[] { 'H', 'i', (byte) 0xFF, (byte) 0xFE, (byte) 0x80,
                        (byte) 0xC3, (byte) 0x28 });

        // 进程内直接传入相同字节作为逐字节对照基线。
        com.github.guoyyit.emailauthjava.service.EvaluationResult direct = service.evaluate(
                "mail.example.com", "192.0.2.10", "user@example.com", rawMessage);
        assertThat(direct.getDkim().get(0).getStatus()).isEqualTo(DkimStatus.PASS);

        mockMvc.perform(post("/api/evaluate/raw")
                        .param("heloDomain", "mail.example.com")
                        .param("clientIp", "192.0.2.10")
                        .param("envelopeFrom", "user@example.com")
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .content(rawMessage))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.spf.status").value("PASS"))
                .andExpect(jsonPath("$.dkim[0].status").value("PASS"))
                .andExpect(jsonPath("$.messageId").value(direct.getMessageId()));

        // 与进程内直接传入相同字节时的结果逐字段一致。
        // 第二次经 HTTP 与直接评估的 messageId（无 Message-ID 时为原文 SHA-256）一致，
        // 证明 HTTP 链路未替换、丢弃或改动任何字节。
        com.github.guoyyit.emailauthjava.service.EvaluationResult directAgain = service.evaluate(
                "mail.example.com", "192.0.2.10", "user@example.com", rawMessage);
        assertThat(directAgain.getMessageId()).isEqualTo(direct.getMessageId());
        assertThat(directAgain.getSpf().getStatus()).isEqualTo(SpfStatus.PASS);
        assertThat(directAgain.getDkim().get(0).getStatus()).isEqualTo(DkimStatus.PASS);
    }

    @Test
    void rawEndpointBodyBytesArriveUnaltered() throws Exception {
        // 不签名：消息 ID 回退为原文 SHA-256，可直接证明服务端收到的字节与发送字节一致。
        byte[] rawMessage = new byte[] { 'F', 'r', 'o', 'm', ':', ' ', 'a', '@', 'e',
                '\r', '\n', '\r', '\n', 'x', (byte) 0xFF, (byte) 0x80, (byte) 0x00,
                (byte) 0xFE };
        String expectedId = "hash:" + sha256Hex(rawMessage);
        mockMvc.perform(post("/api/evaluate/raw")
                        .param("clientIp", "192.0.2.10")
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .content(rawMessage))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.messageId").value(expectedId));
    }

    private static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(
                    java.security.MessageDigest.getInstance("SHA-256").digest(data));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}

package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimEvaluator;
import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dkim.DkimStatus;
import com.github.guoyyit.emailauthjava.dns.DnsResult;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.MapBackedDnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.message.MessageParser;
import com.github.guoyyit.emailauthjava.message.RawMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DkimEvaluatorTest {
    private static final String DOMAIN = "example.com";
    private static final String SELECTOR = "sel";

    private MapBackedDnsResolver dns;
    private DkimEvaluator evaluator;
    private MessageParser parser;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() {
        dns = new MapBackedDnsResolver(new java.util.HashMap<>());
        evaluator = new DkimEvaluator(dns, new AuthProperties());
        parser = new MessageParser(new AuthProperties());
        keyPair = DkimTestKeys.generateRsa();
    }

    @Test
    void relaxedPass() throws Exception {
        byte[] raw = signed("relaxed/relaxed", null, "Hello\r\n",
                List.of(header("from", "Alice <alice@" + DOMAIN + ">"),
                        header("subject", "Test")),
                null, true);
        assertThat(evaluate(raw).get(0).getStatus()).isEqualTo(DkimStatus.PASS);
    }

    @Test
    void simplePassWithFoldedHeader() throws Exception {
        // Subject 使用折行，签名与验签都按 simple 保留折行字节。
        TestHeader folded = new TestHeader("subject", "Folded\r\n\tworld",
                "Subject: Folded\r\n\tworld\r\n");
        byte[] raw = signed("simple/simple", null, "Hello\r\n",
                List.of(header("from", "Alice <alice@" + DOMAIN + ">"), folded),
                null, true);
        assertThat(evaluate(raw).get(0).getStatus()).isEqualTo(DkimStatus.PASS);
    }

    @Test
    void bodyTamperedFails() throws Exception {
        byte[] raw = signed("relaxed/relaxed", null, "Hello\r\n",
                List.of(header("from", "alice@" + DOMAIN), header("subject", "Test")),
                null, true);
        String text = new String(raw, StandardCharsets.ISO_8859_1)
                .replace("Hello\r\n", "Hacker\r\n");
        RawMessage message = parser.parse("helo", "1.2.3.4",
                text.getBytes(StandardCharsets.ISO_8859_1));
        assertThat(evaluator.evaluate(message).get(0).getStatus()).isEqualTo(DkimStatus.FAIL);
    }

    @Test
    void bodyLengthTruncationAllowsExtraContent() throws Exception {
        // 签名正文为 7 个内容字节，l=5 只覆盖前 5 个；邮件传输后在同一行追加内容。
        byte[] raw = signed("relaxed/relaxed", 5L, "HelloAB\r\n",
                List.of(header("from", "alice@" + DOMAIN), header("subject", "Test")),
                null, true);
        String text = new String(raw, StandardCharsets.ISO_8859_1)
                .replace("HelloAB\r\n", "HelloAB extra unsigned content\r\n");
        RawMessage message = parser.parse("helo", "1.2.3.4",
                text.getBytes(StandardCharsets.ISO_8859_1));
        assertThat(evaluator.evaluate(message).get(0).getStatus()).isEqualTo(DkimStatus.PASS);
    }

    @Test
    void noSignatureIsNone() {
        byte[] raw = "From: a@example.com\r\n\r\nHi\r\n".getBytes(StandardCharsets.UTF_8);
        assertThat(evaluate(raw).get(0).getStatus()).isEqualTo(DkimStatus.NONE);
    }

    @Test
    void expiredSignatureIsPermerror() throws Exception {
        long expiration = System.currentTimeMillis() / 1000 - 3600;
        byte[] raw = signed("relaxed/relaxed", null, "Hi\r\n",
                List.of(header("from", "alice@" + DOMAIN), header("subject", "Test")),
                expiration, true);
        DkimResult result = evaluate(raw).get(0);
        assertThat(result.getStatus()).isEqualTo(DkimStatus.PERMERROR);
        assertThat(result.getReason()).contains("expired");
    }

    @Test
    void unknownSelectorIsPermerror() throws Exception {
        byte[] raw = signed("relaxed/relaxed", null, "Hi\r\n",
                List.of(header("from", "alice@" + DOMAIN), header("subject", "Test")),
                null, false);
        assertThat(evaluate(raw).get(0).getStatus()).isEqualTo(DkimStatus.PERMERROR);
    }

    @Test
    void keyTimeoutIsTemperror() throws Exception {
        byte[] raw = signed("relaxed/relaxed", null, "Hi\r\n",
                List.of(header("from", "alice@" + DOMAIN), header("subject", "Test")),
                null, false);
        dns.put(SELECTOR + "._domainkey." + DOMAIN, RecordType.TXT,
                new DnsResult(DnsStatus.TIMEOUT, List.of(), List.of()));
        assertThat(evaluate(raw).get(0).getStatus()).isEqualTo(DkimStatus.TEMPERROR);
    }

    @Test
    void malformedKeyResponseIsPermerror() throws Exception {
        byte[] raw = signed("relaxed/relaxed", null, "Hi\r\n",
                List.of(header("from", "alice@" + DOMAIN), header("subject", "Test")),
                null, false);
        dns.put(SELECTOR + "._domainkey." + DOMAIN, RecordType.TXT,
                new DnsResult(DnsStatus.MALFORMED, List.of(), List.of()));
        assertThat(evaluate(raw).get(0).getStatus()).isEqualTo(DkimStatus.PERMERROR);
    }

    @Test
    void malformedSignatureIsPermerror() {
        byte[] raw = ("DKIM-Signature: v=1; d=example.com\r\n\r\nHi\r\n")
                .getBytes(StandardCharsets.UTF_8);
        assertThat(evaluate(raw).get(0).getStatus()).isEqualTo(DkimStatus.PERMERROR);
    }

    private List<DkimResult> evaluate(byte[] raw) {
        RawMessage message = parser.parse("helo", "1.2.3.4", raw);
        return evaluator.evaluate(message);
    }

    private static TestHeader header(String name, String value) {
        return new TestHeader(name, value,
                capitalize(name) + ": " + value + "\r\n");
    }

    private static String capitalize(String value) {
        return value.substring(0, 1).toUpperCase() + value.substring(1);
    }

    private byte[] signed(String canonicalization, Long bodyLength, String body,
                          List<TestHeader> headers, Long expiration,
                          boolean publishKey) throws Exception {
        boolean headerRelaxed = canonicalization.startsWith("relaxed");
        boolean bodyRelaxed = canonicalization.endsWith("relaxed");

        String canonicalBody = canonicalBody(body, bodyRelaxed, bodyLength);
        String bh = base64(MessageDigest.getInstance("SHA-256").digest(
                canonicalBody.getBytes(StandardCharsets.ISO_8859_1)));

        StringBuilder hTag = new StringBuilder();
        for (int i = 0; i < headers.size(); i++) {
            if (i > 0) {
                hTag.append(':');
            }
            hTag.append(headers.get(i).name);
        }

        String tagsPrefix = "v=1; a=rsa-sha256; d=" + DOMAIN + "; s=" + SELECTOR
                + "; c=" + canonicalization + "; h=" + hTag + "; bh=" + bh;
        if (bodyLength != null) {
            tagsPrefix += "; l=" + bodyLength;
        }
        if (expiration != null) {
            tagsPrefix += "; x=" + expiration;
        }

        StringBuilder signedData = new StringBuilder();
        for (TestHeader testHeader : headers) {
            signedData.append(canonicalHeader(testHeader, headerRelaxed));
        }
        signedData.append(canonicalHeader(
                new TestHeader("dkim-signature", tagsPrefix + "; b=",
                        "DKIM-Signature: " + tagsPrefix + "; b=\r\n"), headerRelaxed));

        java.security.Signature signer = java.security.Signature.getInstance("SHA256withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(signedData.toString().getBytes(StandardCharsets.ISO_8859_1));
        String b = base64(signer.sign());

        StringBuilder rawMessage = new StringBuilder();
        for (TestHeader testHeader : headers) {
            rawMessage.append(testHeader.wireForm);
        }
        rawMessage.append("DKIM-Signature: ").append(tagsPrefix).append("; b=").append(b)
                .append("\r\n\r\n").append(body);

        if (publishKey) {
            dns.put(SELECTOR + "._domainkey." + DOMAIN, RecordType.TXT, DnsStatus.OK,
                    List.of(DkimTestKeys.publicKeyTxt(keyPair)));
        }
        return rawMessage.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private String canonicalHeader(TestHeader testHeader, boolean relaxed) {
        if (relaxed) {
            String value = testHeader.unfoldedValue.replaceAll("[ \\t]+", " ").trim();
            return testHeader.name + ":" + value + "\r\n";
        }
        String wire = testHeader.wireForm;
        int colon = wire.indexOf(':');
        return wire.substring(0, colon + 1) + wire.substring(colon + 1);
    }

    private String canonicalBody(String body, boolean relaxed, Long lengthLimit) {
        // 与 RFC l= 截断语义对齐：截取前 lengthLimit 个内容字节并补行尾，
        // 然后按 relaxed 规范化（折叠 WSP、去行尾空白、结尾单 CRLF）。
        String considered = body;
        if (lengthLimit != null) {
            int lineEnd = considered.indexOf('\n');
            String line = lineEnd >= 0 ? considered.substring(0, lineEnd)
                    .replaceFirst("\\r$", "") : considered;
            String kept = line.substring(0, (int) Math.min(lengthLimit, line.length()));
            considered = kept + "\r\n";
        }
        if (relaxed) {
            return considered.replaceAll("[ \\t]+\r\n", "\r\n")
                    .replaceAll("[ \\t]+", " ").trim() + "\r\n";
        }
        return considered;
    }

    private String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static final class TestHeader {
        private final String name;
        private final String unfoldedValue;
        private final String wireForm;

        private TestHeader(String name, String unfoldedValue, String wireForm) {
            this.name = name;
            this.unfoldedValue = unfoldedValue;
            this.wireForm = wireForm;
        }
    }
}

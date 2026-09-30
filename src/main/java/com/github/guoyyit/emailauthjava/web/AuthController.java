package com.github.guoyyit.emailauthjava.web;

import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.eval.AuthResult;
import com.github.guoyyit.emailauthjava.eval.AuthService;
import com.github.guoyyit.emailauthjava.mail.MailParseException;
import com.github.guoyyit.emailauthjava.report.AggregateBucket;
import com.github.guoyyit.emailauthjava.report.AggregateStore;
import com.github.guoyyit.emailauthjava.report.ReportGenerator;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * HTTP 接口：提交原始邮件，返回结构化判定结果；并支持拉取/提交聚合报告。
 */
@RestController
@RequestMapping("/api")
public class AuthController {

    private final AuthService authService;
    private final AggregateStore aggregateStore;
    private final ReportGenerator reportGenerator;
    private final DnsCache dnsCache;

    public AuthController(AuthService authService, AggregateStore aggregateStore,
                          ReportGenerator reportGenerator, DnsCache dnsCache) {
        this.authService = authService;
        this.aggregateStore = aggregateStore;
        this.reportGenerator = reportGenerator;
        this.dnsCache = dnsCache;
    }

    @PostMapping("/evaluate")
    public AuthResult evaluate(@RequestBody EvaluationRequest request) {
        byte[] raw = decodeMessage(request);
        return authService.evaluate(raw, request.getClientIp(),
                request.getHeloDomain(), request.getMailFrom());
    }

    @GetMapping(value = "/report/{domain}", produces = MediaType.APPLICATION_XML_VALUE)
    public String report(@PathVariable String domain) {
        List<AggregateBucket> buckets = aggregateStore.bucketsFor(domain);
        Instant begin = LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant();
        Instant end = begin.plusSeconds(86400);
        return reportGenerator.generateXml(domain,
                domain + "-" + begin.getEpochSecond(), begin, end, buckets);
    }

    @PostMapping("/report/{domain}/commit")
    public Map<String, Object> commitReport(@PathVariable String domain) {
        aggregateStore.markReported(domain);
        return Map.of("committed", true, "domain", domain);
    }

    @PostMapping("/cache/invalidate")
    public Map<String, Object> invalidateCache() {
        dnsCache.invalidateAll();
        return Map.of("invalidated", true);
    }

    private byte[] decodeMessage(EvaluationRequest request) {
        if (request.getRawMessageBase64() != null && !request.getRawMessageBase64().isBlank()) {
            try {
                return Base64.getDecoder().decode(
                        request.getRawMessageBase64().replaceAll("\\s+", ""));
            } catch (IllegalArgumentException ex) {
                throw new MailParseException("invalid base64 rawMessageBase64", false);
            }
        }
        if (request.getRawMessage() != null) {
            return request.getRawMessage().getBytes(StandardCharsets.ISO_8859_1);
        }
        throw new MailParseException("rawMessage or rawMessageBase64 required", false);
    }

    @ExceptionHandler(MailParseException.class)
    public ResponseEntity<Map<String, String>> handleParseFailure(MailParseException ex) {
        HttpStatus status = ex.isSizeLimit() ? HttpStatus.PAYLOAD_TOO_LARGE
                : HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .body(Map.of(
                        "error", ex.isSizeLimit() ? "message_too_large" : "malformed_message",
                        "message", ex.getMessage() == null ? "" : ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleOther(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .body(Map.of("error", "evaluation_failed",
                        "message", ex.getMessage() == null ? "" : ex.getMessage()));
    }

    /** 请求体：原始邮件（文本或 base64）与 SMTP 会话参数。 */
    public static class EvaluationRequest {
        private String rawMessage;
        private String rawMessageBase64;
        private String clientIp;
        private String heloDomain;
        private String mailFrom;

        public String getRawMessage() { return rawMessage; }
        public void setRawMessage(String rawMessage) { this.rawMessage = rawMessage; }
        public String getRawMessageBase64() { return rawMessageBase64; }
        public void setRawMessageBase64(String rawMessageBase64) { this.rawMessageBase64 = rawMessageBase64; }
        public String getClientIp() { return clientIp; }
        public void setClientIp(String clientIp) { this.clientIp = clientIp; }
        public String getHeloDomain() { return heloDomain; }
        public void setHeloDomain(String heloDomain) { this.heloDomain = heloDomain; }
        public String getMailFrom() { return mailFrom; }
        public void setMailFrom(String mailFrom) { this.mailFrom = mailFrom; }
    }
}

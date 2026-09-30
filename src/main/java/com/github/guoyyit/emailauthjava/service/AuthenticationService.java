package com.github.guoyyit.emailauthjava.service;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimEvaluator;
import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dmarc.DmarcEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.DmarcResult;
import com.github.guoyyit.emailauthjava.dns.CachingDnsResolver;
import com.github.guoyyit.emailauthjava.dns.DnsResolver;
import com.github.guoyyit.emailauthjava.error.ResourceLimitException;
import com.github.guoyyit.emailauthjava.message.Addresses;
import com.github.guoyyit.emailauthjava.message.MessageParser;
import com.github.guoyyit.emailauthjava.message.RawMessage;
import com.github.guoyyit.emailauthjava.report.ReportStore;
import com.github.guoyyit.emailauthjava.spf.SpfResult;
import com.github.guoyyit.emailauthjava.spf.SpfEvaluator;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Service
public class AuthenticationService {
    private final SpfEvaluator spfEvaluator;
    private final DkimEvaluator dkimEvaluator;
    private final DmarcEvaluator dmarcEvaluator;
    private final MessageParser messageParser;
    private final ReportStore reportStore;
    private final AuthProperties properties;

    public AuthenticationService(SpfEvaluator spfEvaluator, DkimEvaluator dkimEvaluator,
                                 DmarcEvaluator dmarcEvaluator, MessageParser messageParser,
                                 ReportStore reportStore, AuthProperties properties) {
        this.spfEvaluator = spfEvaluator;
        this.dkimEvaluator = dkimEvaluator;
        this.dmarcEvaluator = dmarcEvaluator;
        this.messageParser = messageParser;
        this.reportStore = reportStore;
        this.properties = properties;
    }

    public EvaluationResult evaluate(String heloDomain, String clientIp, String envelopeFrom,
                                     byte[] rawMessage) {
        EvaluationResult result = new EvaluationResult();
        result.setEnvelopeFrom(envelopeFrom);
        RawMessage message;
        try {
            message = messageParser.parse(heloDomain, clientIp, rawMessage);
        } catch (ResourceLimitException e) {
            result.setErrorCode(e.getError().name());
            result.setErrorMessage(e.getMessage());
            return result;
        }

        String messageId = stableMessageId(message);
        result.setMessageId(messageId);

        String fromHeader = message.getFirstHeader("From");
        String fromAddress = Addresses.extractAddress(fromHeader);
        String headerFromDomain = Addresses.domainOf(fromAddress);
        result.setHeaderFrom(fromAddress);

        // 单次评估固定一个记录版本快照，全程复用，避免策略更新时混用新旧记录。
        DnsResolver session = dnsSession();
        SpfResult spf;
        List<DkimResult> dkim;
        try {
            spf = spfEvaluator.evaluateWith(session, heloDomain, clientIp, envelopeFrom);
            dkim = dkimEvaluator.evaluate(message, session);
        } catch (ResourceLimitException e) {
            result.setErrorCode(e.getError().name());
            result.setErrorMessage(e.getMessage());
            return result;
        }

        DmarcResult dmarc = dmarcEvaluator.evaluateWith(session, headerFromDomain, spf, dkim,
                saltFor(messageId));
        result.setSpf(spf);
        result.setDkim(dkim);
        result.setDmarc(dmarc);

        reportStore.record(clientIp, result);
        return result;
    }

    private DnsResolver dnsSession() {
        DnsResolver shared = spfEvaluator.getSharedResolver();
        if (shared instanceof CachingDnsResolver caching) {
            return caching.openSession();
        }
        return shared;
    }

    private String stableMessageId(RawMessage message) {
        String messageIdHeader = message.getFirstHeader("Message-ID");
        if (messageIdHeader != null && !messageIdHeader.isBlank()) {
            return messageIdHeader.trim();
        }
        byte[] raw = message.getRaw();
        return "hash:" + toHex(sha256(raw == null ? new byte[0] : raw));
    }

    private long saltFor(String messageId) {
        byte[] digest = sha256(messageId.getBytes(StandardCharsets.UTF_8));
        long salt = 0;
        for (int i = 0; i < 8; i++) {
            salt = (salt << 8) | (digest[i] & 0xFFL);
        }
        return salt;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }
}

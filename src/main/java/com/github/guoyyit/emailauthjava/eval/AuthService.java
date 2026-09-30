package com.github.guoyyit.emailauthjava.eval;

import com.github.guoyyit.emailauthjava.dkim.DkimEvaluator;
import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dmarc.DmarcEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.DmarcPolicyAction;
import com.github.guoyyit.emailauthjava.dmarc.DmarcResult;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.mail.AddressExtractor;
import com.github.guoyyit.emailauthjava.mail.MailParser;
import com.github.guoyyit.emailauthjava.mail.ParsedMail;
import com.github.guoyyit.emailauthjava.report.AggregateKey;
import com.github.guoyyit.emailauthjava.report.AggregateStore;
import com.github.guoyyit.emailauthjava.spf.SpfEvaluator;
import com.github.guoyyit.emailauthjava.spf.SpfResult;

import java.time.Instant;

/**
 * 编排 SPF/DKIM/DMARC 的单次评估。
 * 一次评估进入同一 DNS 快照版本（不混用新旧记录），评估之间不互相阻塞。
 * 未通过认证的邮件按发件域策略进入聚合报告（周期内去重）。
 */
public class AuthService {

    private final MailParser mailParser;
    private final SpfEvaluator spfEvaluator;
    private final DkimEvaluator dkimEvaluator;
    private final DmarcEvaluator dmarcEvaluator;
    private final AggregateStore aggregateStore;
    private final DnsCache dnsCache;

    public AuthService(MailParser mailParser, SpfEvaluator spfEvaluator, DkimEvaluator dkimEvaluator,
                       DmarcEvaluator dmarcEvaluator, AggregateStore aggregateStore,
                       DnsCache dnsCache) {
        this.mailParser = mailParser;
        this.spfEvaluator = spfEvaluator;
        this.dkimEvaluator = dkimEvaluator;
        this.dmarcEvaluator = dmarcEvaluator;
        this.aggregateStore = aggregateStore;
        this.dnsCache = dnsCache;
    }

    public AuthResult evaluate(byte[] rawMessage, String clientIp, String heloDomain, String mailFrom) {
        long snapshotVersion = dnsCache.beginSnapshot();
        ParsedMail mail = parse(rawMessage);
        String fromDomain = AddressExtractor.fromDomain(mail);

        String spfAuthDomain = AddressExtractor.smtpDomain(mailFrom);
        if (spfAuthDomain == null) {
            spfAuthDomain = heloDomain == null ? null
                    : heloDomain.trim().toLowerCase(java.util.Locale.ROOT);
        }
        SpfResult spf = spfEvaluator.evaluate(
                snapshotVersion, clientIp, heloDomain, mailFrom);
        DkimResult dkim = dkimEvaluator.verify(snapshotVersion, mail);
        DmarcResult dmarc = dmarcEvaluator.evaluate(
                snapshotVersion, fromDomain, spf, spfAuthDomain, dkim);

        AuthResult result = new AuthResult(fromDomain, clientIp, spf, spfAuthDomain, dkim, dmarc);
        collectAggregate(mail, result);
        return result;
    }

    public ParsedMail parse(byte[] rawMessage) {
        return mailParser.parse(rawMessage);
    }

    public SpfResult evaluateSpfOnly(String clientIp, String heloDomain, String mailFrom) {
        return spfEvaluator.evaluate(clientIp, heloDomain, mailFrom);
    }

    private void collectAggregate(ParsedMail mail, AuthResult result) {
        DmarcResult dmarc = result.getDmarc();
        if (dmarc == null || dmarc.getPolicyDomain() == null) {
            return;
        }
        boolean aligned = dmarc.isSpfAligned() || dmarc.isDkimAligned();
        if (aligned) {
            return;
        }
        String messageId = mail.getFirstHeader("Message-ID");
        AggregateKey key = new AggregateKey(
                messageId == null ? "no-message-id:" + Integer.toHexString(
                        java.util.Arrays.hashCode(mail.getRawHeaderBlock())) : messageId,
                result.getSourceIp(),
                result.getFromDomain(),
                Instant.now());
        aggregateStore.record(key, Instant.now(),
                result.getSpf() == null ? "none" : result.getSpf().getStatus().name().toLowerCase(java.util.Locale.ROOT),
                result.getSpfAuthDomain(),
                result.getDkim() == null ? "none" : result.getDkim().getStatus().name().toLowerCase(java.util.Locale.ROOT),
                result.getDkim() == null ? null : result.getDkim().getAuthenticatedDomain(),
                dmarc.getDisposition().name().toLowerCase(java.util.Locale.ROOT));
    }
}

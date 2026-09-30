package com.github.guoyyit.emailauthjava.report;

import java.time.Instant;
import java.util.Objects;

/** 单封邮件在聚合报告中的去重键（周期内重复评估只计一次）。 */
public final class AggregateKey {
    private final String messageId;
    private final String sourceIp;
    private final String fromDomain;
    private final Instant firstSeen;

    public AggregateKey(String messageId, String sourceIp, String fromDomain, Instant firstSeen) {
        this.messageId = messageId;
        this.sourceIp = sourceIp;
        this.fromDomain = fromDomain;
        this.firstSeen = firstSeen;
    }

    public String getMessageId() { return messageId; }
    public String getSourceIp() { return sourceIp; }
    public String getFromDomain() { return fromDomain; }
    public Instant getFirstSeen() { return firstSeen; }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AggregateKey other)) {
            return false;
        }
        return Objects.equals(messageId, other.messageId)
                && Objects.equals(sourceIp, other.sourceIp)
                && Objects.equals(fromDomain, other.fromDomain);
    }

    @Override
    public int hashCode() {
        return Objects.hash(messageId, sourceIp, fromDomain);
    }
}

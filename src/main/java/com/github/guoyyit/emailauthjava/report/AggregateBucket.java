package com.github.guoyyit.emailauthjava.report;

import java.time.Instant;

/** 一个报告周期（UTC 日）内、某来源 IP 的聚合计数。 */
public final class AggregateBucket {
    private final AggregateKey key;
    private int count;
    private Instant lastSeen;
    private String spfResult;
    private String spfDomain;
    private String dkimResult;
    private String dkimDomain;
    private String disposition;

    public AggregateBucket(AggregateKey key) {
        this.key = key;
        this.lastSeen = key.getFirstSeen();
    }

    public AggregateKey getKey() { return key; }
    public int getCount() { return count; }
    public Instant getLastSeen() { return lastSeen; }
    public String getSpfResult() { return spfResult; }
    public String getSpfDomain() { return spfDomain; }
    public String getDkimResult() { return dkimResult; }
    public String getDkimDomain() { return dkimDomain; }
    public String getDisposition() { return disposition; }

    public void record(Instant seen, String spfResult, String spfDomain, String dkimResult,
                       String dkimDomain, String disposition) {
        this.count++;
        this.lastSeen = seen;
        this.spfResult = spfResult;
        this.spfDomain = spfDomain;
        this.dkimResult = dkimResult;
        this.dkimDomain = dkimDomain;
        this.disposition = disposition;
    }
}

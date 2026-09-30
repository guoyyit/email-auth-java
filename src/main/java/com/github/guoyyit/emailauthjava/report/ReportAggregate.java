package com.github.guoyyit.emailauthjava.report;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 单个报告周期、单个策略域的聚合数据。
 * 以 messageId 去重：同一封邮件周期内重复评估只计一次。
 */
public class ReportAggregate {
    private String domain;
    private long periodStart;
    private long periodEnd;
    private final Map<String, ReportEntry> entries = new LinkedHashMap<>();

    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }
    public long getPeriodStart() { return periodStart; }
    public void setPeriodStart(long periodStart) { this.periodStart = periodStart; }
    public long getPeriodEnd() { return periodEnd; }
    public void setPeriodEnd(long periodEnd) { this.periodEnd = periodEnd; }

    public Map<String, ReportEntry> getEntries() { return entries; }

    public boolean add(ReportEntry entry) {
        if (entries.containsKey(entry.getMessageId())) {
            return false;
        }
        entries.put(entry.getMessageId(), entry);
        return true;
    }

    public List<ReportEntry> entryList() {
        return new ArrayList<>(entries.values());
    }
}

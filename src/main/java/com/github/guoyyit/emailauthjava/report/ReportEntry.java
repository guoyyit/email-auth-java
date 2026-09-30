package com.github.guoyyit.emailauthjava.report;

/**
 * 聚合报告中的一条失败评估记录（内存模型，JSON 持久化）。
 */
public class ReportEntry {
    private String messageId;
    private String sourceIp;
    private String headerFrom;
    private String spfStatus;
    private String spfAligned;
    private String dkimStatus;
    private String dkimAligned;
    private String disposition;
    private long timestamp;

    public String getMessageId() { return messageId; }
    public void setMessageId(String messageId) { this.messageId = messageId; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getHeaderFrom() { return headerFrom; }
    public void setHeaderFrom(String headerFrom) { this.headerFrom = headerFrom; }
    public String getSpfStatus() { return spfStatus; }
    public void setSpfStatus(String spfStatus) { this.spfStatus = spfStatus; }
    public String getSpfAligned() { return spfAligned; }
    public void setSpfAligned(String spfAligned) { this.spfAligned = spfAligned; }
    public String getDkimStatus() { return dkimStatus; }
    public void setDkimStatus(String dkimStatus) { this.dkimStatus = dkimStatus; }
    public String getDkimAligned() { return dkimAligned; }
    public void setDkimAligned(String dkimAligned) { this.dkimAligned = dkimAligned; }
    public String getDisposition() { return disposition; }
    public void setDisposition(String disposition) { this.disposition = disposition; }
    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
}

package com.github.guoyyit.emailauthjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 可配置的资源边界与行为上限。所有前缀均为 {@code email-auth}。
 */
@ConfigurationProperties(prefix = "email-auth")
public class AuthProperties {

    private final Limits limits = new Limits();
    private final Spf spf = new Spf();
    private final Dkim dkim = new Dkim();
    private final Dmarc dmarc = new Dmarc();
    private final Cache cache = new Cache();
    private final Report report = new Report();

    public Limits getLimits() {
        return limits;
    }

    public Spf getSpf() {
        return spf;
    }

    public Dkim getDkim() {
        return dkim;
    }

    public Dmarc getDmarc() {
        return dmarc;
    }

    public Cache getCache() {
        return cache;
    }

    public Report getReport() {
        return report;
    }

    /** 通用输入资源上限。 */
    public static class Limits {
        /** 允许提交的原始邮件最大字节数。 */
        private long maxMessageBytes = 2L * 1024 * 1024;
        /** 单个头部行（折行展开后）最大字节数。 */
        private long maxHeaderLineBytes = 65536;
        /** 头部区最大总字节数。 */
        private long maxHeaderBytes = 512 * 1024;
        /** 头部数量上限。 */
        private int maxHeaders = 1000;
        /** 单条 DNS 响应（拼接后的 TXT 文本等）最大字节数。 */
        private long maxDnsResponseBytes = 16 * 1024;
        /** DKIM h= 标签中头部数量上限。 */
        private int maxSignedHeaders = 256;

        public long getMaxMessageBytes() { return maxMessageBytes; }
        public void setMaxMessageBytes(long maxMessageBytes) { this.maxMessageBytes = maxMessageBytes; }
        public long getMaxHeaderLineBytes() { return maxHeaderLineBytes; }
        public void setMaxHeaderLineBytes(long maxHeaderLineBytes) { this.maxHeaderLineBytes = maxHeaderLineBytes; }
        public long getMaxHeaderBytes() { return maxHeaderBytes; }
        public void setMaxHeaderBytes(long maxHeaderBytes) { this.maxHeaderBytes = maxHeaderBytes; }
        public int getMaxHeaders() { return maxHeaders; }
        public void setMaxHeaders(int maxHeaders) { this.maxHeaders = maxHeaders; }
        public long getMaxDnsResponseBytes() { return maxDnsResponseBytes; }
        public void setMaxDnsResponseBytes(long maxDnsResponseBytes) { this.maxDnsResponseBytes = maxDnsResponseBytes; }
        public int getMaxSignedHeaders() { return maxSignedHeaders; }
        public void setMaxSignedHeaders(int maxSignedHeaders) { this.maxSignedHeaders = maxSignedHeaders; }
    }

    /** SPF 求值上限。 */
    public static class Spf {
        /** include/redirect 递归深度上限。 */
        private int maxIncludeDepth = 10;
        /** 单次 SPF 求值 DNS 查询次数上限。 */
        private int maxDnsQueries = 30;
        /** 空应答（NXDOMAIN/NODATA）次数上限，超出视为 permerror。 */
        private int maxVoidLookups = 2;

        public int getMaxIncludeDepth() { return maxIncludeDepth; }
        public void setMaxIncludeDepth(int maxIncludeDepth) { this.maxIncludeDepth = maxIncludeDepth; }
        public int getMaxDnsQueries() { return maxDnsQueries; }
        public void setMaxDnsQueries(int maxDnsQueries) { this.maxDnsQueries = maxDnsQueries; }
        public int getMaxVoidLookups() { return maxVoidLookups; }
        public void setMaxVoidLookups(int maxVoidLookups) { this.maxVoidLookups = maxVoidLookups; }
    }

    /** DKIM 求值上限。 */
    public static class Dkim {
        /** 单次验证最多处理的签名数量。 */
        private int maxSignatures = 10;
        /** 签名容忍的时钟偏移（秒），用于 x= 过期判定。 */
        private long expirySkewSeconds = 0;

        public int getMaxSignatures() { return maxSignatures; }
        public void setMaxSignatures(int maxSignatures) { this.maxSignatures = maxSignatures; }
        public long getExpirySkewSeconds() { return expirySkewSeconds; }
        public void setExpirySkewSeconds(long expirySkewSeconds) { this.expirySkewSeconds = expirySkewSeconds; }
    }

    /** DMARC 求值配置。 */
    public static class Dmarc {
        /** 额外的私有后缀（多标签），用于组织域判定，每行一个。 */
        private java.util.List<String> privateSuffixes = new java.util.ArrayList<>();

        public java.util.List<String> getPrivateSuffixes() { return privateSuffixes; }
        public void setPrivateSuffixes(java.util.List<String> privateSuffixes) { this.privateSuffixes = privateSuffixes; }
    }

    /** DNS 缓存 TTL（秒）。 */
    public static class Cache {
        /** 正向记录 TTL 上限，记录自身 TTL 超过此值时截断。 */
        private long maxPositiveTtlSeconds = 86400;
        /** NXDOMAIN/NODATA 缓存秒数。 */
        private long nxdomainTtlSeconds = 300;
        /** 格式错误应答缓存秒数。 */
        private long malformedTtlSeconds = 60;
        /** 超时应答缓存秒数，0 表示不缓存。 */
        private long timeoutTtlSeconds = 0;

        public long getMaxPositiveTtlSeconds() { return maxPositiveTtlSeconds; }
        public void setMaxPositiveTtlSeconds(long maxPositiveTtlSeconds) { this.maxPositiveTtlSeconds = maxPositiveTtlSeconds; }
        public long getNxdomainTtlSeconds() { return nxdomainTtlSeconds; }
        public void setNxdomainTtlSeconds(long nxdomainTtlSeconds) { this.nxdomainTtlSeconds = nxdomainTtlSeconds; }
        public long getMalformedTtlSeconds() { return malformedTtlSeconds; }
        public void setMalformedTtlSeconds(long malformedTtlSeconds) { this.malformedTtlSeconds = malformedTtlSeconds; }
        public long getTimeoutTtlSeconds() { return timeoutTtlSeconds; }
        public void setTimeoutTtlSeconds(long timeoutTtlSeconds) { this.timeoutTtlSeconds = timeoutTtlSeconds; }
    }

    /** 聚合反馈报告配置。 */
    public static class Report {
        /** 是否启用聚合收集。 */
        private boolean enabled = true;
        /** 持久化目录（重启后不丢失未提交聚合数据）。 */
        private String storeDir = "data/aggregate";
        /** 报告中本机构的接收方标识（DMARC rua 报告发送方）。 */
        private String reportReceiver = "receiver.example";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getStoreDir() { return storeDir; }
        public void setStoreDir(String storeDir) { this.storeDir = storeDir; }
        public String getReportReceiver() { return reportReceiver; }
        public void setReportReceiver(String reportReceiver) { this.reportReceiver = reportReceiver; }
    }
}

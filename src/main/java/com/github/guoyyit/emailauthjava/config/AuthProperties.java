package com.github.guoyyit.emailauthjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "emailauth")
public class AuthProperties {
    private final Limits limits = new Limits();
    private final Dns dns = new Dns();
    private final Report report = new Report();

    public Limits getLimits() { return limits; }
    public Dns getDns() { return dns; }
    public Report getReport() { return report; }

    public static class Limits {
        private long maxMessageBytes = 10 * 1024 * 1024;
        private int maxHeaderBytes = 16384;
        private int maxHeaders = 256;
        private int maxHeaderLineBytes = 8192;
        private int maxDnsResponseBytes = 65535;
        private int maxIncludeDepth = 8;
        private int maxDnsQueries = 64;
        private int maxSignatures = 16;

        public long getMaxMessageBytes() { return maxMessageBytes; }
        public void setMaxMessageBytes(long v) { this.maxMessageBytes = v; }
        public int getMaxHeaderBytes() { return maxHeaderBytes; }
        public void setMaxHeaderBytes(int v) { this.maxHeaderBytes = v; }
        public int getMaxHeaders() { return maxHeaders; }
        public void setMaxHeaders(int v) { this.maxHeaders = v; }
        public int getMaxHeaderLineBytes() { return maxHeaderLineBytes; }
        public void setMaxHeaderLineBytes(int v) { this.maxHeaderLineBytes = v; }
        public int getMaxDnsResponseBytes() { return maxDnsResponseBytes; }
        public void setMaxDnsResponseBytes(int v) { this.maxDnsResponseBytes = v; }
        public int getMaxIncludeDepth() { return maxIncludeDepth; }
        public void setMaxIncludeDepth(int v) { this.maxIncludeDepth = v; }
        public int getMaxDnsQueries() { return maxDnsQueries; }
        public void setMaxDnsQueries(int v) { this.maxDnsQueries = v; }
        public int getMaxSignatures() { return maxSignatures; }
        public void setMaxSignatures(int v) { this.maxSignatures = v; }
    }

    public static class Dns {
        private long timeoutMillis = 3000;
        private long cacheTtlSeconds = 300;
        // 三类失败结果各自独立的缓存时长（秒）；配置为 0 时对应失败结果不缓存。
        private long nxdomainCacheTtlSeconds = 60;
        private long timeoutCacheTtlSeconds = 5;
        private long malformedCacheTtlSeconds = 60;

        public long getTimeoutMillis() { return timeoutMillis; }
        public void setTimeoutMillis(long v) { this.timeoutMillis = v; }
        public long getCacheTtlSeconds() { return cacheTtlSeconds; }
        public void setCacheTtlSeconds(long v) { this.cacheTtlSeconds = v; }
        public long getNxdomainCacheTtlSeconds() { return nxdomainCacheTtlSeconds; }
        public void setNxdomainCacheTtlSeconds(long v) { this.nxdomainCacheTtlSeconds = v; }
        public long getTimeoutCacheTtlSeconds() { return timeoutCacheTtlSeconds; }
        public void setTimeoutCacheTtlSeconds(long v) { this.timeoutCacheTtlSeconds = v; }
        public long getMalformedCacheTtlSeconds() { return malformedCacheTtlSeconds; }
        public void setMalformedCacheTtlSeconds(long v) { this.malformedCacheTtlSeconds = v; }
    }

    public static class Report {
        private String storagePath = "data/report";
        private long intervalSeconds = 86400;

        public String getStoragePath() { return storagePath; }
        public void setStoragePath(String v) { this.storagePath = v; }
        public long getIntervalSeconds() { return intervalSeconds; }
        public void setIntervalSeconds(long v) { this.intervalSeconds = v; }
    }
}

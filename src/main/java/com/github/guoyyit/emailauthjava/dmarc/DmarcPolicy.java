package com.github.guoyyit.emailauthjava.dmarc;

public class DmarcPolicy {
    private String domain;
    private String policy;
    private String subdomainPolicy;
    private int percent;
    private String alignmentSpf;
    private String alignmentDkim;
    private String reportEmail;
    private boolean found;

    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }
    public String getPolicy() { return policy; }
    public void setPolicy(String policy) { this.policy = policy; }
    public String getSubdomainPolicy() { return subdomainPolicy; }
    public void setSubdomainPolicy(String subdomainPolicy) { this.subdomainPolicy = subdomainPolicy; }
    public int getPercent() { return percent; }
    public void setPercent(int percent) { this.percent = percent; }
    public String getAlignmentSpf() { return alignmentSpf; }
    public void setAlignmentSpf(String alignmentSpf) { this.alignmentSpf = alignmentSpf; }
    public String getAlignmentDkim() { return alignmentDkim; }
    public void setAlignmentDkim(String alignmentDkim) { this.alignmentDkim = alignmentDkim; }
    public String getReportEmail() { return reportEmail; }
    public void setReportEmail(String reportEmail) { this.reportEmail = reportEmail; }
    public boolean isFound() { return found; }
    public void setFound(boolean found) { this.found = found; }
}

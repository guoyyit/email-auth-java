package com.github.guoyyit.emailauthjava.dkim;

public class DkimResult {
    private final DkimStatus status;
    private final String selector;
    private final String domain;
    private final String reason;

    public DkimResult(DkimStatus status, String selector, String domain, String reason) {
        this.status = status;
        this.selector = selector;
        this.domain = domain;
        this.reason = reason;
    }

    public DkimStatus getStatus() { return status; }
    public String getSelector() { return selector; }
    public String getDomain() { return domain; }
    public String getReason() { return reason; }
}

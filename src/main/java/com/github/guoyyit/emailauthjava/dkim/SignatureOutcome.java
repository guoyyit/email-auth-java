package com.github.guoyyit.emailauthjava.dkim;

/**
 * 单个 DKIM-Signature 的判定。{@code selector} 与 {@code domain} 取自签名标签 d=/s=。
 */
public final class SignatureOutcome {
    private final String selector;
    private final String domain;
    private final DkimStatus status;
    private final String reason;

    public SignatureOutcome(String selector, String domain, DkimStatus status, String reason) {
        this.selector = selector;
        this.domain = domain;
        this.status = status;
        this.reason = reason;
    }

    public String getSelector() { return selector; }
    public String getDomain() { return domain; }
    public DkimStatus getStatus() { return status; }
    public String getReason() { return reason; }
}

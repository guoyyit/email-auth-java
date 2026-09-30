package com.github.guoyyit.emailauthjava.dns;

/** DNS 查询异常，携带与 {@link DnsStatus} 对应的稳定故障分类。 */
public class DnsException extends RuntimeException {
    private final DnsStatus status;

    public DnsException(DnsStatus status, String message) {
        super(message);
        this.status = status;
    }

    public DnsException(DnsStatus status, String message, Throwable cause) {
 super(message, cause);
        this.status = status;
    }

    public DnsStatus getStatus() {
        return status;
    }
}

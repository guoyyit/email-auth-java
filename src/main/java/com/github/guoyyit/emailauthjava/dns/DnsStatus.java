package com.github.guoyyit.emailauthjava.dns;

/**
 * DNS 解析结果的三类互斥故障语义与成功状态。
 * NO_DATA 为域名存在但无对应类型记录（RFC 2308）。
 */
public enum DnsStatus {
    OK,
    NXDOMAIN,
    NO_DATA,
    TIMEOUT,
    MALFORMED
}

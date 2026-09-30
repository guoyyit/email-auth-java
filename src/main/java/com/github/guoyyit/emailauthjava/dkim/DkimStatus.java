package com.github.guoyyit.emailauthjava.dkim;

/** DKIM 单签名/整体结果（RFC 6376 §3.7/§3.8/§4.2）。 */
public enum DkimStatus {
    PASS,
    FAIL,
    NONE,
    PERMERROR,
    TEMPERROR
}

package com.github.guoyyit.emailauthjava.spf;

/** SPF 七类结果（RFC 7208 §2.6）。 */
public enum SpfStatus {
    PASS,
    FAIL,
    SOFTFAIL,
    NEUTRAL,
    NONE,
    PERMERROR,
    TEMPERROR
}

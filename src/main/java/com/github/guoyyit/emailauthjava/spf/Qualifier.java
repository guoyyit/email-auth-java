package com.github.guoyyit.emailauthjava.spf;

/** 机制限定符（RFC 7208 §4.6.2）到 SPF 结果的映射。 */
enum Qualifier {
    PASS(SpfStatus.PASS),
    FAIL(SpfStatus.FAIL),
    SOFTFAIL(SpfStatus.SOFTFAIL),
    NEUTRAL(SpfStatus.NEUTRAL);

    final SpfStatus result;

    Qualifier(SpfStatus result) {
        this.result = result;
    }
}

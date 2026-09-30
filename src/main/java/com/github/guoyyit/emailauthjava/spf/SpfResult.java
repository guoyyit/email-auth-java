package com.github.guoyyit.emailauthjava.spf;

import java.util.List;

/** SPF 结果（RFC 7208）。 */
public final class SpfResult {
    private final SpfStatus status;
    private final String explanation;
    private final List<String> matchedMechanisms;

    public SpfResult(SpfStatus status, String explanation, List<String> matchedMechanisms) {
        this.status = status;
        this.explanation = explanation;
        this.matchedMechanisms = matchedMechanisms == null ? List.of() : List.copyOf(matchedMechanisms);
    }

    public static SpfResult of(SpfStatus status, String explanation) {
        return new SpfResult(status, explanation, List.of());
    }

    public static SpfResult of(SpfStatus status, String explanation, List<String> matchedMechanisms) {
        return new SpfResult(status, explanation, matchedMechanisms);
    }

    public SpfStatus getStatus() { return status; }
    public String getExplanation() { return explanation; }
    public List<String> getMatchedMechanisms() { return matchedMechanisms; }

    /** 仅 PASS 可作为 SPF 认证通过参与 DMARC 对齐。 */
    public boolean isPass() {
        return status == SpfStatus.PASS;
    }
}

package com.github.guoyyit.emailauthjava.spf;

public class SpfResult {
    private final SpfStatus status;
    private final String explanation;
    private final String matchedDomain;

    public SpfResult(SpfStatus status, String explanation, String matchedDomain) {
        this.status = status;
        this.explanation = explanation;
        this.matchedDomain = matchedDomain;
    }

    public SpfStatus getStatus() { return status; }
    public String getExplanation() { return explanation; }
    public String getMatchedDomain() { return matchedDomain; }
}

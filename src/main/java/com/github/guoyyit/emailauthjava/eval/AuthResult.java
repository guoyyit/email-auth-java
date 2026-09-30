package com.github.guoyyit.emailauthjava.eval;

import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dmarc.DmarcResult;
import com.github.guoyyit.emailauthjava.spf.SpfResult;

/** 单次邮件认证评估的结构化判定结果。 */
public final class AuthResult {
    private final String fromDomain;
    private final String sourceIp;
    private final SpfResult spf;
    private final String spfAuthDomain;
    private final DkimResult dkim;
    private final DmarcResult dmarc;

    public AuthResult(String fromDomain, String sourceIp, SpfResult spf, String spfAuthDomain,
                      DkimResult dkim, DmarcResult dmarc) {
        this.fromDomain = fromDomain;
        this.sourceIp = sourceIp;
        this.spf = spf;
        this.spfAuthDomain = spfAuthDomain;
        this.dkim = dkim;
        this.dmarc = dmarc;
    }

    public String getFromDomain() { return fromDomain; }
    public String getSourceIp() { return sourceIp; }
    public SpfResult getSpf() { return spf; }
    public String getSpfAuthDomain() { return spfAuthDomain; }
    public DkimResult getDkim() { return dkim; }
    public DmarcResult getDmarc() { return dmarc; }
}

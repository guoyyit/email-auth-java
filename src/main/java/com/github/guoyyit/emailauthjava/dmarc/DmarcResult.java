package com.github.guoyyit.emailauthjava.dmarc;

/** DMARC 综合判定。 */
public final class DmarcResult {
    private final DmarcPolicyAction disposition;
    private final boolean spfAligned;
    private final boolean dkimAligned;
    private final String policyDomain;
    private final String reason;

    public DmarcResult(DmarcPolicyAction disposition, boolean spfAligned, boolean dkimAligned,
                       String policyDomain, String reason) {
        this.disposition = disposition;
        this.spfAligned = spfAligned;
        this.dkimAligned = dkimAligned;
        this.policyDomain = policyDomain;
        this.reason = reason;
    }

    public DmarcPolicyAction getDisposition() { return disposition; }
    public boolean isSpfAligned() { return spfAligned; }
    public boolean isDkimAligned() { return dkimAligned; }
    public String getPolicyDomain() { return policyDomain; }
    public String getReason() { return reason; }
}

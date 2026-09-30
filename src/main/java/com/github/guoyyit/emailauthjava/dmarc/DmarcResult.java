package com.github.guoyyit.emailauthjava.dmarc;

import java.util.List;

public class DmarcResult {
    private final DmarcDisposition disposition;
    private final boolean spfAligned;
    private final boolean dkimAligned;
    private final String policyDomain;
    private final List<String> reasons;

    public DmarcResult(DmarcDisposition disposition, boolean spfAligned, boolean dkimAligned,
                       String policyDomain, List<String> reasons) {
        this.disposition = disposition;
        this.spfAligned = spfAligned;
        this.dkimAligned = dkimAligned;
        this.policyDomain = policyDomain;
        this.reasons = reasons;
    }

    public DmarcDisposition getDisposition() { return disposition; }
    public boolean isSpfAligned() { return spfAligned; }
    public boolean isDkimAligned() { return dkimAligned; }
    public String getPolicyDomain() { return policyDomain; }
    public List<String> getReasons() { return reasons; }
}

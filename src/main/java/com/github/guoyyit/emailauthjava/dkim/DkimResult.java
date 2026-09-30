package com.github.guoyyit.emailauthjava.dkim;

import java.util.List;

/** DKIM 整体验证结果（多签名中的最佳结果）及逐签名明细。 */
public final class DkimResult {
    private final DkimStatus status;
    private final List<SignatureOutcome> signatures;

    public DkimResult(DkimStatus status, List<SignatureOutcome> signatures) {
        this.status = status;
        this.signatures = signatures == null ? List.of() : List.copyOf(signatures);
    }

    public DkimStatus getStatus() { return status; }
    public List<SignatureOutcome> getSignatures() { return signatures; }

    /** 首个 PASS 签名的 d= 域；无 PASS 时返回 null。 */
    public String getAuthenticatedDomain() {
        for (SignatureOutcome outcome : signatures) {
            if (outcome.getStatus() == DkimStatus.PASS) {
                return outcome.getDomain();
            }
        }
        return null;
    }

    /**
     * 汇总多签名结果（RFC 6376 §3.8/§6.1）：
     * 任一 PASS 则整体 PASS；无签名为 NONE；有临时失败且无更终态则 TEMPERROR；
     * 否则（存在签名但均失败/格式错误）为 FAIL 或 PERMERROR。
     */
    public static DkimResult combine(List<SignatureOutcome> outcomes) {
        if (outcomes == null || outcomes.isEmpty()) {
            return new DkimResult(DkimStatus.NONE, List.of());
        }
        boolean temp = false;
        boolean fail = false;
        boolean perm = false;
        for (SignatureOutcome outcome : outcomes) {
            switch (outcome.getStatus()) {
                case PASS -> {
                    return new DkimResult(DkimStatus.PASS, outcomes);
                }
                case TEMPERROR -> temp = true;
                case PERMERROR -> perm = true;
                default -> fail = true;
            }
        }
        DkimStatus overall = fail ? DkimStatus.FAIL : (perm ? DkimStatus.PERMERROR
                : (temp ? DkimStatus.TEMPERROR : DkimStatus.NONE));
        return new DkimResult(overall, outcomes);
    }
}

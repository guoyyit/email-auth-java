package com.github.guoyyit.emailauthjava.dmarc;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dkim.DkimStatus;
import com.github.guoyyit.emailauthjava.dns.DnsResult;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.DnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.spf.SpfStatus;
import com.github.guoyyit.emailauthjava.spf.SpfResult;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Component
public class DmarcEvaluator {
    private final DnsResolver dnsResolver;
    private final AuthProperties properties;

    public DmarcEvaluator(DnsResolver dnsResolver, AuthProperties properties) {
        this.dnsResolver = dnsResolver;
        this.properties = properties;
    }

    public DmarcResult evaluate(String headerFromDomain, SpfResult spf, List<DkimResult> dkim, long samplingSalt) {
        return evaluateWith(dnsResolver, headerFromDomain, spf, dkim, samplingSalt);
    }

    public DmarcResult evaluateWith(DnsResolver resolver, String headerFromDomain, SpfResult spf,
                                    List<DkimResult> dkim, long samplingSalt) {
        List<String> reasons = new ArrayList<>();
        if (headerFromDomain == null) {
            return new DmarcResult(DmarcDisposition.NONE, false, false, null,
                    List.of("no header-from domain"));
        }
        String fromDomain = headerFromDomain.toLowerCase(Locale.ROOT);

        PolicyLookup lookup = lookupPolicy(resolver, fromDomain, reasons);
        if (lookup.temperror != null) {
            reasons.add(lookup.temperror);
            return new DmarcResult(DmarcDisposition.NONE, false, false, null, reasons);
        }
        if (lookup.permerror) {
            reasons.add("dmarc policy permerror; disposition none");
            return new DmarcResult(DmarcDisposition.NONE, false, false,
                    lookup.policy == null ? null : lookup.policy.getDomain(), reasons);
        }
        if (lookup.policy == null) {
            reasons.add("no dmarc policy");
            return new DmarcResult(DmarcDisposition.NONE, false, false, null, reasons);
        }

        DmarcPolicy policy = lookup.policy;
        boolean spfStrict = "s".equals(policy.getAlignmentSpf());
        boolean dkimStrict = "s".equals(policy.getAlignmentDkim());

        boolean spfAligned = spf != null
                && spf.getStatus() == SpfStatus.PASS
                && OrgDomains.isAligned(spf.getMatchedDomain(), fromDomain, spfStrict);
        reasons.add(spfAligned ? "spf_aligned"
                : "spf_not_aligned:" + (spf == null ? "missing" : spf.getStatus()));

        boolean dkimAligned = false;
        for (DkimResult result : dkim) {
            if (result.getStatus() == DkimStatus.PASS
                    && OrgDomains.isAligned(result.getDomain(), fromDomain, dkimStrict)) {
                dkimAligned = true;
                break;
            }
        }
        reasons.add(dkimAligned ? "dkim_aligned" : "dkim_not_aligned");

        if (spfAligned || dkimAligned) {
            reasons.add("authenticated");
            return new DmarcResult(DmarcDisposition.NONE, spfAligned, dkimAligned,
                    policy.getDomain(), reasons);
        }

        boolean isSubdomain = !fromDomain.equals(policy.getDomain());
        String effectivePolicy;
        if (isSubdomain) {
            effectivePolicy = policy.getSubdomainPolicy() != null
                    ? policy.getSubdomainPolicy() : policy.getPolicy();
            reasons.add("subdomain policy=" + effectivePolicy);
        } else {
            effectivePolicy = policy.getPolicy();
            reasons.add("domain policy=" + effectivePolicy);
        }

        if (!inSample(policy.getPercent(), fromDomain, samplingSalt)) {
            reasons.add("not_in_pct_sample(" + policy.getPercent() + ")");
            return new DmarcResult(DmarcDisposition.NONE, false, false,
                    policy.getDomain(), reasons);
        }
        reasons.add("in_pct_sample(" + policy.getPercent() + ")");

        DmarcDisposition disposition = switch (effectivePolicy) {
            case "reject" -> DmarcDisposition.REJECT;
            case "quarantine" -> DmarcDisposition.QUARANTINE;
            default -> DmarcDisposition.NONE;
        };
        reasons.add("disposition=" + disposition.name().toLowerCase(Locale.ROOT));
        return new DmarcResult(disposition, spfAligned, dkimAligned,
                policy.getDomain(), reasons);
    }

    private PolicyLookup lookupPolicy(DnsResolver resolver, String fromDomain,
                                      List<String> reasons) {
        PolicyLookup lookup = queryOne(resolver, "_dmarc." + fromDomain, fromDomain, reasons);
        if (lookup.policy != null || lookup.temperror != null || lookup.permerror) {
            return lookup;
        }
        String orgDomain = OrgDomains.organizationalDomain(fromDomain);
        if (orgDomain != null && !orgDomain.equals(fromDomain)) {
            reasons.add("org domain fallback to " + orgDomain);
            return queryOne(resolver, "_dmarc." + orgDomain, orgDomain, reasons);
        }
        return lookup;
    }

    private PolicyLookup queryOne(DnsResolver resolver, String dnsName, String policyDomain,
                                  List<String> reasons) {
        PolicyLookup lookup = new PolicyLookup();
        DnsResult result = resolver.resolve(dnsName, RecordType.TXT);
        switch (result.getStatus()) {
            case NXDOMAIN -> reasons.add("no policy record at " + dnsName);
            case TIMEOUT -> lookup.temperror = "dmarc policy lookup timeout at " + dnsName;
            case MALFORMED -> lookup.temperror = "dmarc policy lookup malformed at " + dnsName;
            case OK -> {
                String dmarcRecord = selectDmarcRecord(result, reasons, lookup);
                if (dmarcRecord != null) {
                    try {
                        lookup.policy = DmarcPolicyParser.parse(policyDomain, dmarcRecord);
                    } catch (IllegalArgumentException e) {
                        lookup.permerror = true;
                        reasons.add("invalid policy record: " + e.getMessage());
                    }
                }
            }
        }
        return lookup;
    }

    private String selectDmarcRecord(DnsResult result, List<String> reasons, PolicyLookup lookup) {
        String found = null;
        for (String txt : result.getRecords()) {
            String candidate = txt == null ? "" : txt.trim();
            String prefix = candidate.toLowerCase(Locale.ROOT);
            if (prefix.startsWith("v=dmarc1")) {
                if (found != null) {
                    lookup.permerror = true;
                    reasons.add("multiple dmarc policy records");
                    return null;
                }
                found = candidate;
            }
        }
        return found;
    }

    private boolean inSample(int percent, String domain, long salt) {
        if (percent >= 100) {
            return true;
        }
        if (percent <= 0) {
            return false;
        }
        long hash = salt;
        for (byte b : domain.getBytes(StandardCharsets.UTF_8)) {
            hash = hash * 31L + b;
        }
        int bucket = (int) (Math.floorMod(hash, 100L));
        return bucket < percent;
    }

    private static final class PolicyLookup {
        private DmarcPolicy policy;
        private String temperror;
        private boolean permerror;
    }
}

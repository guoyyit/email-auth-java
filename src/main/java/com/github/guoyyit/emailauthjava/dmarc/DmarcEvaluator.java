package com.github.guoyyit.emailauthjava.dmarc;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dns.DnsAnswer;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.spf.SpfResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * DMARC 策略求值（RFC 7489）。
 * 身份对齐（strict/relaxed）、组织域回退、子域策略继承、pct 采样，
 * 输出 none/quarantine/reject 处置及理由。
 */
public class DmarcEvaluator {

    private final DnsCache dnsCache;
    private final AuthProperties properties;
    private final OrganizationalDomain organizationalDomain;

    public DmarcEvaluator(DnsCache dnsCache, AuthProperties properties,
                          OrganizationalDomain organizationalDomain) {
        this.dnsCache = dnsCache;
        this.properties = properties;
        this.organizationalDomain = organizationalDomain;
    }

    public DmarcResult evaluate(String fromDomain, SpfResult spfResult, String spfAuthDomain,
                                DkimResult dkimResult) {
        return evaluate(dnsCache.beginSnapshot(), fromDomain, spfResult, spfAuthDomain, dkimResult);
    }

    /** 在给定 DNS 快照版本上求值，保证单次评估一致性。 */
    public DmarcResult evaluate(long snapshotVersion, String fromDomain, SpfResult spfResult,
                                String spfAuthDomain, DkimResult dkimResult) {
        if (fromDomain == null || fromDomain.isBlank()) {
            return new DmarcResult(DmarcPolicyAction.NONE, false, false, null,
                    "no valid From domain");
        }
        String normalizedFrom = normalize(fromDomain);

        DmarcLookup lookup = lookupPolicy(snapshotVersion, normalizedFrom);
        if (lookup.record == null) {
            return new DmarcResult(DmarcPolicyAction.NONE,
                    spfAligned(normalizedFrom, spfResult, spfAuthDomain, false),
                    dkimAligned(normalizedFrom, dkimResult, false),
                    null, lookup.reason);
        }

        DmarcRecord record = lookup.record;
        boolean strictSpf = "s".equals(record.getAlignmentSpf());
        boolean strictDkim = "s".equals(record.getAlignmentDkim());
        boolean spfAligned = spfAligned(normalizedFrom, spfResult, spfAuthDomain, strictSpf);
        boolean dkimAligned = dkimAligned(normalizedFrom, dkimResult, strictDkim);

        boolean isSubdomain = !normalizedFrom.equalsIgnoreCase(record.getDomain());
        DmarcPolicyAction action = isSubdomain ? record.getSubdomainPolicy() : record.getPolicy();

        if (spfAligned || dkimAligned) {
            return new DmarcResult(DmarcPolicyAction.NONE, spfAligned, dkimAligned,
                    record.getDomain(), "authenticated and aligned");
        }

        if (action == DmarcPolicyAction.NONE) {
            return new DmarcResult(DmarcPolicyAction.NONE, false, false,
                    record.getDomain(), "DMARC policy p=none, monitoring only");
        }

        boolean sampledIn = sampleIn(normalizedFrom, record.getPct());
        if (!sampledIn) {
            return new DmarcResult(DmarcPolicyAction.NONE, false, false,
                    record.getDomain(),
                    "failed alignment but not selected by pct=" + record.getPct());
        }

        String reason = "failed SPF and DKIM alignment; policy "
                + action.name().toLowerCase(Locale.ROOT)
                + (isSubdomain ? " (subdomain)" : "");
        return new DmarcResult(action, false, false, record.getDomain(), reason);
    }

    private boolean spfAligned(String fromDomain, SpfResult spfResult,
                               String spfAuthDomain, boolean strict) {
        if (spfResult == null || !spfResult.isPass() || spfAuthDomain == null) {
            return false;
        }
        return aligned(fromDomain, spfAuthDomain, strict);
    }

    private boolean dkimAligned(String fromDomain, DkimResult dkimResult, boolean strict) {
        if (dkimResult == null) {
            return false;
        }
        String authDomain = dkimResult.getAuthenticatedDomain();
        if (authDomain == null) {
            return false;
        }
        return aligned(fromDomain, authDomain, strict);
    }

    private boolean aligned(String fromDomain, String authenticatedDomain, boolean strict) {
        String from = normalize(fromDomain);
        String authenticated = normalize(authenticatedDomain);
        if (strict) {
            return from.equals(authenticated);
        }
        return organizationalDomain.of(from).equals(organizationalDomain.of(authenticated));
    }

    private boolean sampleIn(String fromDomain, int pct) {
        if (pct >= 100) {
            return true;
        }
        if (pct <= 0) {
            return false;
        }
        int bucket = Math.floorMod(fromDomain.hashCode(), 100);
        return bucket < pct;
    }

    private DmarcLookup lookupPolicy(long snapshotVersion, String fromDomain) {
        DnsAnswer direct = queryRecord(snapshotVersion, "_dmarc." + fromDomain);
        DmarcRecord directRecord = parseSingle(fromDomain, direct);
        if (directRecord != null) {
            return new DmarcLookup(directRecord, "policy found at sender domain");
        }
        if (direct.getStatus() == DnsStatus.TIMEOUT) {
            return new DmarcLookup(null, "temporary DNS error fetching DMARC policy");
        }
        if (direct.getStatus() == DnsStatus.MALFORMED) {
            return new DmarcLookup(null, "malformed DMARC record at sender domain");
        }

        String orgDomain = organizationalDomain.of(fromDomain);
        if (!orgDomain.equals(fromDomain)) {
            DnsAnswer org = queryRecord(snapshotVersion, "_dmarc." + orgDomain);
            DmarcRecord orgRecord = parseSingle(orgDomain, org);
            if (orgRecord != null) {
                return new DmarcLookup(orgRecord,
                        "policy inherited from organizational domain " + orgDomain);
            }
            if (org.getStatus() == DnsStatus.TIMEOUT) {
                return new DmarcLookup(null,
                        "temporary DNS error fetching organizational DMARC policy");
            }
            if (org.getStatus() == DnsStatus.MALFORMED) {
                return new DmarcLookup(null,
                        "malformed DMARC record at organizational domain");
            }
        }
        return new DmarcLookup(null, "no DMARC policy present");
    }

    private DnsAnswer queryRecord(long snapshotVersion, String name) {
        return dnsCache.queryAtVersion(snapshotVersion, name, RecordType.TXT);
    }

    private DmarcRecord parseSingle(String domain, DnsAnswer answer) {
        if (answer.getStatus() != DnsStatus.OK) {
            return null;
        }
        List<String> candidates = new ArrayList<>();
        for (var record : answer.getRecords()) {
            String text = record.getText();
            if (text != null && text.trim().toLowerCase(Locale.ROOT).startsWith("v=dmarc1")) {
                candidates.add(text);
            }
        }
        if (candidates.isEmpty()) {
            return null;
        }
        if (candidates.size() > 1) {
            return null;
        }
        if (candidates.get(0).length() > properties.getLimits().getMaxDnsResponseBytes()) {
            return null;
        }
        try {
            return DmarcRecord.parse(domain, candidates.get(0));
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private static String normalize(String domain) {
        String trimmed = domain.trim().toLowerCase(Locale.ROOT);
        while (trimmed.endsWith(".")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private record DmarcLookup(DmarcRecord record, String reason) {
    }
}

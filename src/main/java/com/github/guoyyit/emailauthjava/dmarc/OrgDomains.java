package com.github.guoyyit.emailauthjava.dmarc;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 组织域（组织名/注册域）判定：基于一个小型内置公共后缀集合，
 * 覆盖常见多级后缀（如 co.uk）。无需联网，可按需扩展。
 */
final class OrgDomains {
    private static final Set<String> MULTI_LABEL_SUFFIXES = Set.of(
            "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk", "ltd.uk", "plc.uk",
            "co.jp", "or.jp", "ne.jp", "go.jp", "ac.jp",
            "com.cn", "org.cn", "net.cn", "gov.cn", "edu.cn",
            "com.au", "org.au", "net.au", "edu.au", "gov.au",
            "co.nz", "org.nz", "govt.nz",
            "com.br", "org.br", "net.br",
            "co.in", "org.in", "net.in", "gov.in", "firm.in",
            "com.sg", "org.sg", "gov.sg", "edu.sg",
            "co.za", "org.za",
            "com.mx", "org.mx",
            "co.kr", "or.kr", "go.kr",
            "com.tw", "org.tw",
            "com.hk", "org.hk"
    );

    private OrgDomains() {
    }

    static String organizationalDomain(String domain) {
        if (domain == null || domain.isBlank()) {
            return null;
        }
        String normalized = domain.trim().toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        List<String> labels = List.of(normalized.split("\\."));
        if (labels.size() <= 2) {
            return normalized;
        }
        String lastTwo = String.join(".",
                labels.subList(labels.size() - 2, labels.size()));
        String lastThree = String.join(".",
                labels.subList(labels.size() - 3, labels.size()));
        if (MULTI_LABEL_SUFFIXES.contains(lastTwo) && labels.size() >= 3) {
            return lastThree;
        }
        return lastTwo;
    }

    static boolean isAligned(String authenticatedDomain, String headerFromDomain, boolean strict) {
        if (authenticatedDomain == null || headerFromDomain == null) {
            return false;
        }
        String auth = authenticatedDomain.toLowerCase(Locale.ROOT);
        String from = headerFromDomain.toLowerCase(Locale.ROOT);
        if (strict) {
            return auth.equals(from);
        }
        String authOrg = organizationalDomain(auth);
        String fromOrg = organizationalDomain(from);
        return authOrg != null && authOrg.equals(fromOrg);
    }
}

package com.github.guoyyit.emailauthjava.dmarc;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 解析 _dmarc 下的 DMARC TXT 策略记录（RFC 7489）。
 */
final class DmarcPolicyParser {
    private DmarcPolicyParser() {
    }

    static DmarcPolicy parse(String domain, String txtRecord) {
        Map<String, String> tags = parseTags(txtRecord);
        DmarcPolicy policy = new DmarcPolicy();
        policy.setDomain(domain);
        policy.setFound(true);
        String version = tags.get("v");
        if (version != null && !"DMARC1".equals(version.trim().toUpperCase(Locale.ROOT))) {
            throw new IllegalArgumentException("unsupported DMARC version: " + version);
        }
        String requestedPolicy = tags.getOrDefault("p", "none").trim()
                .toLowerCase(Locale.ROOT);
        policy.setPolicy(normalizePolicy(requestedPolicy));
        String subdomainPolicy = tags.get("sp");
        if (subdomainPolicy != null) {
            policy.setSubdomainPolicy(
                    normalizePolicy(subdomainPolicy.trim().toLowerCase(Locale.ROOT)));
        }
        String percent = tags.get("pct");
        policy.setPercent(percent == null ? 100 : parsePercent(percent));
        policy.setAlignmentSpf(normalizeAlignment(tags.get("aspf"), "r"));
        policy.setAlignmentDkim(normalizeAlignment(tags.get("adkim"), "r"));
        String rua = tags.get("rua");
        policy.setReportEmail(rua == null ? null : rua.trim());
        return policy;
    }

    private static Map<String, String> parseTags(String value) {
        Map<String, String> tags = new LinkedHashMap<>();
        String[] parts = value.split(";");
        for (String part : parts) {
            int eq = part.indexOf('=');
            if (eq < 0) {
                continue;
            }
            tags.putIfAbsent(part.substring(0, eq).trim().toLowerCase(Locale.ROOT),
                    part.substring(eq + 1).trim());
        }
        return tags;
    }

    private static String normalizePolicy(String value) {
        return switch (value) {
            case "none", "quarantine", "reject" -> value;
            default -> throw new IllegalArgumentException("invalid p= policy: " + value);
        };
    }

    private static int parsePercent(String value) {
        try {
            int percent = Integer.parseInt(value.trim());
            if (percent < 0 || percent > 100) {
                throw new IllegalArgumentException("pct out of range: " + value);
            }
            return percent;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid pct: " + value);
        }
    }

    private static String normalizeAlignment(String value, String fallback) {
        if (value == null) {
            return fallback;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "r", "s" -> normalized;
            default -> fallback;
        };
    }
}

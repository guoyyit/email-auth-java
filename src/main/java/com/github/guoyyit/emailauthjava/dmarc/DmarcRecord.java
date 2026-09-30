package com.github.guoyyit.emailauthjava.dmarc;

import java.util.List;

/**
 * 解析后的 _dmarc 策略记录（v=DMARC1）。
 */
public final class DmarcRecord {
    private final String domain;
    private final DmarcPolicyAction policy;
    private final DmarcPolicyAction subdomainPolicy;
    private final int pct;
    private final List<String> rua;
    private final String alignmentSpf;
    private final String alignmentDkim;

    public DmarcRecord(String domain, DmarcPolicyAction policy, DmarcPolicyAction subdomainPolicy,
                       int pct, List<String> rua, String alignmentSpf, String alignmentDkim) {
        this.domain = domain;
        this.policy = policy;
        this.subdomainPolicy = subdomainPolicy;
        this.pct = pct;
        this.rua = rua;
        this.alignmentSpf = alignmentSpf;
        this.alignmentDkim = alignmentDkim;
    }

    public String getDomain() { return domain; }
    public DmarcPolicyAction getPolicy() { return policy; }
    public DmarcPolicyAction getSubdomainPolicy() { return subdomainPolicy; }
    public int getPct() { return pct; }
    public List<String> getRua() { return rua; }
    public String getAlignmentSpf() { return alignmentSpf; }
    public String getAlignmentDkim() { return alignmentDkim; }

    /**
     * 解析单条 DMARC TXT 记录。格式错误抛 {@link IllegalArgumentException}。
     */
    public static DmarcRecord parse(String domain, String text) {
        if (text == null) {
            throw new IllegalArgumentException("null DMARC record");
        }
        String[] parts = text.trim().split("\\s*;\\s*", -1);
        String first = parts[0].replaceAll("\\s+", "").toLowerCase(java.util.Locale.ROOT);
        if (!first.equals("v=dmarc1")) {
            throw new IllegalArgumentException("not a DMARC record");
        }
        java.util.Map<String, String> tags = new java.util.LinkedHashMap<>();
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i];
            if (part.isBlank()) {
                continue;
            }
            int eq = part.indexOf('=');
            if (eq <= 0) {
                throw new IllegalArgumentException("malformed DMARC tag: " + part);
            }
            String name = part.substring(0, eq).trim().toLowerCase(java.util.Locale.ROOT);
            String value = part.substring(eq + 1).trim();
            if (tags.put(name, value) != null) {
                throw new IllegalArgumentException("duplicate DMARC tag: " + name);
            }
        }

        DmarcPolicyAction policy = parseAction(tags.get("p"));
        if (policy == null) {
            throw new IllegalArgumentException("missing or invalid p= tag");
        }
        String sub = tags.get("sp");
        DmarcPolicyAction subdomainPolicy = sub == null ? policy : parseAction(sub);
        if (sub != null && subdomainPolicy == null) {
            throw new IllegalArgumentException("invalid sp= tag");
        }
        int pct = 100;
        if (tags.containsKey("pct")) {
            try {
                pct = Integer.parseInt(tags.get("pct").trim());
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("invalid pct= tag");
            }
            if (pct < 0 || pct > 100) {
                throw new IllegalArgumentException("pct= out of range");
            }
        }
        List<String> rua = new java.util.ArrayList<>();
        String ruaTag = tags.get("rua");
        if (ruaTag != null && !ruaTag.isBlank()) {
            for (String uri : ruaTag.split(",")) {
                String trimmed = uri.trim();
                if (!trimmed.isEmpty()) {
                    rua.add(trimmed);
                }
            }
        }
        String aspf = tags.getOrDefault("aspf", "r").toLowerCase(java.util.Locale.ROOT);
        String adkim = tags.getOrDefault("adkim", "r").toLowerCase(java.util.Locale.ROOT);
        if (!aspf.equals("r") && !aspf.equals("s")) {
            throw new IllegalArgumentException("invalid aspf= tag");
        }
        if (!adkim.equals("r") && !adkim.equals("s")) {
            throw new IllegalArgumentException("invalid adkim= tag");
        }
        return new DmarcRecord(domain, policy, subdomainPolicy, pct,
                List.copyOf(rua), aspf, adkim);
    }

    private static DmarcPolicyAction parseAction(String value) {
        if (value == null) {
            return null;
        }
        return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "none" -> DmarcPolicyAction.NONE;
            case "quarantine" -> DmarcPolicyAction.QUARANTINE;
            case "reject" -> DmarcPolicyAction.REJECT;
            default -> null;
        };
    }
}

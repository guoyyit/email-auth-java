package com.github.guoyyit.emailauthjava.dmarc;

import com.github.guoyyit.emailauthjava.config.AuthProperties;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 组织域（Organization Domain）判定：默认最后两个标签，
 * 可通过 {@code email-auth.dmarc.private-suffixes} 扩展多标签私有后缀。
 */
public final class OrganizationalDomain {

    private final Set<String> privateSuffixes;

    public OrganizationalDomain(AuthProperties properties) {
        this.privateSuffixes = new HashSet<>();
        List<String> configured = properties.getDmarc().getPrivateSuffixes();
        if (configured != null) {
            for (String suffix : configured) {
                if (suffix != null && !suffix.isBlank()) {
                    privateSuffixes.add(normalize(suffix));
                }
            }
        }
    }

    public String of(String domain) {
        if (domain == null) {
            return null;
        }
        String normalized = normalize(domain);
        String[] labels = normalized.split("\\.", -1);
        if (labels.length <= 2) {
            return normalized;
        }
        for (int suffixLabels = Math.min(labels.length - 1, 6); suffixLabels >= 2; suffixLabels--) {
            String suffix = joinLabels(labels, labels.length - suffixLabels);
            if (privateSuffixes.contains(suffix)) {
                int orgStart = labels.length - suffixLabels - 1;
                if (orgStart < 0) {
                    return normalized;
                }
                return joinLabels(labels, orgStart);
            }
        }
        return labels[labels.length - 2] + "." + labels[labels.length - 1];
    }

    private static String joinLabels(String[] labels, int from) {
        StringBuilder builder = new StringBuilder();
        for (int i = from; i < labels.length; i++) {
            if (builder.length() > 0) {
                builder.append('.');
            }
            builder.append(labels[i]);
        }
        return builder.toString();
    }

    private static String normalize(String domain) {
        String trimmed = domain.trim().toLowerCase(Locale.ROOT);
        while (trimmed.endsWith(".")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }
}

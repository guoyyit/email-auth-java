package com.github.guoyyit.emailauthjava.dkim;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * 解析 DKIM-Signature 头的 tag-list（RFC 6376 3.2）。
 * 解析失败抛出 {@link DkimFormatException}，由求值器映射为 permerror。
 */
final class DkimSignatureParser {
    private DkimSignatureParser() {
    }

    static DkimSignature parse(String unfoldedValue) {
        DkimSignature signature = new DkimSignature();
        java.util.Map<String, String> tags = parseTags(unfoldedValue);

        signature.setVersion(tags.get("v"));
        signature.setAlgorithm(required(tags, "a"));
        signature.setDomain(normalizeDomain(required(tags, "d")));
        signature.setSelector(normalizeDomain(required(tags, "s")));
        signature.setSignedHeaders(parseHeaderList(required(tags, "h")));
        signature.setBodyHash(decodeBase64(required(tags, "bh"), "bh"));
        signature.setSignatureData(decodeBase64(required(tags, "b"), "b"));
        signature.setCanonicalization(tags.getOrDefault("c", "simple/simple"));
        String bodyLength = tags.get("l");
        if (bodyLength != null) {
            try {
                signature.setBodyLength(Long.parseLong(bodyLength.trim()));
            } catch (NumberFormatException e) {
                throw new DkimFormatException("invalid l= tag: " + bodyLength);
            }
        }
        String expiration = tags.get("x");
        if (expiration != null) {
            try {
                signature.setExpiration(Long.parseLong(expiration.trim()));
            } catch (NumberFormatException e) {
                throw new DkimFormatException("invalid x= tag: " + expiration);
            }
        }
        validate(signature);
        return signature;
    }

    private static java.util.Map<String, String> parseTags(String value) {
        java.util.LinkedHashMap<String, String> tags = new java.util.LinkedHashMap<>();
        boolean inB = false;
        int index = 0;
        while (index < value.length()) {
            int eq = value.indexOf('=', index);
            if (eq < 0) {
                throw new DkimFormatException("tag missing '=' near: "
                        + safeSnippet(value, index));
            }
            String key = value.substring(index, eq).trim().toLowerCase(Locale.ROOT);
            if (key.isEmpty() || key.indexOf(' ') >= 0 || key.indexOf('\t') >= 0) {
                throw new DkimFormatException("illegal tag name: '" + key + "'");
            }
            int valueStart = eq + 1;
            int valueEnd;
            if ("b".equals(key)) {
                int semicolon = value.indexOf(';', valueStart);
                valueEnd = semicolon < 0 ? value.length() : semicolon;
                inB = false;
            } else {
                valueEnd = value.indexOf(';', valueStart);
                if (valueEnd < 0) {
                    valueEnd = value.length();
                }
            }
            String tagValue = value.substring(valueStart, valueEnd).trim();
            if (tags.put(key, tagValue) != null && !"z".equals(key)) {
                throw new DkimFormatException("duplicate tag: " + key);
            }
            index = valueEnd + 1;
            if (index <= valueStart) {
                break;
            }
        }
        if (inB) {
            throw new DkimFormatException("unterminated b= tag");
        }
        return tags;
    }

    private static List<String> parseHeaderList(String raw) {
        List<String> headers = new ArrayList<>();
        for (String name : raw.split(":")) {
            String trimmed = name.trim().toLowerCase(Locale.ROOT);
            if (!trimmed.isEmpty()) {
                headers.add(trimmed);
            }
        }
        return headers;
    }

    private static byte[] decodeBase64(String raw, String tag) {
        String compact = raw.replaceAll("\\s+", "");
        try {
            return Base64.getDecoder().decode(compact);
        } catch (IllegalArgumentException e) {
            throw new DkimFormatException("invalid base64 in " + tag + " tag");
        }
    }

    private static String required(java.util.Map<String, String> tags, String key) {
        String value = tags.get(key);
        if (value == null || value.isEmpty()) {
            throw new DkimFormatException("missing required tag " + key);
        }
        return value;
    }

    private static String normalizeDomain(String value) {
        String domain = value.trim().toLowerCase(Locale.ROOT);
        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }
        if (domain.isEmpty()) {
            throw new DkimFormatException("empty domain in tag");
        }
        return domain;
    }

    private static void validate(DkimSignature signature) {
        if (signature.getVersion() != null && !"1".equals(signature.getVersion().trim())) {
            throw new DkimFormatException("unsupported DKIM version " + signature.getVersion());
        }
        String algorithm = signature.getAlgorithm().toLowerCase(Locale.ROOT);
        if (!algorithm.equals("rsa-sha256") && !algorithm.equals("rsa-sha1")
                && !algorithm.equals("ed25519-sha256")) {
            throw new DkimFormatException("unsupported algorithm " + signature.getAlgorithm());
        }
        String canonicalization = signature.getCanonicalization().toLowerCase(Locale.ROOT);
        String[] parts = canonicalization.split("/");
        if (parts.length < 1 || parts.length > 2
                || !isCanonAlgo(parts[0])
                || (parts.length == 2 && !isCanonAlgo(parts[1]))) {
            throw new DkimFormatException("unsupported canonicalization " + canonicalization);
        }
        if (signature.getBodyLength() != null && signature.getBodyLength() < 0) {
            throw new DkimFormatException("negative body length");
        }
        if (signature.getSignedHeaders().isEmpty()) {
            throw new DkimFormatException("empty h= tag");
        }
    }

    private static boolean isCanonAlgo(String value) {
        return "simple".equals(value) || "relaxed".equals(value);
    }

    private static String safeSnippet(String value, int index) {
        int end = Math.min(value.length(), index + 20);
        return value.substring(index, end);
    }
}

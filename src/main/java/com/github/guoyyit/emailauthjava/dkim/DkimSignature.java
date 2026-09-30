package com.github.guoyyit.emailauthjava.dkim;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 解析后的 DKIM-Signature 标签集合（RFC 6376 §3.5）。
 */
public final class DkimSignature {

    final String version;
    final String algorithm;
    final String domain;
    final String selector;
    final List<String> signedHeaders;
    final byte[] bodyHash;
    final byte[] signatureData;
    final Canonicalizer.HeaderMode headerMode;
    final Canonicalizer.BodyMode bodyMode;
    final Integer bodyLength;
    final Long created;
    final Long expires;
    final String copiedHeaders;
    final String query;
    final String rawTagBlock;

    private DkimSignature(Builder builder) {
        this.version = builder.tags.get("v");
        this.algorithm = builder.tags.get("a");
        this.domain = stripDot(builder.tags.get("d"));
        this.selector = builder.tags.get("s");
        String headerTag = builder.tags.get("h");
        this.signedHeaders = headerTag == null ? List.of()
                : splitHeaderList(headerTag);
        this.bodyHash = decodeBase64(builder.tags.get("bh"));
        this.signatureData = decodeBase64(builder.tags.get("b"));
        String canonicalization = builder.tags.getOrDefault("c", "simple/simple");
        String[] modes = canonicalization.split("/", -1);
        this.headerMode = modes[0].trim().equalsIgnoreCase("relaxed")
                ? Canonicalizer.HeaderMode.RELAXED : Canonicalizer.HeaderMode.SIMPLE;
        this.bodyMode = modes.length > 1 && modes[1].trim().equalsIgnoreCase("relaxed")
                ? Canonicalizer.BodyMode.RELAXED : Canonicalizer.BodyMode.SIMPLE;
        String length = builder.tags.get("l");
        this.bodyLength = length == null ? null : parseLength(length);
        this.created = parseLongTag(builder.tags.get("t"));
        this.expires = parseLongTag(builder.tags.get("x"));
        this.copiedHeaders = builder.tags.get("z");
        this.query = builder.tags.get("q");
        this.rawTagBlock = builder.rawTagBlock;
    }

    public static DkimSignature parse(String unfoldedHeaderValue) {
        Builder builder = new Builder();
        String value = unfoldedHeaderValue == null ? "" : unfoldedHeaderValue;
        StringBuilder rawForSigning = new StringBuilder(value.length() + 16);
        rawForSigning.append("DKIM-Signature: ");
        Map<String, String> seen = new LinkedHashMap<>();
        String[] parts = value.split(";", -1);
        for (String part : parts) {
            int eq = part.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String tag = part.substring(0, eq).trim().toLowerCase(java.util.Locale.ROOT);
            String tagValue = part.substring(eq + 1);
            if (tag.equals("b")) {
                rawForSigning.append(part, 0, eq + 1);
                tagValue = tagValue.trim();
                if (seen.put(tag, tagValue) != null) {
                    throw new DkimSignatureException("duplicate tag: " + tag);
                }
                continue;
            } else {
                rawForSigning.append(part);
                tagValue = tagValue.replaceAll("\\s+", "").trim();
            }
            rawForSigning.append(';');
            if (seen.put(tag, tagValue) != null) {
                throw new DkimSignatureException("duplicate tag: " + tag);
            }
        }
        if (!seen.containsKey("b")) {
            throw new DkimSignatureException("missing b= tag");
        }
        builder.rawTagBlock = rawForSigning.toString();
        builder.tags = seen;
        DkimSignature signature = new DkimSignature(builder);
        signature.validate();
        return signature;
    }

    private void validate() {
        if (algorithm == null || domain == null || selector == null
                || signedHeaders.isEmpty() || bodyHash == null || signatureData == null) {
            throw new DkimSignatureException("missing required DKIM tag");
        }
        if (version != null && !version.equals("1")) {
            throw new DkimSignatureException("unsupported DKIM version: " + version);
        }
        if (!(algorithm.startsWith("rsa-sha") || algorithm.equals("ed25519-sha256"))) {
            throw new DkimSignatureException("unsupported algorithm: " + algorithm);
        }
        if (bodyLength != null && bodyLength < 0) {
            throw new DkimSignatureException("negative body length");
        }
        if (expires != null && created != null && expires < created) {
            throw new DkimSignatureException("expiration precedes creation");
        }
        if (signatureData == null || signatureData.length == 0) {
            throw new DkimSignatureException("empty signature b= tag");
        }
        boolean fromSigned = false;
        for (String header : signedHeaders) {
            if (header.equalsIgnoreCase("from")) {
                fromSigned = true;
                break;
            }
        }
        if (!fromSigned) {
            throw new DkimSignatureException("From header not covered by h= tag");
        }
    }

    private static List<String> splitHeaderList(String headerTag) {
        String[] tokens = headerTag.split(":");
        List<String> headers = new ArrayList<>();
        for (String token : tokens) {
            String name = token.trim().toLowerCase(java.util.Locale.ROOT);
            if (!name.isEmpty()) {
                headers.add(name);
            }
        }
        return List.copyOf(headers);
    }

    private static byte[] decodeBase64(String value) {
        if (value == null) {
            return null;
        }
        try {
            return Base64.getDecoder().decode(value.replaceAll("\\s+", ""));
        } catch (IllegalArgumentException ex) {
            throw new DkimSignatureException("invalid base64 tag value");
        }
    }

    private static Integer parseLength(String value) {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException ex) {
            throw new DkimSignatureException("invalid l= length");
        }
    }

    private static Long parseLongTag(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException ex) {
            throw new DkimSignatureException("invalid timestamp tag");
        }
    }

    private static String stripDot(String domain) {
        if (domain == null) {
            return null;
        }
        String trimmed = domain.trim().toLowerCase(java.util.Locale.ROOT);
        while (trimmed.endsWith(".")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private static final class Builder {
        private Map<String, String> tags = Map.of();
        private String rawTagBlock = "";
    }
}

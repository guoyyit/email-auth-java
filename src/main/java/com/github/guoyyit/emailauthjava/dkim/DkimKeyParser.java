package com.github.guoyyit.emailauthjava.dkim;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 解析 DKIM 公钥 TXT 记录（RFC 6376 3.6.1）。
 * 公钥以 X.509 SubjectPublicKeyInfo 的 Base64 形式放入 p= 标签。
 */
final class DkimKeyParser {
    private DkimKeyParser() {
    }

    static DkimPublicKey parse(String txtRecord) {
        Map<String, String> tags = parseTags(txtRecord);
        String version = tags.get("v");
        if (version != null && !"DKIM1".equals(version.trim())) {
            throw new DkimFormatException("unsupported key record version " + version);
        }
        String keyType = tags.getOrDefault("k", "rsa").trim().toLowerCase(Locale.ROOT);
        String encoded = tags.get("p");
        if (encoded == null) {
            throw new DkimFormatException("missing p= in key record");
        }
        if (encoded.trim().isEmpty()) {
            return new DkimPublicKey(keyType, null, true);
        }
        try {
            byte[] der = Base64.getDecoder().decode(encoded.replaceAll("\\s+", ""));
            KeyFactory factory = KeyFactory.getInstance(keyType.equals("rsa") ? "RSA" : "Ed25519");
            PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(der));
            return new DkimPublicKey(keyType, publicKey, false);
        } catch (IllegalArgumentException e) {
            throw new DkimFormatException("invalid base64 in p= tag");
        } catch (Exception e) {
            throw new DkimFormatException("unusable public key: " + e.getMessage());
        }
    }

    private static Map<String, String> parseTags(String value) {
        Map<String, String> tags = new LinkedHashMap<>();
        String[] parts = value.split(";");
        for (String part : parts) {
            int eq = part.indexOf('=');
            if (eq < 0) {
                if (part.isBlank()) {
                    continue;
                }
                throw new DkimFormatException("key tag missing '=': " + part.trim());
            }
            String key = part.substring(0, eq).trim().toLowerCase(Locale.ROOT);
            String tagValue = part.substring(eq + 1).trim();
            tags.put(key, tagValue);
        }
        return tags;
    }
}

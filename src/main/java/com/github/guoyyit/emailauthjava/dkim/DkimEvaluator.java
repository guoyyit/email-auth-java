package com.github.guoyyit.emailauthjava.dkim;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dns.DnsAnswer;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.dns.DnsRecord;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.mail.Header;
import com.github.guoyyit.emailauthjava.mail.ParsedMail;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * DKIM 签名验证（RFC 6376，兼顾 RFC 8301/8463）。
 * 多签名逐一验证；simple/relaxed 规范化；支持 l= 正文长度截断；
 * 过期签名（x=）与未知选择器给出明确分类。
 */
public class DkimEvaluator {

    private final DnsCache dnsCache;
    private final AuthProperties properties;

    public DkimEvaluator(DnsCache dnsCache, AuthProperties properties) {
        this.dnsCache = dnsCache;
        this.properties = properties;
    }

    public DkimResult verify(ParsedMail mail) {
        return verify(dnsCache.beginSnapshot(), mail);
    }

    /** 在给定 DNS 快照版本上验证，保证单次评估一致性。 */
    public DkimResult verify(long snapshotVersion, ParsedMail mail) {
        List<Header> signatureHeaders = mail.getHeaders("DKIM-Signature");
        if (signatureHeaders.isEmpty()) {
            return new DkimResult(DkimStatus.NONE, List.of());
        }
        int limit = Math.min(signatureHeaders.size(), properties.getDkim().getMaxSignatures());
        List<SignatureOutcome> outcomes = new ArrayList<>();
        for (int i = 0; i < limit; i++) {
            outcomes.add(verifyOne(snapshotVersion, mail, signatureHeaders.get(i)));
        }
        return DkimResult.combine(outcomes);
    }

    private SignatureOutcome verifyOne(long snapshotVersion, ParsedMail mail, Header header) {
        DkimSignature signature;
        try {
            signature = DkimSignature.parse(header.getUnfoldedValue());
        } catch (DkimSignatureException ex) {
            return new SignatureOutcome(null, null, DkimStatus.PERMERROR, ex.getMessage());
        }

        long now = System.currentTimeMillis() / 1000L;
        long skew = properties.getDkim().getExpirySkewSeconds();
        if (signature.expires != null && now - skew > signature.expires) {
            return new SignatureOutcome(signature.selector, signature.domain,
                    DkimStatus.FAIL, "signature expired at " + signature.expires);
        }

        if (signature.signedHeaders.size() > properties.getLimits().getMaxSignedHeaders()) {
            return new SignatureOutcome(signature.selector, signature.domain,
                    DkimStatus.PERMERROR, "too many signed headers");
        }

        PublicKeyLookup keyLookup = fetchPublicKey(snapshotVersion, signature);
        if (keyLookup.status != DnsStatus.OK || keyLookup.publicKey == null) {
            DkimStatus mapped = mapKeyStatus(keyLookup.status, keyLookup.reason);
            return new SignatureOutcome(signature.selector, signature.domain,
                    mapped, keyLookup.reason);
        }

        try {
            byte[] canonicalBody = Canonicalizer.canonicalizeBody(
                    mail.getRawBody(), signature.bodyMode, signature.bodyLength);
            byte[] actualBodyHash = digestFor(signature.algorithm).digest(canonicalBody);
            if (!MessageDigest.isEqual(actualBodyHash, signature.bodyHash)) {
                return new SignatureOutcome(signature.selector, signature.domain,
                        DkimStatus.FAIL, "body hash mismatch");
            }

            byte[] signedData = buildSignedData(mail, signature);
            if (!verifyCryptographic(signature, keyLookup.publicKey, signedData)) {
                return new SignatureOutcome(signature.selector, signature.domain,
                        DkimStatus.FAIL, "signature verification failed");
            }
            return new SignatureOutcome(signature.selector, signature.domain,
                    DkimStatus.PASS, "ok");
        } catch (DkimSignatureException ex) {
            return new SignatureOutcome(signature.selector, signature.domain,
                    DkimStatus.PERMERROR, ex.getMessage());
        } catch (Exception ex) {
            return new SignatureOutcome(signature.selector, signature.domain,
                    DkimStatus.TEMPERROR, "verification error: " + ex.getMessage());
        }
    }

    private DkimStatus mapKeyStatus(DnsStatus status, String reason) {
        return switch (status) {
            case TIMEOUT -> DkimStatus.TEMPERROR;
            case NXDOMAIN, NO_DATA -> DkimStatus.FAIL;
            default -> DkimStatus.PERMERROR;
        };
    }

    private PublicKeyLookup fetchPublicKey(long snapshotVersion, DkimSignature signature) {
        String name = signature.selector + "._domainkey." + signature.domain;
        DnsAnswer answer;
        try {
            answer = dnsCache.queryAtVersion(snapshotVersion, name, RecordType.TXT);
        } catch (RuntimeException ex) {
            return new PublicKeyLookup(null, DnsStatus.TIMEOUT, "key lookup timeout");
        }
        if (answer.getStatus() == DnsStatus.TIMEOUT) {
            return new PublicKeyLookup(null, DnsStatus.TIMEOUT, "key lookup timeout");
        }
        if (answer.getStatus() == DnsStatus.NXDOMAIN || answer.getStatus() == DnsStatus.NO_DATA) {
            return new PublicKeyLookup(null, answer.getStatus(),
                    "unknown selector " + signature.selector);
        }
        if (answer.getStatus() == DnsStatus.MALFORMED) {
            return new PublicKeyLookup(null, DnsStatus.MALFORMED, "malformed key record");
        }
        String joined = joinTxt(answer);
        if (joined.length() > properties.getLimits().getMaxDnsResponseBytes()) {
            return new PublicKeyLookup(null, DnsStatus.MALFORMED, "key record too large");
        }
        try {
            Map<String, String> tags = parseTagList(joined);
            String keyType = tags.getOrDefault("k", "rsa").toLowerCase(java.util.Locale.ROOT);
            String revocation = tags.get("p");
            if (revocation == null) {
                return new PublicKeyLookup(null, DnsStatus.MALFORMED, "missing p= tag");
            }
            if (revocation.isEmpty()) {
                return new PublicKeyLookup(null, DnsStatus.MALFORMED, "revoked public key");
            }
            String domainTag = tags.get("d");
            if (domainTag != null && !domainTag.isEmpty()
                    && !domainTag.equalsIgnoreCase(signature.domain)) {
                return new PublicKeyLookup(null, DnsStatus.MALFORMED, "key domain mismatch");
            }
            String expectedType = signature.algorithm.startsWith("rsa") ? "rsa" : "ed25519";
            if (!keyType.equals(expectedType)) {
                return new PublicKeyLookup(null, DnsStatus.MALFORMED,
                        "key type " + keyType + " does not match signature algorithm");
            }
            PublicKey publicKey = decodePublicKey(keyType, revocation);
            return new PublicKeyLookup(publicKey, DnsStatus.OK, "ok");
        } catch (IllegalArgumentException ex) {
            return new PublicKeyLookup(null, DnsStatus.MALFORMED,
                    "malformed key record: " + ex.getMessage());
        }
    }

    private String joinTxt(DnsAnswer answer) {
        StringBuilder builder = new StringBuilder();
        for (DnsRecord record : answer.getRecords()) {
            if (record.getText() != null) {
                builder.append(record.getText());
            }
        }
        return builder.toString();
    }

    private PublicKey decodePublicKey(String keyType, String base64Value) {
        try {
            byte[] der = Base64.getDecoder().decode(base64Value.replaceAll("\\s+", ""));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            return switch (keyType) {
                case "rsa" -> KeyFactory.getInstance("RSA").generatePublic(spec);
                case "ed25519" -> KeyFactory.getInstance("Ed25519").generatePublic(spec);
                default -> throw new IllegalArgumentException("unsupported key type " + keyType);
            };
        } catch (Exception ex) {
            throw new IllegalArgumentException("invalid public key: " + ex.getMessage());
        }
    }

    private byte[] buildSignedData(ParsedMail mail, DkimSignature signature) {
        Map<String, List<Header>> available = new LinkedHashMap<>();
        for (Header header : mail.getHeaders()) {
            available.computeIfAbsent(header.getName(), key -> new ArrayList<>()).add(header);
        }
        Map<String, Integer> cursor = new LinkedHashMap<>();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String signedName : signature.signedHeaders) {
            String key = signedName.toLowerCase(java.util.Locale.ROOT);
            List<Header> candidates = available.get(key);
            if (candidates == null || candidates.isEmpty()) {
                out.writeBytes(Canonicalizer.canonicalizeHeader(signedName, "",
                        signature.headerMode));
                continue;
            }
            int index = cursor.getOrDefault(key, 0);
            if (index >= candidates.size()) {
                out.writeBytes(Canonicalizer.canonicalizeHeader(signedName, "",
                        signature.headerMode));
                continue;
            }
            Header chosen = candidates.get(index);
            cursor.put(key, index + 1);
            byte[] canonical = Canonicalizer.canonicalizeHeader(
                    chosen.getRawName(), chosen.getUnfoldedValue(), signature.headerMode);
            out.writeBytes(canonical);
        }
        String rawTagBlock = signature.rawTagBlock;
        String headerValue = rawTagBlock;
        int colon = rawTagBlock.indexOf(':');
        if (colon > 0) {
            headerValue = rawTagBlock.substring(colon + 1);
        }
        out.writeBytes(Canonicalizer.canonicalizeHeader(
                "DKIM-Signature", headerValue, signature.headerMode));
        return out.toByteArray();
    }

    private boolean verifyCryptographic(DkimSignature signature, PublicKey publicKey,
                                        byte[] signedData) throws Exception {
        if (signature.algorithm.startsWith("rsa-")) {
            String jcaName = switch (signature.algorithm) {
                case "rsa-sha256" -> "SHA256withRSA";
                case "rsa-sha1" -> "SHA1withRSA";
                default -> throw new DkimSignatureException(
                        "unsupported RSA algorithm " + signature.algorithm);
            };
            Signature verifier = Signature.getInstance(jcaName);
            verifier.initVerify(publicKey);
            verifier.update(signedData);
            return verifier.verify(signature.signatureData);
        }
        if (signature.algorithm.equals("ed25519-sha256")) {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(signedData);
            return verifier.verify(signature.signatureData);
        }
        throw new DkimSignatureException("unsupported algorithm " + signature.algorithm);
    }

    private MessageDigest digestFor(String algorithm) throws Exception {
        if (algorithm == null) {
            throw new DkimSignatureException("missing algorithm");
        }
        return switch (algorithm) {
            case "rsa-sha256", "ed25519-sha256" -> MessageDigest.getInstance("SHA-256");
            case "rsa-sha1" -> MessageDigest.getInstance("SHA-1");
            default -> throw new DkimSignatureException("unsupported digest in " + algorithm);
        };
    }

    private static Map<String, String> parseTagList(String text) {
        Map<String, String> tags = new LinkedHashMap<>();
        for (String part : text.split(";", -1)) {
            int eq = part.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = part.substring(0, eq).trim().toLowerCase(java.util.Locale.ROOT);
            String value = part.substring(eq + 1).trim();
            tags.put(name, value);
        }
        return tags;
    }

    private record PublicKeyLookup(PublicKey publicKey, DnsStatus status, String reason) {
    }
}

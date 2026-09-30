package com.github.guoyyit.emailauthjava.dkim;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dns.DnsResolver;
import com.github.guoyyit.emailauthjava.dns.DnsResult;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.error.AuthError;
import com.github.guoyyit.emailauthjava.error.ResourceLimitException;
import com.github.guoyyit.emailauthjava.message.RawMessage;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

@Component
public class DkimEvaluator {
    private final DnsResolver dnsResolver;
    private final AuthProperties properties;

    public DkimEvaluator(DnsResolver dnsResolver, AuthProperties properties) {
        this.dnsResolver = dnsResolver;
        this.properties = properties;
    }

    public List<DkimResult> evaluate(RawMessage message) {
        return evaluate(message, dnsResolver);
    }

    public List<DkimResult> evaluate(RawMessage message, DnsResolver resolver) {
        List<RawMessage.Header> signatureHeaders = message.getHeaders("dkim-signature");
        if (signatureHeaders.isEmpty()) {
            return List.of(new DkimResult(DkimStatus.NONE, null, null,
                    "no DKIM-Signature header"));
        }
        if (signatureHeaders.size() > properties.getLimits().getMaxSignatures()) {
            throw new ResourceLimitException(AuthError.TOO_MANY_SIGNATURES,
                    "DKIM-Signature count exceeds " + properties.getLimits().getMaxSignatures());
        }
        List<DkimResult> results = new ArrayList<>();
        for (RawMessage.Header header : signatureHeaders) {
            results.add(verifyOne(header, message, resolver));
        }
        return results;
    }

    private DkimResult verifyOne(RawMessage.Header signatureHeader, RawMessage message,
                                 DnsResolver resolver) {
        DkimSignature signature;
        try {
            signature = DkimSignatureParser.parse(signatureHeader.getUnfoldedValue());
        } catch (DkimFormatException e) {
            return new DkimResult(DkimStatus.PERMERROR, null, null,
                    "malformed signature: " + e.getMessage());
        }
        if (signature.getExpiration() != null
                && signature.getExpiration() * 1000L < System.currentTimeMillis()) {
            return new DkimResult(DkimStatus.PERMERROR, signature.getSelector(),
                    signature.getDomain(), "signature expired");
        }
        Canonicalization canon = Canonicalization.parse(signature.getCanonicalization());
        if (!verifyBodyHash(signature, message, canon)) {
            return new DkimResult(DkimStatus.FAIL, signature.getSelector(),
                    signature.getDomain(), "body hash mismatch");
        }
        DnsResult dnsResult = fetchKey(signature, resolver);
        if (dnsResult.getStatus() == DnsStatus.NXDOMAIN) {
            return new DkimResult(DkimStatus.PERMERROR, signature.getSelector(),
                    signature.getDomain(), "unknown selector / key record not found");
        }
        if (dnsResult.getStatus() == DnsStatus.TIMEOUT) {
            return new DkimResult(DkimStatus.TEMPERROR, signature.getSelector(),
                    signature.getDomain(), "key lookup timeout");
        }
        if (dnsResult.getStatus() == DnsStatus.MALFORMED) {
            return new DkimResult(DkimStatus.PERMERROR, signature.getSelector(),
                    signature.getDomain(), "key lookup malformed response");
        }
        DkimPublicKey publicKey;
        try {
            publicKey = DkimKeyParser.parse(joinTxt(dnsResult));
        } catch (DkimFormatException e) {
            return new DkimResult(DkimStatus.PERMERROR, signature.getSelector(),
                    signature.getDomain(), "malformed key record: " + e.getMessage());
        }
        if (publicKey.isRevoked()) {
            return new DkimResult(DkimStatus.FAIL, signature.getSelector(),
                    signature.getDomain(), "public key revoked");
        }
        if (!algorithmMatchesKey(signature.getAlgorithm(), publicKey.getKeyType())) {
            return new DkimResult(DkimStatus.PERMERROR, signature.getSelector(),
                    signature.getDomain(), "algorithm/key type mismatch");
        }
        try {
            byte[] signedData = buildSignedData(signature, message, signatureHeader);
            boolean valid = verifySignature(signature, publicKey, signedData);
            if (!valid) {
                return new DkimResult(DkimStatus.FAIL, signature.getSelector(),
                        signature.getDomain(), "signature verification failed");
            }
        } catch (DkimFormatException e) {
            return new DkimResult(DkimStatus.PERMERROR, signature.getSelector(),
                    signature.getDomain(), e.getMessage());
        } catch (SignatureException e) {
            return new DkimResult(DkimStatus.FAIL, signature.getSelector(),
                    signature.getDomain(), "signature verification failed: " + e.getMessage());
        } catch (Exception e) {
            return new DkimResult(DkimStatus.TEMPERROR, signature.getSelector(),
                    signature.getDomain(), "unexpected verification error: " + e.getMessage());
        }
        return new DkimResult(DkimStatus.PASS, signature.getSelector(),
                signature.getDomain(), "ok");
    }

    private boolean verifyBodyHash(DkimSignature signature, RawMessage message,
                                   Canonicalization canon) {
        byte[] canonicalBody = DkimCanonicalizer.canonicalizeBody(
                message.getBody(), canon.relaxedBody(), signature.getBodyLength());
        String digestAlgorithm = signature.getAlgorithm().toLowerCase(java.util.Locale.ROOT)
                .contains("sha1") ? "SHA-1" : "SHA-256";
        byte[] actual;
        try {
            actual = java.security.MessageDigest.getInstance(digestAlgorithm).digest(canonicalBody);
        } catch (Exception e) {
            throw new IllegalStateException("unsupported digest " + digestAlgorithm, e);
        }
        return java.security.MessageDigest.isEqual(actual, signature.getBodyHash());
    }

    private DnsResult fetchKey(DkimSignature signature, DnsResolver resolver) {
        String keyName = signature.getSelector() + "._domainkey." + signature.getDomain();
        return resolver.resolve(keyName, RecordType.TXT);
    }

    private String joinTxt(DnsResult dnsResult) {
        return String.join("", dnsResult.getRecords());
    }

    private boolean algorithmMatchesKey(String algorithm, String keyType) {
        String algo = algorithm.toLowerCase(java.util.Locale.ROOT);
        if (algo.startsWith("rsa-")) {
            return "rsa".equals(keyType);
        }
        if (algo.startsWith("ed25519-")) {
            return "ed25519".equals(keyType);
        }
        return false;
    }

    private byte[] buildSignedData(DkimSignature signature, RawMessage message,
                                   RawMessage.Header signatureHeader) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        List<String> signedHeaders = signature.getSignedHeaders();
        java.util.Map<String, Integer> cursor = new java.util.HashMap<>();
        for (String wanted : signedHeaders) {
            RawMessage.Header matched = findHeader(message, wanted, cursor);
            if (matched == null) {
                byte[] empty = (canonHeaderRelaxed(signature)
                        ? (wanted + ":\r\n") : "\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1);
                output.write(empty, 0, empty.length);
                continue;
            }
            byte[] canonical = DkimCanonicalizer.canonicalizeHeader(
                    matched.getRawName(),
                    matched.getUnfoldedValue(),
                    matched.getRawFoldedValue(),
                    signature.getCanonicalization().startsWith("relaxed"));
            output.write(canonical, 0, canonical.length);
        }
        byte[] signatureHeaderCanonical = buildCanonicalSignatureHeader(
                signatureHeader, signature, canonHeaderRelaxed(signature));
        output.write(signatureHeaderCanonical, 0, signatureHeaderCanonical.length);
        return output.toByteArray();
    }

    private RawMessage.Header findHeader(RawMessage message, String wanted,
                                         java.util.Map<String, Integer> cursor) {
        List<RawMessage.Header> all = message.getHeaders(wanted);
        if (all.isEmpty()) {
            return null;
        }
        int used = cursor.merge(wanted, 1, Integer::sum);
        int index = all.size() - used;
        return index >= 0 ? all.get(index) : null;
    }

    private boolean canonHeaderRelaxed(DkimSignature signature) {
        return signature.getCanonicalization().startsWith("relaxed");
    }

    private byte[] buildCanonicalSignatureHeader(RawMessage.Header signatureHeader,
                                                 DkimSignature signature, boolean relaxed) {
        String value = signatureHeader.getUnfoldedValue();
        if (relaxed) {
            return DkimCanonicalizer.canonicalizeHeader(signatureHeader.getRawName(),
                    emptyBTag(value), signatureHeader.getRawFoldedValue(), true);
        }
        String foldedLine = signatureHeader.getRawFoldedValue();
        String emptiedFolded = emptyBTagFoldedKeepFolding(foldedLine);
        return (signatureHeader.getRawName() + ":" + emptiedFolded + "\r\n")
                .getBytes(StandardCharsets.ISO_8859_1);
    }

    private String emptyBTagFoldedKeepFolding(String foldedValue) {
        String trimmed = foldedValue;
        while (trimmed.endsWith("\r\n") || trimmed.endsWith("\n")) {
            trimmed = trimmed.substring(0, trimmed.length()
                    - (trimmed.endsWith("\r\n") ? 2 : 1));
        }
        int equals = indexOfBEqualsAcrossFolding(trimmed);
        return trimmed.substring(0, equals + 1);
    }

    private String emptyBTag(String unfoldedValue) {
        int index = indexOfBTag(unfoldedValue);
        return unfoldedValue.substring(0, unfoldedValue.indexOf('=', index) + 1);
    }

    private int indexOfBTag(String value) {
        int search = 0;
        while (search < value.length()) {
            int semi = value.indexOf(';', search);
            int tokenEnd = semi < 0 ? value.length() : semi;
            int index = search;
            while (index < tokenEnd
                    && (value.charAt(index) == ' ' || value.charAt(index) == '\t')) {
                index++;
            }
            if (index + 1 < tokenEnd && value.regionMatches(true, index, "b=", 0, 2)) {
                return index;
            }
            if (semi < 0) {
                break;
            }
            search = semi + 1;
        }
        int index = 0;
        while (index < value.length()
                && (value.charAt(index) == ' ' || value.charAt(index) == '\t')) {
            index++;
        }
        if (index + 1 < value.length() && value.regionMatches(true, index, "b=", 0, 2)) {
            return index;
        }
        throw new DkimFormatException("signature missing b= tag");
    }

    /**
     * 在同一行表示（已去 CRLF、保留续行空白）中定位 b= 的等号。
     */
    private int indexOfBTagEquals(String value) {
        int index = indexOfBTag(value);
        return value.indexOf('=', index);
    }

    /**
     * 在带 CRLF 折行的签名头值中定位 b= 的等号下标；
     * 折行只允许出现在空白处，标签名与 '=' 本身不跨行。
     */
    private int indexOfBEqualsAcrossFolding(String value) {
        int search = 0;
        while (search < value.length()) {
            int tokenStart = skipFoldingWhitespace(value, search);
            if (tokenStart + 1 < value.length()
                    && value.regionMatches(true, tokenStart, "b=", 0, 2)) {
                return tokenStart + 1;
            }
            int semi = indexOfSemicolon(value, search);
            if (semi < 0) {
                break;
            }
            search = semi + 1;
        }
        throw new DkimFormatException("signature missing b= tag");
    }

    private int indexOfSemicolon(String value, int from) {
        for (int i = from; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ';') {
                return i;
            }
            if (c == '\r' || c == '\n') {
                // 折行不会出现在 ';' 之前的值内部（b= 除外，b= 总在末尾）。
                i = skipFoldingWhitespace(value, i) - 1;
            }
        }
        return -1;
    }

    private int skipFoldingWhitespace(String value, int pos) {
        int end = pos;
        while (end < value.length()) {
            char c = value.charAt(end);
            if (c == ' ' || c == '\t') {
                end++;
            } else if (c == '\r' || c == '\n') {
                if (c == '\r' && end + 1 < value.length() && value.charAt(end + 1) == '\n') {
                    end++;
                }
                end++;
            } else {
                break;
            }
        }
        return end;
    }

    private boolean verifySignature(DkimSignature signature, DkimPublicKey publicKey,
                                   byte[] signedData) throws Exception {
        String algo = signature.getAlgorithm().toLowerCase(java.util.Locale.ROOT);
        java.security.Signature verifier;
        if (algo.startsWith("rsa-")) {
            String jca = algo.contains("sha256") ? "SHA256withRSA" : "SHA1withRSA";
            verifier = java.security.Signature.getInstance(jca);
        } else {
            verifier = java.security.Signature.getInstance("Ed25519");
        }
        verifier.initVerify(publicKey.getPublicKey());
        verifier.update(signedData);
        return verifier.verify(signature.getSignatureData());
    }

    private enum Canonicalization {
        SIMPLE_SIMPLE(false, false),
        SIMPLE_RELAXED(false, true),
        RELAXED_SIMPLE(true, false),
        RELAXED_RELAXED(true, true);

        private final boolean relaxedHeader;
        private final boolean relaxedBody;

        Canonicalization(boolean relaxedHeader, boolean relaxedBody) {
            this.relaxedHeader = relaxedHeader;
            this.relaxedBody = relaxedBody;
        }

        boolean relaxedHeader() {
            return relaxedHeader;
        }

        boolean relaxedBody() {
            return relaxedBody;
        }

        static Canonicalization parse(String raw) {
            String value = raw == null ? "simple/simple" : raw.toLowerCase(java.util.Locale.ROOT);
            String[] parts = value.split("/");
            String header = parts[0];
            String body = parts.length > 1 ? parts[1] : "simple";
            if ("relaxed".equals(header) && "relaxed".equals(body)) {
                return RELAXED_RELAXED;
            }
            if ("relaxed".equals(header)) {
                return RELAXED_SIMPLE;
            }
            if ("relaxed".equals(body)) {
                return SIMPLE_RELAXED;
            }
            return SIMPLE_SIMPLE;
        }
    }
}

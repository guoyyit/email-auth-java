package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.dkim.Canonicalizer;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

/**
 * 测试夹具：生成 RSA 密钥、对构造邮件做 DKIM 签名。
 */
final class TestFixtures {

    private TestFixtures() {
    }

    record DkimKeyPair(KeyPair keyPair, String publicBase64) {
    }

    static DkimKeyPair generateRsaKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        String publicBase64 = Base64.getEncoder().encodeToString(
                keyPair.getPublic().getEncoded());
        return new DkimKeyPair(keyPair, publicBase64);
    }

    /**
     * 生成一封带 DKIM-Signature 的邮件。
     */
    static byte[] signMessage(byte[] message, KeyPair keyPair, String domain, String selector,
                              String headerCanonicalization, String bodyCanonicalization,
                              String... signedHeaders) throws Exception {
        int separator = findHeaderBody(message);
        int bodyStart = separator;
        int headerEnd;
        if (bodyStart >= 2 && message[bodyStart - 2] == '\r' && message[bodyStart - 1] == '\n') {
            headerEnd = bodyStart - 2;
        } else if (bodyStart >= 1 && message[bodyStart - 1] == '\n') {
            headerEnd = bodyStart - 1;
        } else {
            headerEnd = bodyStart;
        }
        byte[] headerBlock = new byte[headerEnd];
        System.arraycopy(message, 0, headerBlock, 0, headerEnd);
        byte[] body = new byte[message.length - bodyStart];
        System.arraycopy(message, bodyStart, body, 0, body.length);

        Canonicalizer.BodyMode bodyMode = "relaxed".equals(bodyCanonicalization)
                ? Canonicalizer.BodyMode.RELAXED : Canonicalizer.BodyMode.SIMPLE;
        Canonicalizer.HeaderMode headerMode = "relaxed".equals(headerCanonicalization)
                ? Canonicalizer.HeaderMode.RELAXED : Canonicalizer.HeaderMode.SIMPLE;

        byte[] canonicalBody = Canonicalizer.canonicalizeBody(body, bodyMode, null);
        byte[] bodyHash = java.security.MessageDigest.getInstance("SHA-256").digest(canonicalBody);
        String bh = Base64.getEncoder().encodeToString(bodyHash);

        String tagPrefix = "v=1; a=rsa-sha256; c=" + headerCanonicalization + "/"
                + bodyCanonicalization + "; d=" + domain + "; s=" + selector + "; "
                + "h=" + String.join(":", signedHeaders) + "; bh=" + bh + "; b=";

        ByteArrayOutputStream signedData = new ByteArrayOutputStream();
        for (String headerName : signedHeaders) {
            String displayName = displayHeaderName(headerName);
            String value = findHeader(headerBlock, displayName);
            signedData.writeBytes(Canonicalizer.canonicalizeHeader(
                    displayName, value, headerMode));
        }
        signedData.writeBytes(Canonicalizer.canonicalizeHeader(
                "DKIM-Signature", " " + tagPrefix, headerMode));

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(signedData.toByteArray());
        byte[] signature = signer.sign();
        String b = Base64.getEncoder().encodeToString(signature);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(headerBlock);
        out.writeBytes(("DKIM-Signature: " + tagPrefix + b + "\r\n").getBytes(StandardCharsets.UTF_8));
        out.write(message, headerEnd, message.length - headerEnd);
        return out.toByteArray();
    }

    private static int findHeaderBody(byte[] message) {
        int pos = 0;
        while (pos < message.length) {
            if (message[pos] == '\n' || message[pos] == '\r') {
                int lineEndExclusive;
                if (message[pos] == '\r' && pos + 1 < message.length && message[pos + 1] == '\n') {
                    lineEndExclusive = pos + 2;
                } else {
                    lineEndExclusive = pos + 1;
                }
                if (lineEndExclusive >= message.length
                        || message[lineEndExclusive] == '\n' || message[lineEndExclusive] == '\r') {
                    if (lineEndExclusive < message.length
                            && message[lineEndExclusive] == '\r'
                            && lineEndExclusive + 1 < message.length
                            && message[lineEndExclusive + 1] == '\n') {
                        return lineEndExclusive + 2;
                    }
                    if (lineEndExclusive < message.length
                            && message[lineEndExclusive] == '\n') {
                        return lineEndExclusive + 1;
                    }
                    return message.length;
                }
                pos = lineEndExclusive;
            } else {
                pos++;
            }
        }
        throw new IllegalArgumentException("no header/body separator");
    }

    private static String findHeader(byte[] headerBlock, String name) {
        String block = new String(headerBlock, StandardCharsets.ISO_8859_1);
        for (String line : block.split("\r\n|\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).equalsIgnoreCase(name)) {
                return line.substring(colon + 1).trim();
            }
        }
        throw new IllegalArgumentException("header not found: " + name);
    }

    private static String displayHeaderName(String name) {
        return switch (name.toLowerCase(java.util.Locale.ROOT)) {
            case "message-id" -> "Message-ID";
            case "from" -> "From";
            case "to" -> "To";
            case "subject" -> "Subject";
            case "date" -> "Date";
            default -> name;
        };
    }

    static String message(String from, String subject, String body) {
        return "From: " + from + "\r\n"
                + "To: receiver@receiver.example\r\n"
                + "Subject: " + subject + "\r\n"
                + "Message-ID: <msg-" + Math.abs(java.util.UUID.randomUUID().hashCode())
                + "@receiver.example>\r\n"
                + "Date: Wed, 30 Sep 2026 10:00:00 +0800\r\n"
                + "\r\n"
                + body;
    }
}

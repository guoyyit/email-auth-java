package com.github.guoyyit.emailauthjava.tests;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * 生成 relaxed/relaxed DKIM 签名邮件，供集成测试使用。
 */
final class DkimMessageSigner {
    private static final String DOMAIN = "example.com";
    private static final String SELECTOR = "sel";

    private final KeyPair keyPair;

    DkimMessageSigner(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    byte[] relaxed(String body) throws Exception {
        return relaxed(body.getBytes(StandardCharsets.ISO_8859_1));
    }

    /**
     * 使用正文字节直接生成签名，正文可包含任意 8 位（包括非 UTF-8）字节序列。
     */
    byte[] relaxed(byte[] bodyBytes) throws Exception {
        String fromValue = "user@" + DOMAIN;
        String canonicalBody = trimTrailingBytes(bodyBytes) + "\r\n";
        String bh = Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256")
                        .digest(canonicalBody.getBytes(StandardCharsets.ISO_8859_1)));
        String prefix = "v=1; a=rsa-sha256; d=" + DOMAIN + "; s=" + SELECTOR
                + "; c=relaxed/relaxed; h=from; bh=" + bh;
        String signedData = "from:" + fromValue + "\r\n"
                + "dkim-signature:" + prefix + "; b=" + "\r\n";

        java.security.Signature signer = java.security.Signature.getInstance("SHA256withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(signedData.getBytes(StandardCharsets.ISO_8859_1));
        String b = Base64.getEncoder().encodeToString(signer.sign());

        byte[] headerBytes = ("From: " + fromValue + "\r\n"
                + "DKIM-Signature: " + prefix + "; b=" + b + "\r\n\r\n").getBytes(
                StandardCharsets.ISO_8859_1);
        byte[] full = new byte[headerBytes.length + bodyBytes.length];
        System.arraycopy(headerBytes, 0, full, 0, headerBytes.length);
        System.arraycopy(bodyBytes, 0, full, headerBytes.length, bodyBytes.length);
        return full;
    }

    private static String trimTrailingBytes(byte[] body) {
        int end = body.length;
        while (end > 0) {
            byte value = body[end - 1];
            if (value == ' ' || value == '\t' || value == '\r' || value == '\n') {
                end--;
            } else {
                break;
            }
        }
        return new String(body, 0, end, StandardCharsets.ISO_8859_1);
    }
}

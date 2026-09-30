package com.github.guoyyit.emailauthjava.tests;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

/**
 * 测试用 RSA 密钥对与 DKIM 公钥 TXT 记录生成。
 */
final class DkimTestKeys {
    private DkimTestKeys() {
    }

    static KeyPair generateRsa() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String publicKeyTxt(KeyPair keyPair) {
        try {
            byte[] encoded = KeyFactory.getInstance("RSA")
                    .getKeySpec(keyPair.getPublic(),
                            java.security.spec.X509EncodedKeySpec.class)
                    .getEncoded();
            return "v=DKIM1; k=rsa; p=" + Base64.getEncoder().encodeToString(encoded);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}

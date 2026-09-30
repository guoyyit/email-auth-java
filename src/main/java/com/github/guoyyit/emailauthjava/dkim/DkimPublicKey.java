package com.github.guoyyit.emailauthjava.dkim;

import java.security.PublicKey;

/**
 * selector._domainkey 记录解析出的公钥信息。
 */
final class DkimPublicKey {
    private final String keyType;
    private final PublicKey publicKey;
    private final boolean revoked;

    DkimPublicKey(String keyType, PublicKey publicKey, boolean revoked) {
        this.keyType = keyType;
        this.publicKey = publicKey;
        this.revoked = revoked;
    }

    String getKeyType() {
        return keyType;
    }

    PublicKey getPublicKey() {
        return publicKey;
    }

    boolean isRevoked() {
        return revoked;
    }
}

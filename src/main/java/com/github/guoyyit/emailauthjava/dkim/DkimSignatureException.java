package com.github.guoyyit.emailauthjava.dkim;

/** DKIM 签名标签格式错误，归类为 permerror。 */
class DkimSignatureException extends RuntimeException {
    DkimSignatureException(String message) {
        super(message);
    }
}

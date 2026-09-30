package com.github.guoyyit.emailauthjava.dkim;

/**
 * DKIM 记录或签名格式错误，求值时映射为 permerror。
 */
class DkimFormatException extends RuntimeException {
    DkimFormatException(String message) {
        super(message);
    }
}

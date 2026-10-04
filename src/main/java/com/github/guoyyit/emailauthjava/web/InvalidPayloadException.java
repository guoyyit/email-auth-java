package com.github.guoyyit.emailauthjava.web;

/**
 * 请求载荷无法解码（例如 rawMessageBase64 不是合法 Base64）。
 */
public class InvalidPayloadException extends RuntimeException {
    public InvalidPayloadException(String message, Throwable cause) {
        super(message, cause);
    }
}

package com.github.guoyyit.emailauthjava.error;

public class ResourceLimitException extends RuntimeException {
    private final AuthError error;

    public ResourceLimitException(AuthError error, String message) {
        super(message);
        this.error = error;
    }

    public AuthError getError() { return error; }
}

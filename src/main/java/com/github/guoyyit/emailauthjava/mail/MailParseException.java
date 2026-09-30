package com.github.guoyyit.emailauthjava.mail;

/** 邮件解析错误。区分超大输入与畸形结构两类。 */
public class MailParseException extends RuntimeException {
    private final boolean sizeLimit;

    public MailParseException(String message, boolean sizeLimit) {
        super(message);
        this.sizeLimit = sizeLimit;
    }

    public boolean isSizeLimit() {
        return sizeLimit;
    }
}

package com.github.guoyyit.emailauthjava.report;

/** 聚合数据持久化/恢复失败。 */
public class ReportPersistenceException extends RuntimeException {
    public ReportPersistenceException(String message, Throwable cause) {
        super(message, cause);
    }
}

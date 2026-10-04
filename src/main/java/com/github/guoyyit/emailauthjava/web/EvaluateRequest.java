package com.github.guoyyit.emailauthjava.web;

public class EvaluateRequest {
    private String heloDomain;
    private String clientIp;
    private String envelopeFrom;
    private String rawMessage;
    /**
     * 邮件原文的 Base64 编码（标准字母表，可省略填充）。提供时优先于
     * {@link #rawMessage}，用于无损承载任意 8 位字节序列（含非 UTF-8 字节）。
     */
    private String rawMessageBase64;

    public String getHeloDomain() { return heloDomain; }
    public void setHeloDomain(String heloDomain) { this.heloDomain = heloDomain; }
    public String getClientIp() { return clientIp; }
    public void setClientIp(String clientIp) { this.clientIp = clientIp; }
    public String getEnvelopeFrom() { return envelopeFrom; }
    public void setEnvelopeFrom(String envelopeFrom) { this.envelopeFrom = envelopeFrom; }
    public String getRawMessage() { return rawMessage; }
    public void setRawMessage(String rawMessage) { this.rawMessage = rawMessage; }
    public String getRawMessageBase64() { return rawMessageBase64; }
    public void setRawMessageBase64(String rawMessageBase64) {
        this.rawMessageBase64 = rawMessageBase64;
    }
}

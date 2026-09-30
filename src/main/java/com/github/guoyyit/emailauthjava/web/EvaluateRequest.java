package com.github.guoyyit.emailauthjava.web;

public class EvaluateRequest {
    private String heloDomain;
    private String clientIp;
    private String envelopeFrom;
    private String rawMessage;

    public String getHeloDomain() { return heloDomain; }
    public void setHeloDomain(String heloDomain) { this.heloDomain = heloDomain; }
    public String getClientIp() { return clientIp; }
    public void setClientIp(String clientIp) { this.clientIp = clientIp; }
    public String getEnvelopeFrom() { return envelopeFrom; }
    public void setEnvelopeFrom(String envelopeFrom) { this.envelopeFrom = envelopeFrom; }
    public String getRawMessage() { return rawMessage; }
    public void setRawMessage(String rawMessage) { this.rawMessage = rawMessage; }
}

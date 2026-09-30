package com.github.guoyyit.emailauthjava.service;

import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dmarc.DmarcResult;
import com.github.guoyyit.emailauthjava.spf.SpfResult;

import java.util.List;

public class EvaluationResult {
    private String messageId;
    private String envelopeFrom;
    private String headerFrom;
    private SpfResult spf;
    private List<DkimResult> dkim;
    private DmarcResult dmarc;
    private String errorCode;
    private String errorMessage;

    public String getMessageId() { return messageId; }
    public void setMessageId(String messageId) { this.messageId = messageId; }
    public String getEnvelopeFrom() { return envelopeFrom; }
    public void setEnvelopeFrom(String envelopeFrom) { this.envelopeFrom = envelopeFrom; }
    public String getHeaderFrom() { return headerFrom; }
    public void setHeaderFrom(String headerFrom) { this.headerFrom = headerFrom; }
    public SpfResult getSpf() { return spf; }
    public void setSpf(SpfResult spf) { this.spf = spf; }
    public List<DkimResult> getDkim() { return dkim; }
    public void setDkim(List<DkimResult> dkim) { this.dkim = dkim; }
    public DmarcResult getDmarc() { return dmarc; }
    public void setDmarc(DmarcResult dmarc) { this.dmarc = dmarc; }
    public String getErrorCode() { return errorCode; }
    public void setErrorCode(String errorCode) { this.errorCode = errorCode; }
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
}

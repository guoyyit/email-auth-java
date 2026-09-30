package com.github.guoyyit.emailauthjava.dkim;

import java.util.List;

public class DkimSignature {
    private String version;
    private String algorithm;
    private String domain;
    private String selector;
    private List<String> signedHeaders;
    private byte[] bodyHash;
    private byte[] signatureData;
    private String canonicalization;
    private Long bodyLength;
    private Long expiration;

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }
    public String getSelector() { return selector; }
    public void setSelector(String selector) { this.selector = selector; }
    public List<String> getSignedHeaders() { return signedHeaders; }
    public void setSignedHeaders(List<String> signedHeaders) { this.signedHeaders = signedHeaders; }
    public byte[] getBodyHash() { return bodyHash; }
    public void setBodyHash(byte[] bodyHash) { this.bodyHash = bodyHash; }
    public byte[] getSignatureData() { return signatureData; }
    public void setSignatureData(byte[] signatureData) { this.signatureData = signatureData; }
    public String getCanonicalization() { return canonicalization; }
    public void setCanonicalization(String canonicalization) { this.canonicalization = canonicalization; }
    public Long getBodyLength() { return bodyLength; }
    public void setBodyLength(Long bodyLength) { this.bodyLength = bodyLength; }
    public Long getExpiration() { return expiration; }
    public void setExpiration(Long expiration) { this.expiration = expiration; }
}

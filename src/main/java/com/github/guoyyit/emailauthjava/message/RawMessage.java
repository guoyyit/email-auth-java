package com.github.guoyyit.emailauthjava.message;

import java.util.List;

public class RawMessage {
    private final String heloDomain;
    private final String clientIp;
    private final List<Header> headers;
    private final byte[] body;
    private final byte[] rawHeaderBytes;
    private final byte[] raw;

    public RawMessage(String heloDomain, String clientIp, List<Header> headers, byte[] body,
                      byte[] rawHeaderBytes, byte[] raw) {
        this.heloDomain = heloDomain;
        this.clientIp = clientIp;
        this.headers = headers;
        this.body = body;
        this.rawHeaderBytes = rawHeaderBytes;
        this.raw = raw;
    }

    public String getHeloDomain() { return heloDomain; }
    public String getClientIp() { return clientIp; }
    public List<Header> getHeaders() { return headers; }
    public byte[] getBody() { return body; }
    public byte[] getRawHeaderBytes() { return rawHeaderBytes; }
    public byte[] getRaw() { return raw; }

    public String getFirstHeader(String name) {
        String wanted = name.toLowerCase(java.util.Locale.ROOT);
        for (Header header : headers) {
            if (header.getName().toLowerCase(java.util.Locale.ROOT).equals(wanted)) {
                return header.getUnfoldedValue();
            }
        }
        return null;
    }

    public java.util.List<Header> getHeaders(String name) {
        String wanted = name.toLowerCase(java.util.Locale.ROOT);
        java.util.List<Header> matched = new java.util.ArrayList<>();
        for (Header header : headers) {
            if (header.getName().toLowerCase(java.util.Locale.ROOT).equals(wanted)) {
                matched.add(header);
            }
        }
        return matched;
    }

    public static class Header {
        private final String name;
        private final String unfoldedValue;
        private final String rawName;
        private final byte[] rawBytes;
        private final String rawFoldedValue;

        public Header(String name, String unfoldedValue, String rawName, byte[] rawBytes,
                      String rawFoldedValue) {
            this.name = name;
            this.unfoldedValue = unfoldedValue;
            this.rawName = rawName;
            this.rawBytes = rawBytes;
            this.rawFoldedValue = rawFoldedValue;
        }

        public String getName() { return name; }
        public String getUnfoldedValue() { return unfoldedValue; }
        public String getRawName() { return rawName; }
        public byte[] getRawBytes() { return rawBytes; }
        public String getRawFoldedValue() { return rawFoldedValue; }
    }
}

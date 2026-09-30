package com.github.guoyyit.emailauthjava.mail;

import java.util.List;

/**
 * 解析后的邮件：头部列表（保持出现顺序）、原始头部字节块与正文原始字节。
 */
public final class ParsedMail {

    private final List<Header> headers;
    private final byte[] rawHeaderBlock;
    private final byte[] rawBody;

    public ParsedMail(List<Header> headers, byte[] rawHeaderBlock, byte[] rawBody) {
        this.headers = List.copyOf(headers);
        this.rawHeaderBlock = rawHeaderBlock.clone();
        this.rawBody = rawBody.clone();
    }

    public List<Header> getHeaders() {
        return headers;
    }

    /** 按名称（大小写不敏感）返回所有同名头部。 */
    public List<Header> getHeaders(String name) {
        String target = name.toLowerCase(java.util.Locale.ROOT);
        List<Header> matched = new java.util.ArrayList<>();
        for (Header header : headers) {
            if (header.getName().equals(target)) {
                matched.add(header);
            }
        }
        return List.copyOf(matched);
    }

    /** 取第一个同名头部的值，不存在返回 null。 */
    public String getFirstHeader(String name) {
        String target = name.toLowerCase(java.util.Locale.ROOT);
        for (Header header : headers) {
            if (header.getName().equals(target)) {
                return header.getUnfoldedValue();
            }
        }
        return null;
    }

    public byte[] getRawHeaderBlock() {
        return rawHeaderBlock.clone();
    }

    public byte[] getRawBody() {
        return rawBody.clone();
    }
}

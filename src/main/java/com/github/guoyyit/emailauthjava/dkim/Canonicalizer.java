package com.github.guoyyit.emailauthjava.dkim;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * DKIM simple/relaxed 规范化（RFC 6376 §3.4），输出规范化后的字节。
 */
public final class Canonicalizer {

    private Canonicalizer() {
    }

    public enum HeaderMode { SIMPLE, RELAXED }

    public enum BodyMode { SIMPLE, RELAXED }

    public static byte[] canonicalizeHeader(String name, String unfoldedValue, HeaderMode mode) {
        if (mode == HeaderMode.RELAXED) {
            String relaxedName = name.trim().toLowerCase(java.util.Locale.ROOT);
            String value = unfoldedValue.replaceAll("[ \\t]+", " ").trim();
            return (relaxedName + ":" + value + "\r\n").getBytes(StandardCharsets.UTF_8);
        }
        return (name + ":" + unfoldedValue + "\r\n").getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] canonicalizeBody(byte[] rawBody, BodyMode mode, Integer lengthLimit) {
        byte[] normalized = mode == BodyMode.RELAXED
                ? relaxedBody(rawBody)
                : simpleBody(rawBody);
        if (lengthLimit != null) {
            int limit = Math.max(lengthLimit, 0);
            if (normalized.length > limit) {
                byte[] truncated = new byte[limit];
                System.arraycopy(normalized, 0, truncated, 0, limit);
                normalized = truncated;
            }
        }
        return normalized;
    }

    /** simple：原样保留，仅将多个结尾 CRLF 折叠为一个；无正文时补一个 CRLF。 */
    static byte[] simpleBody(byte[] raw) {
        int end = raw.length;
        while (hasCrlfAt(raw, end - 2) && hasCrlfAt(raw, end - 4)) {
            end -= 2;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(end, 2));
        out.write(raw, 0, end);
        if (!hasCrlfAt(raw, end - 2)) {
            out.write('\r');
            out.write('\n');
        }
        return out.toByteArray();
    }

    private static boolean hasCrlfAt(byte[] raw, int index) {
        return index >= 0 && index + 1 < raw.length
                && raw[index] == '\r' && raw[index + 1] == '\n';
    }

    /** relaxed：逐行空白归并、行尾归一、丢弃尾部空行，末尾保证单个 CRLF。 */
    static byte[] relaxedBody(byte[] raw) {
        List<byte[]> contentLines = new ArrayList<>();
        int pos = 0;
        while (pos < raw.length || pos == 0) {
            int lineStart = pos;
            while (pos < raw.length && raw[pos] != '\n' && raw[pos] != '\r') {
                pos++;
            }
            byte[] line = new byte[pos - lineStart];
            System.arraycopy(raw, lineStart, line, 0, line.length);
            byte[] collapsed = collapseLine(line);
            if (collapsed.length > 0) {
                contentLines.add(collapsed);
            }
            if (pos >= raw.length) {
                break;
            }
            if (raw[pos] == '\r' && pos + 1 < raw.length && raw[pos + 1] == '\n') {
                pos += 2;
            } else {
                pos++;
            }
            if (pos > raw.length) {
                break;
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < contentLines.size(); i++) {
            out.writeBytes(contentLines.get(i));
            out.write('\r');
            out.write('\n');
        }
        if (contentLines.isEmpty()) {
            out.write('\r');
            out.write('\n');
        }
        return out.toByteArray();
    }

    private static byte[] collapseLine(byte[] line) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(line.length);
        boolean pendingSpace = false;
        for (byte value : line) {
            if (value == ' ' || value == '\t') {
                pendingSpace = true;
            } else {
                if (pendingSpace) {
                    out.write(' ');
                    pendingSpace = false;
                }
                out.write(value & 0xff);
            }
        }
        byte[] collapsed = out.toByteArray();
        int end = collapsed.length;
        while (end > 0 && collapsed[end - 1] == ' ') {
            end--;
        }
        if (end == collapsed.length) {
            return collapsed;
        }
        byte[] trimmed = new byte[end];
        System.arraycopy(collapsed, 0, trimmed, 0, end);
        return trimmed;
    }
}

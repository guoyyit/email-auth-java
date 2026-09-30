package com.github.guoyyit.emailauthjava.dkim;

/**
 * RFC 6376 规范化：simple/relaxed 两种头部与正文算法。
 * 输入输出均为原始字节（ISO-8859-1 与文本头值配合），不破坏 8 位正文。
 */
final class DkimCanonicalizer {
    private static final byte CR = '\r';
    private static final byte LF = '\n';
    private static final byte SP = ' ';

    private DkimCanonicalizer() {
    }

    static byte[] canonicalizeHeader(String rawName, String unfoldedValue,
                                     String rawFoldedValue, boolean relaxed) {
        if (relaxed) {
            String name = rawName.trim().toLowerCase(java.util.Locale.ROOT);
            String value = relaxWhitespace(unfoldedValue).trim();
            return (name + ":" + value + "\r\n").getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        }
        String line = rawName + ":"
                + (rawFoldedValue == null ? unfoldedValue : stripLineEnd(rawFoldedValue)) + "\r\n";
        return line.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    private static String stripLineEnd(String value) {
        int end = value.length();
        if (end >= 2 && value.charAt(end - 1) == '\n' && value.charAt(end - 2) == '\r') {
            return value.substring(0, end - 2);
        }
        if (end >= 1 && (value.charAt(end - 1) == '\n' || value.charAt(end - 1) == '\r')) {
            return value.substring(0, end - 1);
        }
        return value;
    }

    static byte[] canonicalizeBody(byte[] body, boolean relaxed, Long lengthLimit) {
        byte[] considered = truncateByLength(body, relaxed, lengthLimit);
        if (relaxed) {
            return relaxedBody(considered);
        }
        return simpleBody(considered);
    }

    private static byte[] truncateByLength(byte[] body, boolean relaxed, Long lengthLimit) {
        if (lengthLimit == null) {
            return body;
        }
        long limit = lengthLimit;
        if (limit < 0) {
            return body;
        }
        // RFC 6376 3.4.5：l= 限定被签名的正文字节数（CRLF 不计数）。
        // 计数在“内容字节”上进行；预算耗尽后跳过当前行剩余内容，
        // 并保留行尾，使被截断的内容仍是完整行。后续行视为追加的未签名正文。
        long remaining = limit;
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        int pos = 0;
        while (pos < body.length) {
            int lineStart = pos;
            int lineEnd = lineStart;
            while (lineEnd < body.length && body[lineEnd] != LF) {
                lineEnd++;
            }
            int contentEnd = lineEnd;
            if (contentEnd > lineStart && body[contentEnd - 1] == CR) {
                contentEnd--;
            }
            long lineLength = contentEnd - lineStart;
            if (lineLength <= remaining) {
                output.write(body, lineStart, lineEnd - lineStart);
                writeLineEnd(body, lineEnd, output);
                remaining -= lineLength;
                pos = lineEnd + (lineEnd < body.length && body[lineEnd] == CR ? 2 : 1);
            } else {
                output.write(body, lineStart, (int) remaining);
                writeLineEnd(body, lineEnd, output);
                pos = body.length;
            }
        }
        return output.toByteArray();
    }

    private static void writeLineEnd(byte[] body, int lineEnd,
                                     java.io.ByteArrayOutputStream output) {
        if (lineEnd >= body.length) {
            return;
        }
        if (body[lineEnd] == CR) {
            output.write(CR);
            output.write(LF);
        } else {
            output.write(LF);
        }
    }

    private static byte[] simpleBody(byte[] body) {
        // RFC 6376 3.4.4：body 末尾的空行被忽略。
        // 即去除尾部所有 CRLF，再补回恰好一个 CRLF（空正文也保留一个 CRLF）。
        int end = body.length;
        while (end >= 2 && body[end - 1] == LF && body[end - 2] == CR) {
            end -= 2;
        }
        // 容忍裸 LF 的历史写法。
        if (end == body.length && end >= 1 && body[end - 1] == LF) {
            int cursor = end;
            while (cursor >= 1 && body[cursor - 1] == LF) {
                cursor--;
            }
            end = cursor;
        }
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        output.write(body, 0, end);
        output.write(CR);
        output.write(LF);
        return output.toByteArray();
    }

    private static byte[] relaxedBody(byte[] body) {
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        int pos = 0;
        while (pos < body.length) {
            int lineEnd = pos;
            while (lineEnd < body.length && body[lineEnd] != LF) {
                lineEnd++;
            }
            int contentEnd = lineEnd;
            if (contentEnd > pos && body[contentEnd - 1] == CR) {
                contentEnd--;
            }
            String line = new String(body, pos, contentEnd - pos,
                    java.nio.charset.StandardCharsets.ISO_8859_1);
            byte[] relaxedLine = relaxWhitespace(line).trim()
                    .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
            output.write(relaxedLine, 0, relaxedLine.length);
            output.write(CR);
            output.write(LF);
            pos = lineEnd + 1;
        }
        byte[] normalized = output.toByteArray();
        int end = normalized.length;
        while (end >= 4 && normalized[end - 1] == LF && normalized[end - 2] == CR
                && normalized[end - 3] == LF && normalized[end - 4] == CR) {
            end -= 2;
        }
        byte[] result = new byte[end];
        System.arraycopy(normalized, 0, result, 0, end);
        return result;
    }

    private static String relaxWhitespace(String value) {
        StringBuilder builder = new StringBuilder(value.length());
        boolean inWhitespace = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ' ' || c == '\t') {
                if (!inWhitespace) {
                    builder.append(' ');
                    inWhitespace = true;
                }
            } else {
                builder.append(c);
                inWhitespace = false;
            }
        }
        return builder.toString();
    }
}

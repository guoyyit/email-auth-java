package com.github.guoyyit.emailauthjava.message;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.error.AuthError;
import com.github.guoyyit.emailauthjava.error.ResourceLimitException;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 解析 RFC 5322 风格邮件：兼容 CRLF 与裸 LF 折行（折叠头）、8 位头与正文、
 * 常见历史写法（冒号前后空白、行尾空白）。严格执行可配置的资源边界。
 */
@Component
public class MessageParser {
    private static final byte CR = '\r';
    private static final byte LF = '\n';

    private final AuthProperties properties;

    public MessageParser(AuthProperties properties) {
        this.properties = properties;
    }

    public RawMessage parse(String heloDomain, String clientIp, byte[] raw) {
        if (raw == null) {
            raw = new byte[0];
        }
        if (raw.length > properties.getLimits().getMaxMessageBytes()) {
            throw new ResourceLimitException(AuthError.MESSAGE_TOO_LARGE,
                    "message size " + raw.length + " exceeds limit "
                            + properties.getLimits().getMaxMessageBytes());
        }
        int headerEnd = findHeaderEnd(raw);
        byte[] headerBlock = new byte[headerEnd];
        System.arraycopy(raw, 0, headerBlock, 0, headerEnd);
        byte[] body = new byte[raw.length - headerEnd];
        System.arraycopy(raw, headerEnd, body, 0, body.length);

        List<RawMessage.Header> headers = parseHeaders(headerBlock);
        byte[] rawHeaderBytes = headerBlock;
        return new RawMessage(heloDomain, clientIp, headers, body, rawHeaderBytes, raw);
    }

    /**
     * 定位头部分与正文之间的空行分隔位置，返回正文起始下标。
     * 兼容 CRLFCRLF、LFLF、CRLF LF 等历史写法。
     */
    private int findHeaderEnd(byte[] raw) {
        int i = 0;
        while (i < raw.length) {
            int lineEnd = findLineEnd(raw, i);
            int lineLength = lineEnd - i;
            if (lineLength == 0) {
                return skipLineEnd(raw, lineEnd);
            }
            i = skipLineEnd(raw, lineEnd);
        }
        return raw.length;
    }

    private List<RawMessage.Header> parseHeaders(byte[] headerBlock) {
        if (headerBlock.length > properties.getLimits().getMaxHeaderBytes()) {
            throw new ResourceLimitException(AuthError.HEADER_TOO_LARGE,
                    "header block " + headerBlock.length + " exceeds limit "
                            + properties.getLimits().getMaxHeaderBytes());
        }
        List<RawMessage.Header> headers = new ArrayList<>();
        List<int[]> lineRanges = splitLines(headerBlock);
        int index = 0;
        while (index < lineRanges.size()) {
            int[] startLine = lineRanges.get(index);
            if (startLine[1] - startLine[0] == 0) {
                index++;
                continue;
            }
            int groupStart = startLine[0];
            int groupEndLine = startLine[1];
            int next = index + 1;
            while (next < lineRanges.size() && isContinuation(headerBlock, lineRanges.get(next))) {
                groupEndLine = lineRanges.get(next)[1];
                next++;
            }
            RawMessage.Header header = buildHeader(headerBlock, groupStart, groupEndLine);
            headers.add(header);
            if (headers.size() > properties.getLimits().getMaxHeaders()) {
                throw new ResourceLimitException(AuthError.TOO_MANY_HEADERS,
                        "header count exceeds limit " + properties.getLimits().getMaxHeaders());
            }
            index = next;
        }
        return headers;
    }

    private boolean isContinuation(byte[] block, int[] range) {
        return range[1] - range[0] > 0
                && (block[range[0]] == ' ' || block[range[0]] == '\t');
    }

    private RawMessage.Header buildHeader(byte[] block, int start, int end) {
        int colon = start;
        while (colon < end && block[colon] != ':') {
            colon++;
        }
        if (colon >= end) {
            throw new ResourceLimitException(AuthError.MALFORMED_HEADER,
                    "header without ':' at offset " + start);
        }
        String rawName = new String(block, start, colon - start, StandardCharsets.ISO_8859_1);
        String name = rawName.trim();
        if (!isValidToken(name)) {
            throw new ResourceLimitException(AuthError.MALFORMED_HEADER,
                    "illegal header name: '" + rawName + "'");
        }
        int valueStart = colon + 1;
        String unfoldedValue = unfold(block, valueStart, end).trim();
        String rawFoldedValue = new String(block, valueStart, end - valueStart,
                StandardCharsets.ISO_8859_1);
        byte[] rawBytes = new byte[end - start];
        System.arraycopy(block, start, rawBytes, 0, rawBytes.length);
        return new RawMessage.Header(name, unfoldedValue, rawName, rawBytes, rawFoldedValue);
    }

    private String unfold(byte[] block, int start, int end) {
        StringBuilder builder = new StringBuilder();
        int pos = start;
        int lineNo = 0;
        while (pos < end) {
            int lineEnd = findLineEnd(block, pos);
            int lineLen = lineEnd - pos;
            if (lineLen > properties.getLimits().getMaxHeaderLineBytes()) {
                throw new ResourceLimitException(AuthError.HEADER_LINE_TOO_LONG,
                        "header line exceeds " + properties.getLimits().getMaxHeaderLineBytes()
                                + " bytes");
            }
            if (lineNo > 0) {
                // RFC 折叠：CRLF 与续行行首的一个或多个 WSP 一起折叠为一个空格。
                builder.append(' ');
                int contentStart = pos;
                while (contentStart < lineEnd
                        && (block[contentStart] == ' ' || block[contentStart] == '\t')) {
                    contentStart++;
                }
                builder.append(new String(block, contentStart, lineEnd - contentStart,
                        StandardCharsets.ISO_8859_1));
            } else {
                builder.append(new String(block, pos, lineLen, StandardCharsets.ISO_8859_1));
            }
            pos = skipLineEnd(block, lineEnd);
            lineNo++;
        }
        return builder.toString();
    }

    private boolean isValidToken(String name) {
        if (name.isEmpty()) {
            return false;
        }
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c <= ' ' || c >= 127) {
                return false;
            }
        }
        return true;
    }

    private List<int[]> splitLines(byte[] data) {
        List<int[]> ranges = new ArrayList<>();
        int pos = 0;
        while (pos <= data.length) {
            int lineEnd = findLineEnd(data, pos);
            ranges.add(new int[]{pos, lineEnd});
            int next = skipLineEnd(data, lineEnd);
            if (next <= pos) {
                break;
            }
            pos = next;
        }
        return ranges;
    }

    private int findLineEnd(byte[] data, int from) {
        int pos = from;
        while (pos < data.length && data[pos] != CR && data[pos] != LF) {
            pos++;
        }
        return pos;
    }

    private int skipLineEnd(byte[] data, int lineEnd) {
        if (lineEnd >= data.length) {
            return lineEnd;
        }
        if (data[lineEnd] == CR) {
            if (lineEnd + 1 < data.length && data[lineEnd + 1] == LF) {
                return lineEnd + 2;
            }
            return lineEnd + 1;
        }
        return lineEnd + 1;
    }
}

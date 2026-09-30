package com.github.guoyyit.emailauthjava.mail;

import com.github.guoyyit.emailauthjava.config.AuthProperties;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 兼容 RFC 5322 的原始邮件解析：
 * <ul>
 *   <li>折行头部（CRLF WSP / LF WSP）展开；</li>
 *   <li>头部名大小写保留；</li>
 *   <li>8 位正文按原始字节保留（不强制 ASCII/UTF-8，按 ISO-8859-1 读头部）；</li>
 *   <li>容忍 LF 行尾、孤立 CR、缺结尾换行等历史写法；</li>
 *   <li>执行可配置的大小/数量上限，超限抛 {@link MailParseException}。</li>
 * </ul>
 */
public class MailParser {

    private static final java.nio.charset.Charset LATIN1 = StandardCharsets.ISO_8859_1;

    private final AuthProperties properties;

    public MailParser(AuthProperties properties) {
        this.properties = properties;
    }

    public ParsedMail parse(byte[] raw) {
        if (raw == null) {
            throw new MailParseException("null message", false);
        }
        if (raw.length > properties.getLimits().getMaxMessageBytes()) {
            throw new MailParseException(
                    "message exceeds max size " + properties.getLimits().getMaxMessageBytes(), true);
        }

        int separator = findHeaderBodySeparator(raw);
        int headerEnd;
        int bodyStart;
        if (separator < 0) {
            headerEnd = raw.length;
            bodyStart = raw.length;
        } else {
            headerEnd = separator;
            bodyStart = afterSeparator(raw, separator);
        }

        List<Header> headers = parseHeaders(raw, headerEnd);
        byte[] rawHeaderBlock = new byte[headerEnd];
        System.arraycopy(raw, 0, rawHeaderBlock, 0, headerEnd);
        byte[] rawBody = new byte[raw.length - bodyStart];
        System.arraycopy(raw, bodyStart, rawBody, 0, rawBody.length);
        return new ParsedMail(headers, rawHeaderBlock, rawBody);
    }

    /**
     * 定位头部/正文分隔空行的起始下标（CRLF、LF 或孤立 CR 均认可）；不存在返回 -1。
     */
    private int findHeaderBodySeparator(byte[] raw) {
        int i = 0;
        while (i < raw.length) {
            int lineStart = i;
            byte current = raw[i];
            if (current == '\n' || current == '\r') {
                return lineStart;
            }
            while (i < raw.length && raw[i] != '\n' && raw[i] != '\r') {
                i++;
            }
            if (i < raw.length && raw[i] == '\r' && i + 1 < raw.length && raw[i + 1] == '\n') {
                i += 2;
            } else if (i < raw.length) {
                i++;
            }
        }
        return -1;
    }

    private int afterSeparator(byte[] raw, int separator) {
        if (raw[separator] == '\r' && separator + 1 < raw.length && raw[separator + 1] == '\n') {
            return separator + 2;
        }
        return separator + 1;
    }

    private List<Header> parseHeaders(byte[] raw, int headerEnd) {
        List<int[]> logicalLines = splitLogicalLines(raw, headerEnd);
        List<Header> headers = new ArrayList<>();
        for (int[] line : logicalLines) {
            String unfolded = unfold(raw, line[0], line[1]);
            int colon = indexOfColon(raw, line[0], line[1]);
            if (colon < 0) {
                throw new MailParseException("malformed header line without ':'", false);
            }
            String name = new String(raw, line[0], colon - line[0], LATIN1).trim();
            if (name.isEmpty() || !isValidFieldName(name)) {
                throw new MailParseException("malformed header field name", false);
            }
            int valueStart = colon + 1;
            String value = unfolded.substring(valueStart - line[0]);
            value = stripLeadingWsp(value);
            headers.add(new Header(name, trimTrailingLineBreaks(value)));
        }
        return headers;
    }

    /**
     * 将头部区切分为逻辑行区间（折行续行并入上一行），每个元素为 [start,end)。
     * 执行头部总量、单行大小与数量上限。
     */
    private List<int[]> splitLogicalLines(byte[] raw, int headerEnd) {
        if (headerEnd > properties.getLimits().getMaxHeaderBytes()) {
            throw new MailParseException("header block exceeds max bytes", true);
        }
        List<int[]> physical = new ArrayList<>();
        int pos = 0;
        while (pos < headerEnd) {
            int contentStart = pos;
            while (pos < headerEnd && raw[pos] != '\n' && raw[pos] != '\r') {
                pos++;
            }
            int contentEnd = pos;
            physical.add(new int[]{contentStart, contentEnd});
            if (pos < headerEnd && raw[pos] == '\r'
                    && pos + 1 < headerEnd && raw[pos + 1] == '\n') {
                pos += 2;
            } else if (pos < headerEnd) {
                pos++;
            }
        }
        List<int[]> logical = new ArrayList<>();
        int start = -1;
        int end = -1;
        for (int[] range : physical) {
            boolean continuation = range[0] < range[1]
                    && (raw[range[0]] == ' ' || raw[range[0]] == '\t');
            if (!continuation) {
                if (start >= 0) {
                    addLogicalLine(logical, raw, start, end);
                }
                start = range[0];
            }
            end = range[1];
        }
        if (start >= 0) {
            addLogicalLine(logical, raw, start, end);
        }
        if (logical.size() > properties.getLimits().getMaxHeaders()) {
            throw new MailParseException(
                    "header count exceeds " + properties.getLimits().getMaxHeaders(), true);
        }
        return logical;
    }

    private void addLogicalLine(List<int[]> logical, byte[] raw, int start, int end) {
        if (end - start > properties.getLimits().getMaxHeaderLineBytes()) {
            throw new MailParseException("header line exceeds max bytes", true);
        }
        logical.add(new int[]{start, end});
    }

    /** 去掉物理行尾换行，保留折行处的 WSP（值中的折叠空白由规范化层处理）。 */
    private String unfold(byte[] raw, int start, int end) {
        StringBuilder builder = new StringBuilder(end - start);
        int i = start;
        while (i < end) {
            byte current = raw[i];
            if (current == '\r' && i + 1 < end && raw[i + 1] == '\n') {
                i += 2;
                continue;
            }
            if (current == '\n' || current == '\r') {
                i++;
                continue;
            }
            builder.append((char) (current & 0xff));
            i++;
        }
        return builder.toString();
    }

    private int indexOfColon(byte[] raw, int start, int end) {
        for (int i = start; i < end; i++) {
            if (raw[i] == ':') {
                return i;
            }
        }
        return -1;
    }

    private static String stripLeadingWsp(String value) {
        int index = 0;
        while (index < value.length() && (value.charAt(index) == ' ' || value.charAt(index) == '\t')) {
            index++;
        }
        return value.substring(index);
    }

    private boolean isValidFieldName(String name) {
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c <= ' ' || c >= 0x7f) {
                return false;
            }
        }
        return true;
    }

    private String trimTrailingLineBreaks(String value) {
        int end = value.length();
        while (end > 0) {
            char c = value.charAt(end - 1);
            if (c == '\r' || c == '\n') {
                end--;
            } else {
                break;
            }
        }
        return value.substring(0, end);
    }
}

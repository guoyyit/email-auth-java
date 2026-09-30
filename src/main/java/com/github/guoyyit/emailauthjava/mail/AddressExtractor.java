package com.github.guoyyit.emailauthjava.mail;

/**
 * 从 From/SMTP Mail From（helo 可选）中提取本地部分与域。
 */
public final class AddressExtractor {

    private AddressExtractor() {
    }

    /** 提取 From 头部中的首个地址域（小写）。非法返回 null。 */
    public static String fromDomain(ParsedMail mail) {
        if (mail == null) {
            return null;
        }
        String from = mail.getFirstHeader("From");
        if (from == null) {
            return null;
        }
        String address = firstAddressSpec(from);
        if (address == null) {
            return null;
        }
        int at = address.lastIndexOf('@');
        if (at < 0 || at == address.length() - 1) {
            return null;
        }
        String domain = address.substring(at + 1).trim().toLowerCase(java.util.Locale.ROOT);
        return isValidDomain(domain) ? stripTrailingDot(domain) : null;
    }

    /** 从 RFC5321 路径（如 {@code <user@example.com>} 或 postmaster）提取域。 */
    public static String smtpDomain(String path) {
        if (path == null) {
            return null;
        }
        String trimmed = path.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        int open = trimmed.indexOf('<');
        int close = trimmed.lastIndexOf('>');
        if (open >= 0 && close > open) {
            trimmed = trimmed.substring(open + 1, close).trim();
        }
        if (trimmed.isEmpty()) {
            return null;
        }
        int colon = trimmed.indexOf(':');
        if (colon >= 0) {
            String localPartPrefix = trimmed.substring(0, colon).toLowerCase(java.util.Locale.ROOT);
            if (!localPartPrefix.equals("postmaster")) {
                trimmed = trimmed.substring(colon + 1);
            }
        }
        int at = trimmed.lastIndexOf('@');
        if (at < 0 || at == trimmed.length() - 1) {
            return null;
        }
        String domain = trimmed.substring(at + 1).trim().toLowerCase(java.util.Locale.ROOT);
        return isValidDomain(domain) ? stripTrailingDot(domain) : null;
    }

    private static String firstAddressSpec(String rawFrom) {
        String value = rawFrom;
        int close = value.lastIndexOf('>');
        if (close >= 0) {
            int open = value.lastIndexOf('<', close - 1);
            if (open >= 0) {
                value = value.substring(open + 1, close);
            }
        }
        int comma = value.indexOf(',');
        if (comma >= 0) {
            value = value.substring(0, comma);
        }
        value = value.trim();
        if (value.isEmpty() || value.indexOf('@') < 0) {
            return null;
        }
        return value;
    }

    private static boolean isValidDomain(String domain) {
        if (domain.isEmpty() || domain.length() > 253) {
            return false;
        }
        String[] labels = domain.split("\\.", -1);
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63) {
                return false;
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                boolean alphaNum = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
                if (!alphaNum) {
                    return false;
                }
            }
        }
        return true;
    }

    private static String stripTrailingDot(String domain) {
        while (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }
        return domain;
    }
}

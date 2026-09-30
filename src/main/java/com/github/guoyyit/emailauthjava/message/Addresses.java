package com.github.guoyyit.emailauthjava.message;

import java.util.Locale;

/**
 * 从含显示名、注释与空白的地址头值（From、Return-Path 等）中提取地址与域名。
 */
public final class Addresses {
    private Addresses() {
    }

    public static String extractAddress(String headerValue) {
        if (headerValue == null) {
            return null;
        }
        String value = stripComments(headerValue).trim();
        int angleOpen = value.lastIndexOf('<');
        if (angleOpen >= 0) {
            int angleClose = value.indexOf('>', angleOpen);
            if (angleClose > angleOpen) {
                String inside = value.substring(angleOpen + 1, angleClose).trim();
                int colon = inside.indexOf(':');
                if (colon >= 0) {
                    inside = inside.substring(colon + 1).trim();
                }
                return inside.isEmpty() ? null : inside;
            }
        }
        if (value.indexOf('@') >= 0) {
            return value;
        }
        return null;
    }

    public static String domainOf(String email) {
        if (email == null) {
            return null;
        }
        int at = email.lastIndexOf('@');
        if (at < 0 || at == email.length() - 1) {
            return null;
        }
        return email.substring(at + 1).trim().toLowerCase(Locale.ROOT);
    }

    private static String stripComments(String value) {
        StringBuilder builder = new StringBuilder(value.length());
        int depth = 0;
        boolean quoted = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' && i + 1 < value.length()) {
                if (depth == 0) {
                    builder.append(c).append(value.charAt(i + 1));
                }
                i++;
                continue;
            }
            if (c == '"') {
                quoted = !quoted;
                if (depth == 0) {
                    builder.append(c);
                }
                continue;
            }
            if (!quoted && c == '(') {
                depth++;
                continue;
            }
            if (!quoted && c == ')' && depth > 0) {
                depth--;
                continue;
            }
            if (depth == 0) {
                builder.append(c);
            }
        }
        return builder.toString();
    }
}

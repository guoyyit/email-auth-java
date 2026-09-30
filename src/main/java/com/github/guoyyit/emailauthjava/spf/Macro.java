package com.github.guoyyit.emailauthjava.spf;

import java.util.Locale;

/**
 * 最小 SPF 宏展开（RFC 7208 §7）。支持 %{x}、%%、%_、%-，
 * 数字截断 r 与反转；本服务的发件人本地部分来自固定上下文。
 */
final class Macro {

    private Macro() {
    }

    /** SPF 宏展开所需的发件会话视图。 */
    interface ContextLike {
        String sender();

        String localPart();

        String senderDomain();

        String clientIp();

        String heloDomain();
    }

    static String expand(String input, Macro.ContextLike context, String currentDomain) {
        if (input == null) {
            return null;
        }
        StringBuilder out = new StringBuilder(input.length());
        int i = 0;
        while (i < input.length()) {
            char c = input.charAt(i);
            if (c != '%') {
                out.append(c);
                i++;
                continue;
            }
            if (i + 1 >= input.length()) {
                out.append(c);
                break;
            }
            char next = input.charAt(i + 1);
            if (next == '%') {
                out.append('%');
                i += 2;
            } else if (next == '_') {
                out.append(' ');
                i += 2;
            } else if (next == '-') {
                out.append("%20");
                i += 2;
            } else if (next == '{') {
                int end = input.indexOf('}', i + 2);
                if (end < 0) {
                    throw new IllegalArgumentException("unterminated macro");
                }
                out.append(expandMacro(input.substring(i + 2, end), context, currentDomain));
                i = end + 1;
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    private static String expandMacro(String spec, Macro.ContextLike context,
                                      String currentDomain) {
        if (spec.isEmpty()) {
            throw new IllegalArgumentException("empty macro");
        }
        char letter = spec.charAt(0);
        int pos = 1;
        int digits = 0;
        while (pos < spec.length() && Character.isDigit(spec.charAt(pos))) {
            digits = digits * 10 + (spec.charAt(pos) - '0');
            pos++;
        }
        boolean reverse = false;
        while (pos < spec.length() && spec.charAt(pos) == 'r') {
            reverse = true;
            pos++;
        }
        String delimiter;
        if (pos < spec.length() && !spec.substring(pos).isEmpty()) {
            String requested = spec.substring(pos);
            delimiter = String.valueOf(requested.charAt(0));
        } else {
            delimiter = (letter == 'l' || letter == 's') ? "." : ".";
        }

        String value = switch (Character.toLowerCase(letter)) {
            case 's' -> context.sender();
            case 'l' -> context.localPart();
            case 'o' -> context.senderDomain();
            case 'd' -> context.senderDomain();
            case 'i' -> context.clientIp();
            case 'p' -> context.clientIp();
            case 'v' -> context.clientIp().contains(":") ? "ip6" : "in-addr";
            case 'h' -> context.heloDomain() == null ? context.senderDomain() : context.heloDomain();
            default -> throw new IllegalArgumentException("unsupported macro letter " + letter);
        };
        value = value == null ? "" : value;

        boolean splitDomain = letter == 'd' || letter == 'p' || letter == 'o'
                || letter == 'h' || letter == 's';
        if (splitDomain) {
            String[] parts = value.split(java.util.regex.Pattern.quote(delimiter), -1);
            if (reverse) {
                reverseArray(parts);
            }
            if (digits > 0 && digits < parts.length) {
                String[] cut = new String[digits];
                System.arraycopy(parts, 0, cut, 0, digits);
                parts = cut;
            }
            value = String.join(".", parts);
        }
        return value.toLowerCase(Locale.ROOT);
    }

    private static void reverseArray(String[] parts) {
        for (int left = 0, right = parts.length - 1; left < right; left++, right--) {
            String tmp = parts[left];
            parts[left] = parts[right];
            parts[right] = tmp;
        }
    }
}

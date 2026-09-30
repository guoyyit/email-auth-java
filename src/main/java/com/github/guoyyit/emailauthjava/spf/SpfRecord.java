package com.github.guoyyit.emailauthjava.spf;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 解析后的一条 SPF 记录（RFC 7208）。保持机制在记录中的出现顺序。
 */
final class SpfRecord {

    final List<Term> terms;

    private SpfRecord(List<Term> terms) {
        this.terms = List.copyOf(terms);
    }

    /** 返回首个同名修饰符值（如 redirect），不存在返回 null。 */
    String modifier(String name) {
        for (Term term : terms) {
            if (term.isModifier && term.mechanism.equalsIgnoreCase(name)) {
                return term.argument;
            }
        }
        return null;
    }

    static SpfRecord parse(String text, long maxBytes) {
        if (text == null) {
            throw new IllegalArgumentException("null SPF record");
        }
        if (text.length() > maxBytes) {
            throw new IllegalArgumentException("SPF record exceeds max DNS response bytes");
        }
        String[] tokens = text.trim().split("\\s+");
        if (tokens.length == 0 || !tokens[0].equalsIgnoreCase("v=spf1")) {
            throw new IllegalArgumentException("not an SPF record");
        }
        List<Term> terms = new ArrayList<>();
        boolean redirectSeen = false;
        for (int i = 1; i < tokens.length; i++) {
            String token = tokens[i];
            if (token.isEmpty()) {
                continue;
            }
            int equals = token.indexOf('=');
            int slash = token.indexOf('/');
            int colon = token.indexOf(':');
            boolean modifier = equals > 0
                    && (colon < 0 || equals < colon)
                    && (slash < 0 || equals < slash);
            if (modifier) {
                String name = token.substring(0, equals).toLowerCase(Locale.ROOT);
                String value = token.substring(equals + 1);
                if (name.equals("redirect")) {
                    if (redirectSeen) {
                        throw new IllegalArgumentException("duplicate redirect modifier");
                    }
                    redirectSeen = true;
                }
                terms.add(Term.modifier(name, value));
                continue;
            }

            int offset = 0;
            Qualifier qualifier = Qualifier.PASS;
            char first = token.charAt(0);
            switch (first) {
                case '+':
                    qualifier = Qualifier.PASS;
                    offset = 1;
                    break;
                case '-':
                    qualifier = Qualifier.FAIL;
                    offset = 1;
                    break;
                case '~':
                    qualifier = Qualifier.SOFTFAIL;
                    offset = 1;
                    break;
                case '?':
                    qualifier = Qualifier.NEUTRAL;
                    offset = 1;
                    break;
                default:
                    break;
            }
            String rest = token.substring(offset);
            String mechanism;
            String argument = null;
            int sep = rest.indexOf(':');
            if (sep >= 0) {
                mechanism = rest.substring(0, sep).toLowerCase(Locale.ROOT);
                argument = rest.substring(sep + 1);
            } else {
                int slashPos = rest.indexOf('/');
                if (slashPos >= 0 && (rest.startsWith("ip4") || rest.startsWith("ip6"))) {
                    mechanism = rest.substring(0, slashPos).toLowerCase(Locale.ROOT);
                    argument = rest.substring(slashPos + 1);
                } else if (slashPos >= 0 && (rest.startsWith("a") || rest.startsWith("mx"))) {
                    mechanism = rest.substring(0, slashPos).toLowerCase(Locale.ROOT);
                    argument = rest.substring(slashPos);
                } else {
                    mechanism = rest.toLowerCase(Locale.ROOT);
                }
            }
            if (mechanism.isEmpty()) {
                throw new IllegalArgumentException("empty mechanism");
            }
            terms.add(Term.mechanism(qualifier, mechanism, argument));
        }
        return new SpfRecord(terms);
    }
}

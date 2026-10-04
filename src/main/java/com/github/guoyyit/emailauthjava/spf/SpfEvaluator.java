package com.github.guoyyit.emailauthjava.spf;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dns.DnsResolver;
import com.github.guoyyit.emailauthjava.dns.DnsResult;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.error.AuthError;
import com.github.guoyyit.emailauthjava.error.ResourceLimitException;
import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * RFC 7208 SPF 策略求值。机制 ip4/ip6/a/mx/include/all 与 redirect 修饰符；
 * 限定符 +(pass) -(fail) ~(softfail) ?(neutral)。
 * include 递归有深度上限与环路检测，DNS 查询有总次数预算；
 * NXDOMAIN/TIMEOUT/MALFORMED 分别映射 none/temperror/permerror。
 */
@Component
public class SpfEvaluator {
    private static final int MAX_MX_HOSTS = 10;

    private final DnsResolver dnsResolver;
    private final AuthProperties properties;

    public SpfEvaluator(DnsResolver dnsResolver, AuthProperties properties) {
        this.dnsResolver = dnsResolver;
        this.properties = properties;
    }

    public SpfResult evaluate(String heloDomain, String clientIp, String envelopeFrom) {
        return evaluateWith(dnsResolver, heloDomain, clientIp, envelopeFrom);
    }

    public DnsResolver getSharedResolver() {
        return dnsResolver;
    }

    public SpfResult evaluateWith(DnsResolver resolver, String heloDomain, String clientIp,
                                  String envelopeFrom) {
        String sender = (envelopeFrom == null || envelopeFrom.isBlank())
                ? "postmaster@" + normalize(heloDomain) : envelopeFrom.trim();
        String senderDomain = afterAt(sender);
        if (senderDomain == null || !isValidDomain(senderDomain)) {
            return new SpfResult(SpfStatus.PERMERROR, "invalid sender domain", null);
        }
        byte[] clientBytes = IpAddresses.parse(clientIp);
        if (clientBytes == null) {
            return new SpfResult(SpfStatus.PERMERROR, "invalid client ip " + clientIp, null);
        }
        Context context = new Context(resolver, clientBytes, clientIp.indexOf(':') >= 0);
        try {
            return checkHost(senderDomain, context, new ArrayDeque<>(), new HashSet<>());
        } catch (DnsFailureException e) {
            return new SpfResult(e.status, e.getMessage(), null);
        } catch (ResourceLimitException e) {
            return new SpfResult(SpfStatus.PERMERROR, e.getMessage(), null);
        }
    }

    private SpfResult checkHost(String domain, Context context, Deque<String> chain,
                                Set<String> ancestors) {
        if (chain.size() >= properties.getLimits().getMaxIncludeDepth()) {
            throw new ResourceLimitException(AuthError.INCLUDE_DEPTH_EXCEEDED,
                    "include depth exceeds " + properties.getLimits().getMaxIncludeDepth());
        }
        String normalized = normalize(domain);
        if (ancestors.contains(normalized)) {
            return new SpfResult(SpfStatus.PERMERROR,
                    "include loop detected at " + normalized, normalized);
        }
        ancestors.add(normalized);
        chain.addLast(normalized);
        try {
            String record = fetchSpfRecord(normalized, context);
            if (record == null) {
                return new SpfResult(SpfStatus.NONE, "no SPF record", normalized);
            }
            List<Term> terms = parseTerms(record);
            String redirect = null;
            for (Term term : terms) {
                if (term.modifier) {
                    if ("redirect".equals(term.name) && redirect == null) {
                        redirect = term.argument;
                    }
                    continue;
                }
                if ("include".equals(term.name)) {
                    SpfStatus includeStatus = evaluateInclude(term, context, chain, ancestors);
                    if (includeStatus == SpfStatus.PASS) {
                        return new SpfResult(qualifierStatus(term.qualifier),
                                "matched include:" + term.argument, term.argument);
                    }
                    if (includeStatus == SpfStatus.TEMPERROR
                            || includeStatus == SpfStatus.PERMERROR) {
                        return new SpfResult(includeStatus,
                                "include " + term.argument + " returned " + includeStatus,
                                term.argument);
                    }
                    continue;
                }
                if (matches(term, normalized, context)) {
                    return new SpfResult(qualifierStatus(term.qualifier),
                            "matched " + term.name, normalized);
                }
            }
            if (redirect != null) {
                if (!isValidDomain(redirect)) {
                    return new SpfResult(SpfStatus.PERMERROR,
                            "invalid redirect target " + redirect, normalized);
                }
                return checkHost(redirect, context, chain, ancestors);
            }
            return new SpfResult(SpfStatus.NEUTRAL, "no mechanism matched", normalized);
        } finally {
            chain.removeLast();
        }
    }

    private SpfStatus evaluateInclude(Term term, Context context, Deque<String> chain,
                                      Set<String> ancestors) {
        if (term.argument == null || !isValidDomain(term.argument)) {
            return SpfStatus.PERMERROR;
        }
        // 祖先集合在整条 include 链上共享，环路在首次重复进入的域上被检测。
        SpfResult nested = checkHost(term.argument, context, chain, ancestors);
        return switch (nested.getStatus()) {
            case PASS -> SpfStatus.PASS;
            case NONE, NEUTRAL, SOFTFAIL, FAIL -> null;
            case TEMPERROR -> SpfStatus.TEMPERROR;
            default -> SpfStatus.PERMERROR;
        };
    }

    private String fetchSpfRecord(String domain, Context context) {
        DnsResult result = query(domain, RecordType.TXT, context);
        if (result.getStatus() == DnsStatus.NXDOMAIN) {
            return null;
        }
        if (result.getStatus() != DnsStatus.OK) {
            throw new DnsFailureException(failureStatus(result.getStatus()),
                    "TXT lookup for " + domain + " returned " + result.getStatus());
        }
        String found = null;
        for (String txt : result.getRecords()) {
            String candidate = txt == null ? "" : txt.trim();
            String lower = candidate.toLowerCase(Locale.ROOT);
            if (lower.equals("v=spf1") || lower.startsWith("v=spf1 ")) {
                if (found != null) {
                    throw new DnsFailureException(SpfStatus.PERMERROR,
                            "multiple SPF records at " + domain);
                }
                found = candidate;
            }
        }
        return found;
    }

    private boolean matches(Term term, String currentDomain, Context context) {
        return switch (term.name) {
            case "all" -> true;
            case "ip4" -> matchesIp4(term, context);
            case "ip6" -> matchesIp6(term, context);
            case "a" -> matchesHostRecord(term, currentDomain, context);
            case "mx" -> matchesMx(term, currentDomain, context);
            default -> throw new DnsFailureException(SpfStatus.PERMERROR,
                    "unknown mechanism " + term.name);
        };
    }

    private boolean matchesIp4(Term term, Context context) {
        if (context.clientIsV6 || term.argument == null) {
            return false;
        }
        byte[] network = IpAddresses.parseIpv4(term.argument);
        if (network == null) {
            throw new DnsFailureException(SpfStatus.PERMERROR, "invalid ip4 " + term.argument);
        }
        int prefix = term.ip4Cidr == null ? 32 : term.ip4Cidr;
        return IpAddresses.prefixMatch(context.clientBytes, network, prefix);
    }

    private boolean matchesIp6(Term term, Context context) {
        if (!context.clientIsV6 || term.argument == null) {
            return false;
        }
        byte[] network = IpAddresses.parseIpv6(term.argument);
        if (network == null) {
            throw new DnsFailureException(SpfStatus.PERMERROR, "invalid ip6 " + term.argument);
        }
        int prefix = term.ip6Cidr == null ? 128 : term.ip6Cidr;
        return IpAddresses.prefixMatch(context.clientBytes, network, prefix);
    }

    private boolean matchesHostRecord(Term term, String currentDomain, Context context) {
        String target = term.argument != null ? term.argument : currentDomain;
        if (!isValidDomain(target)) {
            throw new DnsFailureException(SpfStatus.PERMERROR, "invalid domain " + target);
        }
        RecordType type = context.clientIsV6 ? RecordType.AAAA : RecordType.A;
        DnsResult result = query(target, type, context);
        if (result.getStatus() != DnsStatus.OK) {
            if (result.getStatus() == DnsStatus.TIMEOUT) {
                throw new DnsFailureException(SpfStatus.TEMPERROR,
                        type + " lookup timeout for " + target);
            }
            return false;
        }
        int prefix = context.clientIsV6
                ? (term.ip6Cidr == null ? 128 : term.ip6Cidr)
                : (term.ip4Cidr == null ? 32 : term.ip4Cidr);
        for (String address : result.getRecords()) {
            byte[] candidate = context.clientIsV6
                    ? IpAddresses.parseIpv6(address) : IpAddresses.parseIpv4(address);
            if (candidate != null
                    && IpAddresses.prefixMatch(context.clientBytes, candidate, prefix)) {
                return true;
            }
        }
        return false;
    }

    private boolean matchesMx(Term term, String currentDomain, Context context) {
        String target = term.argument != null ? term.argument : currentDomain;
        DnsResult mx = query(target, RecordType.MX, context);
        if (mx.getStatus() != DnsStatus.OK) {
            if (mx.getStatus() == DnsStatus.TIMEOUT) {
                throw new DnsFailureException(SpfStatus.TEMPERROR, "MX timeout for " + target);
            }
            return false;
        }
        if (mx.getExchangeNames().size() > MAX_MX_HOSTS) {
            throw new DnsFailureException(SpfStatus.PERMERROR,
                    "more than " + MAX_MX_HOSTS + " MX hosts for " + target);
        }
        for (String exchange : mx.getExchangeNames()) {
            if (matchesExchangeAddresses(term, exchange, context)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 以 MX 交换主机名查询其 A/AAAA 记录并与客户端 IP 比对。
     * 目标固定为交换主机本身，绝不回退到 mx 机制参数域；
     * CIDR 前缀仍取自 mx 机制上的 /cidr 或 //cidr。
     */
    private boolean matchesExchangeAddresses(Term term, String exchange, Context context) {
        String target = normalize(exchange);
        if (!isValidDomain(target)) {
            throw new DnsFailureException(SpfStatus.PERMERROR,
                    "invalid MX exchange " + exchange);
        }
        RecordType type = context.clientIsV6 ? RecordType.AAAA : RecordType.A;
        DnsResult result = query(target, type, context);
        if (result.getStatus() != DnsStatus.OK) {
            if (result.getStatus() == DnsStatus.TIMEOUT) {
                throw new DnsFailureException(SpfStatus.TEMPERROR,
                        type + " lookup timeout for MX exchange " + target);
            }
            return false;
        }
        int prefix = context.clientIsV6
                ? (term.ip6Cidr == null ? 128 : term.ip6Cidr)
                : (term.ip4Cidr == null ? 32 : term.ip4Cidr);
        for (String address : result.getRecords()) {
            byte[] candidate = context.clientIsV6
                    ? IpAddresses.parseIpv6(address) : IpAddresses.parseIpv4(address);
            if (candidate != null
                    && IpAddresses.prefixMatch(context.clientBytes, candidate, prefix)) {
                return true;
            }
        }
        return false;
    }

    private DnsResult query(String domain, RecordType type, Context context) {
        if (++context.queryCount > properties.getLimits().getMaxDnsQueries()) {
            throw new ResourceLimitException(AuthError.DNS_QUERY_LIMIT_EXCEEDED,
                    "DNS query budget " + properties.getLimits().getMaxDnsQueries()
                            + " exhausted");
        }
        return context.resolver.resolve(normalize(domain), type);
    }

    private SpfStatus qualifierStatus(char qualifier) {
        return switch (qualifier) {
            case '+' -> SpfStatus.PASS;
            case '-' -> SpfStatus.FAIL;
            case '~' -> SpfStatus.SOFTFAIL;
            default -> SpfStatus.NEUTRAL;
        };
    }

    private SpfStatus failureStatus(DnsStatus status) {
        return status == DnsStatus.TIMEOUT ? SpfStatus.TEMPERROR : SpfStatus.PERMERROR;
    }

    private List<Term> parseTerms(String record) {
        List<Term> terms = new ArrayList<>();
        String[] parts = record.split("\\s+");
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i];
            if (part.isEmpty()) {
                continue;
            }
            int equals = part.indexOf('=');
            if (equals > 0 && !part.startsWith("/")) {
                Term term = new Term();
                term.modifier = true;
                term.name = part.substring(0, equals).toLowerCase(Locale.ROOT);
                term.argument = part.substring(equals + 1);
                terms.add(term);
            } else {
                terms.add(parseMechanism(part));
            }
        }
        return terms;
    }

    private Term parseMechanism(String part) {
        Term term = new Term();
        char first = part.charAt(0);
        if (first == '+' || first == '-' || first == '~' || first == '?') {
            term.qualifier = first;
            part = part.substring(1);
        }
        int colon = part.indexOf(':');
        int slash = part.indexOf('/');
        int nameEnd = part.length();
        if (colon >= 0) {
            nameEnd = Math.min(nameEnd, colon);
        }
        if (slash >= 0) {
            nameEnd = Math.min(nameEnd, slash);
        }
        term.name = part.substring(0, nameEnd).toLowerCase(Locale.ROOT);
        String rest = part.substring(nameEnd);
        if (rest.startsWith(":")) {
            String argumentAndCidr = rest.substring(1);
            int cidrAt = argumentAndCidr.indexOf('/');
            if (cidrAt >= 0) {
                term.argument = argumentAndCidr.substring(0, cidrAt);
                applyCidr(term, argumentAndCidr.substring(cidrAt));
            } else {
                term.argument = argumentAndCidr;
            }
        } else if (!rest.isEmpty()) {
            applyCidr(term, rest);
        }
        validateTerm(term);
        return term;
    }

    private void applyCidr(Term term, String cidrText) {
        String text = cidrText;
        if (text.startsWith("//")) {
            term.ip6Cidr = parseIntCidr(text.substring(2));
            return;
        }
        if (text.startsWith("/")) {
            text = text.substring(1);
        }
        int secondSlash = text.indexOf('/');
        if (secondSlash >= 0) {
            term.ip4Cidr = parseIntCidr(text.substring(0, secondSlash));
            term.ip6Cidr = parseIntCidr(text.substring(secondSlash + 1));
        } else if ("ip6".equals(term.name)) {
            term.ip6Cidr = parseIntCidr(text);
        } else {
            term.ip4Cidr = parseIntCidr(text);
        }
    }

    private int parseIntCidr(String text) {
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException e) {
            throw new DnsFailureException(SpfStatus.PERMERROR, "invalid CIDR " + text);
        }
    }

    private void validateTerm(Term term) {
        switch (term.name) {
            case "all" -> {
                if (term.argument != null || term.ip4Cidr != null || term.ip6Cidr != null) {
                    throw new DnsFailureException(SpfStatus.PERMERROR, "invalid all mechanism");
                }
            }
            case "ip4" -> validateCidr(term.argument, term.ip4Cidr, 32);
            case "ip6" -> validateCidr(term.argument, term.ip6Cidr, 128);
            case "a", "mx" -> validateDualCidr(term);
            case "include" -> {
                if (term.argument == null || !isValidDomain(term.argument)) {
                    throw new DnsFailureException(SpfStatus.PERMERROR,
                            "invalid include target " + term.argument);
                }
            }
            default -> throw new DnsFailureException(SpfStatus.PERMERROR,
                    "unknown mechanism " + term.name);
        }
    }

    private void validateCidr(String argument, Integer cidr, int max) {
        if (argument == null || cidr != null && (cidr < 0 || cidr > max)) {
            throw new DnsFailureException(SpfStatus.PERMERROR, "invalid CIDR " + cidr);
        }
    }

    private void validateDualCidr(Term term) {
        if (term.ip4Cidr != null && (term.ip4Cidr < 0 || term.ip4Cidr > 32)) {
            throw new DnsFailureException(SpfStatus.PERMERROR,
                    "invalid ip4 CIDR " + term.ip4Cidr);
        }
        if (term.ip6Cidr != null && (term.ip6Cidr < 0 || term.ip6Cidr > 128)) {
            throw new DnsFailureException(SpfStatus.PERMERROR,
                    "invalid ip6 CIDR " + term.ip6Cidr);
        }
    }

    private static String normalize(String domain) {
        if (domain == null) {
            return "";
        }
        String value = domain.trim().toLowerCase(Locale.ROOT);
        if (value.endsWith(".")) {
            value = value.substring(0, value.length() - 1);
        }
        return value;
    }

    private static String afterAt(String email) {
        int at = email.lastIndexOf('@');
        if (at < 0 || at == email.length() - 1) {
            return null;
        }
        return email.substring(at + 1);
    }

    static boolean isValidDomain(String domain) {
        if (domain == null || domain.isEmpty() || domain.length() > 253) {
            return false;
        }
        String[] labels = domain.split("\\.", -1);
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63) {
                return false;
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                boolean asciiAlphaNum = (c >= 'a' && c <= 'z')
                        || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
                if (!asciiAlphaNum) {
                    return false;
                }
            }
            if (label.startsWith("-") || label.endsWith("-")) {
                return false;
            }
        }
        return true;
    }

    private static final class Context {
        private final DnsResolver resolver;
        private final byte[] clientBytes;
        private final boolean clientIsV6;
        private int queryCount;

        private Context(DnsResolver resolver, byte[] clientBytes, boolean clientIsV6) {
            this.resolver = resolver;
            this.clientBytes = clientBytes;
            this.clientIsV6 = clientIsV6;
        }
    }

    private static final class Term {
        private String name;
        private String argument;
        private char qualifier = '+';
        private Integer ip4Cidr;
        private Integer ip6Cidr;
        private boolean modifier;
    }

    private static final class DnsFailureException extends RuntimeException {
        private final SpfStatus status;

        private DnsFailureException(SpfStatus status, String message) {
            super(message);
            this.status = status;
        }
    }
}

package com.github.guoyyit.emailauthjava.spf;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dns.DnsAnswer;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.dns.DnsRecord;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.mail.AddressExtractor;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * SPF 策略求值（RFC 7208）。
 * 支持 ip4/ip6/a/mx/include/redirect/all（并容忍 exists）与四种限定符；
 * include 递归有深度上限与环路检测；DNS 故障稳定映射到 temperror/permerror。
 */
public class SpfEvaluator {

    private static final String SPF_VERSION = "v=spf1";

    private final DnsCache dnsCache;
    private final AuthProperties properties;

    public SpfEvaluator(DnsCache dnsCache, AuthProperties properties) {
        this.dnsCache = dnsCache;
        this.properties = properties;
    }

    /**
     * @param clientIp 字面量 IPv4/IPv6
     * @param heloDomain HELO/EHLO 域（可空）
     * @param mailFrom SMTP MAIL FROM 路径（null/空表示 null sender，回退 HELO）
     */
    public SpfResult evaluate(String clientIp, String heloDomain, String mailFrom) {
        return evaluate(dnsCache.beginSnapshot(), clientIp, heloDomain, mailFrom);
    }

    /** 在给定 DNS 快照版本上求值，保证单次评估一致性。 */
    public SpfResult evaluate(long snapshotVersion, String clientIp, String heloDomain,
                              String mailFrom) {
        InetAddress client = parseIp(clientIp);
        if (client == null) {
            return SpfResult.of(SpfStatus.PERMERROR, "invalid client ip: " + clientIp);
        }
        String domain;
        if (mailFrom != null && !mailFrom.isBlank()) {
            domain = AddressExtractor.smtpDomain(mailFrom);
            if (domain == null) {
                String trimmed = mailFrom.trim().toLowerCase(Locale.ROOT);
                if (trimmed.equals("postmaster") || trimmed.equals("<postmaster>")) {
                    domain = normalizeDomain(heloDomain);
                }
            }
        } else {
            domain = normalizeDomain(heloDomain);
        }
        if (domain == null) {
            return SpfResult.of(SpfStatus.NONE, "no usable sender domain");
        }

        Context context = new Context(client, domain, heloDomain, mailFrom, snapshotVersion);
        try {
            SpfRecord record = fetchRecord(context, domain);
            if (record == null) {
                return context.noneOrVoid("no SPF record at " + domain);
            }
            return evaluateRecord(context, domain, record);
        } catch (QueryBudgetException ex) {
            return SpfResult.of(SpfStatus.PERMERROR, ex.getMessage());
        }
    }

    private SpfResult evaluateRecord(Context context, String domain, SpfRecord record) {
        context.chain.addLast(domain);
        try {
            for (Term term : record.terms) {
                if (term.isModifier) {
                    continue;
                }
                MechanismMatch match = evaluateMechanism(context, domain, term);
                if (match == MechanismMatch.NOT_APPLICABLE) {
                    continue;
                }
                if (match == MechanismMatch.MATCH) {
                    context.matched.add(
                            term.qualifier.name().toLowerCase(Locale.ROOT) + ":" + term.mechanism);
                    return SpfResult.of(term.qualifier.result,
                            "matched " + term.mechanism, context.matched);
                }
                if (match == MechanismMatch.TEMP_ERROR) {
                    return SpfResult.of(SpfStatus.TEMPERROR,
                            "temporary DNS error in " + term.mechanism);
                }
                if (match == MechanismMatch.PERM_ERROR) {
                    return SpfResult.of(SpfStatus.PERMERROR,
                            "permanent error in " + term.mechanism);
                }
            }

            String redirect = record.modifier("redirect");
            if (redirect != null) {
                return followRedirect(context, redirect);
            }
            return SpfResult.of(SpfStatus.NEUTRAL, "no mechanism matched");
        } finally {
            context.chain.removeLast();
        }
    }

    private SpfResult followRedirect(Context context, String targetDomain) {
        String normalized = normalizeDomain(Macro.expand(targetDomain, context, context.senderDomain));
        if (normalized == null) {
            return SpfResult.of(SpfStatus.PERMERROR,
                    "invalid redirect target: " + targetDomain);
        }
        if (context.chain.contains(normalized)) {
            return SpfResult.of(SpfStatus.PERMERROR, "redirect loop: " + normalized);
        }
        if (context.chain.size() >= properties.getSpf().getMaxIncludeDepth()) {
            return SpfResult.of(SpfStatus.PERMERROR, "redirect depth exceeded");
        }
        SpfRecord target = fetchRecord(context, normalized);
        if (target == null) {
            return context.noneOrVoid(
                    "redirect target has no SPF record: " + normalized);
        }
        return evaluateRecord(context, normalized, target);
    }

    private MechanismMatch evaluateMechanism(Context context, String currentDomain, Term term) {
        switch (term.mechanism) {
            case "all":
                return MechanismMatch.MATCH;
            case "ip4":
                return matchIp4(context.client, term.argument);
            case "ip6":
                return matchIp6(context.client, term.argument);
            case "a":
                return matchHost(context, term.argument, currentDomain, false);
            case "mx":
                return matchHost(context, term.argument, currentDomain, true);
            case "include":
                return matchInclude(context, term.argument);
            case "exists":
                return matchExists(context, term.argument, currentDomain);
            default:
                return MechanismMatch.PERM_ERROR;
        }
    }

    private SpfRecord fetchRecord(Context context, String domain) {
        DnsAnswer answer = context.query(domain, RecordType.TXT);
        if (answer.getStatus() == DnsStatus.TIMEOUT) {
            context.tempFailure = true;
            return null;
        }
        if (answer.getStatus() == DnsStatus.MALFORMED) {
            context.permFailure = true;
            return null;
        }
        if (answer.getStatus() != DnsStatus.OK) {
            context.registerVoid();
            return null;
        }
        List<String> spfRecords = new ArrayList<>();
        for (DnsRecord record : answer.getRecords()) {
            String text = record.getText();
            if (text != null && isSpfRecord(text)) {
                spfRecords.add(text);
            }
        }
        if (spfRecords.isEmpty()) {
            context.registerVoid();
            return null;
        }
        if (spfRecords.size() > 1) {
            context.permFailure = true;
            return null;
        }
        try {
            return SpfRecord.parse(spfRecords.get(0),
                    properties.getLimits().getMaxDnsResponseBytes());
        } catch (IllegalArgumentException ex) {
            context.permFailure = true;
            return null;
        }
    }

    private static boolean isSpfRecord(String text) {
        String trimmed = text.trim().toLowerCase(Locale.ROOT);
        return trimmed.equals(SPF_VERSION) || trimmed.startsWith(SPF_VERSION + " ");
    }

    private MechanismMatch matchIp4(InetAddress client, String cidr) {
        if (!(client instanceof Inet4Address) || cidr == null) {
            return MechanismMatch.NOT_APPLICABLE;
        }
        String[] parts = cidr.split("/", -1);
        InetAddress network = parseIp(parts[0]);
        if (!(network instanceof Inet4Address) || parts.length > 2) {
            return MechanismMatch.PERM_ERROR;
        }
        int prefix = 32;
        if (parts.length == 2) {
            prefix = parsePrefix(parts[1], 32);
            if (prefix < 0) {
                return MechanismMatch.PERM_ERROR;
            }
        }
        return sameNetwork(client.getAddress(), network.getAddress(), prefix)
                ? MechanismMatch.MATCH : MechanismMatch.NOT_APPLICABLE;
    }

    private MechanismMatch matchIp6(InetAddress client, String cidr) {
        if (!(client instanceof Inet6Address) || cidr == null) {
            return MechanismMatch.NOT_APPLICABLE;
        }
        String[] parts = cidr.split("/", -1);
        InetAddress network = parseIp(parts[0]);
        if (!(network instanceof Inet6Address) || parts.length > 2) {
            return MechanismMatch.PERM_ERROR;
        }
        int prefix = 128;
        if (parts.length == 2) {
            prefix = parsePrefix(parts[1], 128);
            if (prefix < 0) {
                return MechanismMatch.PERM_ERROR;
            }
        }
        return sameNetwork(client.getAddress(), network.getAddress(), prefix)
                ? MechanismMatch.MATCH : MechanismMatch.NOT_APPLICABLE;
    }

    private MechanismMatch matchHost(Context context, String argument,
                                     String currentDomain, boolean mx) {
        HostSpec spec = parseHostArg(argument, context, currentDomain);
        if (spec == null) {
            return MechanismMatch.PERM_ERROR;
        }
        List<InetAddress> addresses = new ArrayList<>();
        if (mx) {
            DnsAnswer mxAnswer = context.query(spec.domain, RecordType.MX);
            if (mxAnswer.getStatus() == DnsStatus.TIMEOUT) {
                return MechanismMatch.TEMP_ERROR;
            }
            if (mxAnswer.getStatus() == DnsStatus.MALFORMED) {
                return MechanismMatch.PERM_ERROR;
            }
            if (mxAnswer.getStatus() == DnsStatus.OK) {
                Set<String> exchanges = new HashSet<>();
                for (DnsRecord record : mxAnswer.getRecords()) {
                    String exchange = normalizeDomain(record.getExchange());
                    if (exchange == null) {
                        return MechanismMatch.PERM_ERROR;
                    }
                    if (!exchanges.add(exchange)) {
                        continue;
                    }
                    MechanismMatch collected = collectAddresses(context, exchange, addresses);
                    if (collected != MechanismMatch.NOT_APPLICABLE) {
                        return collected;
                    }
                }
            } else {
                context.registerVoid();
            }
        } else {
            MechanismMatch collected = collectAddresses(context, spec.domain, addresses);
            if (collected != MechanismMatch.NOT_APPLICABLE) {
                return collected;
            }
        }
        int prefix = context.client instanceof Inet6Address ? spec.cidr6 : spec.cidr4;
        for (InetAddress address : addresses) {
            if (address.getClass() != context.client.getClass()) {
                continue;
            }
            if (sameNetwork(context.client.getAddress(), address.getAddress(), prefix)) {
                return MechanismMatch.MATCH;
            }
        }
        return MechanismMatch.NOT_APPLICABLE;
    }

    private MechanismMatch collectAddresses(Context context, String domain,
                                            List<InetAddress> sink) {
        DnsAnswer v4 = context.query(domain, RecordType.A);
        if (v4.getStatus() == DnsStatus.TIMEOUT) {
            return MechanismMatch.TEMP_ERROR;
        }
        if (v4.getStatus() == DnsStatus.MALFORMED) {
            return MechanismMatch.PERM_ERROR;
        }
        if (v4.getStatus() == DnsStatus.OK) {
            for (DnsRecord record : v4.getRecords()) {
                InetAddress address = parseIp(record.getAddress());
                if (address instanceof Inet4Address) {
                    sink.add(address);
                }
            }
        } else {
            context.registerVoid();
        }
        DnsAnswer v6 = context.query(domain, RecordType.AAAA);
        if (v6.getStatus() == DnsStatus.TIMEOUT) {
            return MechanismMatch.TEMP_ERROR;
        }
        if (v6.getStatus() == DnsStatus.MALFORMED) {
            return MechanismMatch.PERM_ERROR;
        }
        if (v6.getStatus() == DnsStatus.OK) {
            for (DnsRecord record : v6.getRecords()) {
                InetAddress address = parseIp(record.getAddress());
                if (address instanceof Inet6Address) {
                    sink.add(address);
                }
            }
        } else {
            context.registerVoid();
        }
        return MechanismMatch.NOT_APPLICABLE;
    }

    private MechanismMatch matchInclude(Context context, String targetDomain) {
        if (targetDomain == null) {
            return MechanismMatch.PERM_ERROR;
        }
        String normalized = normalizeDomain(Macro.expand(targetDomain, context, context.chain.peekLast()));
        if (normalized == null) {
            return MechanismMatch.PERM_ERROR;
        }
        if (context.chain.contains(normalized)) {
            return MechanismMatch.PERM_ERROR;
        }
        if (context.chain.size() >= properties.getSpf().getMaxIncludeDepth()) {
            return MechanismMatch.PERM_ERROR;
        }
        SpfRecord included = fetchRecord(context, normalized);
        if (included == null) {
            return MechanismMatch.NOT_APPLICABLE;
        }
        SpfResult nested = evaluateRecord(context, normalized, included);
        switch (nested.getStatus()) {
            case PASS:
                return MechanismMatch.MATCH;
            case TEMPERROR:
                return MechanismMatch.TEMP_ERROR;
            case PERMERROR:
                return MechanismMatch.PERM_ERROR;
            default:
                return MechanismMatch.NOT_APPLICABLE;
        }
    }

    private MechanismMatch matchExists(Context context, String argument, String currentDomain) {
        if (argument == null) {
            return MechanismMatch.PERM_ERROR;
        }
        String target = normalizeDomain(Macro.expand(argument, context, currentDomain));
        if (target == null) {
            return MechanismMatch.PERM_ERROR;
        }
        DnsAnswer answer = context.query(target, RecordType.A);
        switch (answer.getStatus()) {
            case OK:
                for (DnsRecord record : answer.getRecords()) {
                    if (parseIp(record.getAddress()) instanceof Inet4Address) {
                        return MechanismMatch.MATCH;
                    }
                }
                return MechanismMatch.NOT_APPLICABLE;
            case TIMEOUT:
                return MechanismMatch.TEMP_ERROR;
            case MALFORMED:
                return MechanismMatch.PERM_ERROR;
            default:
                context.registerVoid();
                return MechanismMatch.NOT_APPLICABLE;
        }
    }

    private HostSpec parseHostArg(String argument, Context context, String currentDomain) {
        String targetDomain = currentDomain;
        int cidr4 = 32;
        int cidr6 = 128;
        if (argument != null && !argument.isBlank()) {
            String trimmed = argument.trim();
            String[] tokens;
            if (trimmed.startsWith("/")) {
                tokens = new String[]{trimmed};
            } else {
                tokens = trimmed.split("(?=/)", -1);
            }
            if (!tokens[0].startsWith("/")) {
                String expanded = Macro.expand(tokens[0], context, currentDomain);
                targetDomain = normalizeDomain(expanded);
                if (targetDomain == null) {
                    return null;
                }
            }
            for (int idx = tokens[0].startsWith("/") ? 0 : 1; idx < tokens.length; idx++) {
                String cidrToken = tokens[idx];
                if (!cidrToken.startsWith("/")) {
                    return null;
                }
                String body = cidrToken.substring(1);
                String[] dual = body.split("/", -1);
                int parsed4 = parsePrefix(dual[0], 32);
                if (parsed4 < 0) {
                    return null;
                }
                cidr4 = parsed4;
                if (dual.length == 2) {
                    int parsed6 = parsePrefix(dual[1], 128);
                    if (parsed6 < 0) {
                        return null;
                    }
                    cidr6 = parsed6;
                } else if (dual.length > 2) {
                    return null;
                }
            }
        }
        return new HostSpec(targetDomain, cidr4, cidr6);
    }

    private static int parsePrefix(String value, int max) {
        try {
            int prefix = Integer.parseInt(value.trim());
            if (prefix < 0 || prefix > max) {
                return -1;
            }
            return prefix;
        } catch (NumberFormatException ex) {
            return -1;
        }
    }

    private static boolean sameNetwork(byte[] client, byte[] network, int prefixLength) {
        if (client.length != network.length) {
            return false;
        }
        int fullBytes = prefixLength / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (client[i] != network[i]) {
                return false;
            }
        }
        int remainingBits = prefixLength % 8;
        if (remainingBits == 0 || fullBytes >= client.length) {
            return true;
        }
        int mask = (0xff00 >> remainingBits) & 0xff;
        return (client[fullBytes] & mask) == (network[fullBytes] & mask);
    }

    private record HostSpec(String domain, int cidr4, int cidr6) {
    }

    private enum MechanismMatch {
        MATCH,
        NOT_APPLICABLE,
        TEMP_ERROR,
        PERM_ERROR
    }

    private static final class QueryBudgetException extends RuntimeException {
        private QueryBudgetException(String message) {
            super(message);
        }
    }

    /**
     * 单次 SPF 求值的可变上下文：查询预算、空应答计数、include 链与命中机制。
     */
    private final class Context implements Macro.ContextLike {
        private final InetAddress client;
        private final String senderDomain;
        private final String heloDomain;
        private final String localPart;
        private final long snapshotVersion;
        private final Deque<String> chain = new ArrayDeque<>();
        private final Set<String> visitedDomains = new HashSet<>();
        private final List<String> matched = new ArrayList<>();
        private int queryCount;
        private int voidLookups;
        private boolean tempFailure;
        private boolean permFailure;

        private Context(InetAddress client, String senderDomain, String heloDomain,
                        String mailFrom, long snapshotVersion) {
            this.client = client;
            this.senderDomain = senderDomain;
            this.snapshotVersion = snapshotVersion;
            this.heloDomain = normalizeDomain(heloDomain);
            String local = "postmaster";
            if (mailFrom != null && !mailFrom.isBlank()) {
                String path = mailFrom.trim();
                int open = path.indexOf('<');
                int close = path.lastIndexOf('>');
                if (open >= 0 && close > open) {
                    path = path.substring(open + 1, close);
                }
                int at = path.lastIndexOf('@');
                if (at > 0) {
                    local = path.substring(0, at);
                }
            }
            this.localPart = local;
        }

        private DnsAnswer query(String name, RecordType type) {
            if (queryCount >= properties.getSpf().getMaxDnsQueries()) {
                throw new QueryBudgetException(
                        "SPF DNS query limit exceeded: " + properties.getSpf().getMaxDnsQueries());
            }
            queryCount++;
            return dnsCache.queryAtVersion(snapshotVersion, name, type);
        }

        private void registerVoid() {
            voidLookups++;
        }

        private SpfResult noneOrVoid(String explanation) {
            if (tempFailure) {
                return SpfResult.of(SpfStatus.TEMPERROR, explanation);
            }
            if (permFailure) {
                return SpfResult.of(SpfStatus.PERMERROR, explanation);
            }
            if (voidLookups > properties.getSpf().getMaxVoidLookups()) {
                return SpfResult.of(SpfStatus.PERMERROR,
                        "void lookup limit exceeded (" + voidLookups + ")");
            }
            return SpfResult.of(SpfStatus.NONE, explanation);
        }

        @Override
        public String sender() {
            return localPart + "@" + senderDomain;
        }

        @Override
        public String localPart() {
            return localPart;
        }

        @Override
        public String senderDomain() {
            return senderDomain;
        }

        @Override
        public String clientIp() {
            return client.getHostAddress();
        }

        @Override
        public String heloDomain() {
            return heloDomain;
        }
    }

    private static InetAddress parseIp(String literal) {
        if (literal == null || literal.isBlank()) {
            return null;
        }
        try {
            return InetAddress.getByName(literal.trim());
        } catch (UnknownHostException ex) {
            return null;
        }
    }

    private static String normalizeDomain(String domain) {
        if (domain == null) {
            return null;
        }
        String trimmed = domain.trim().toLowerCase(Locale.ROOT);
        while (trimmed.endsWith(".")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        if (trimmed.isEmpty() || trimmed.length() > 253) {
            return null;
        }
        return trimmed;
    }
}

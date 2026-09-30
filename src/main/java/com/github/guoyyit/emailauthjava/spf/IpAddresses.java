package com.github.guoyyit.emailauthjava.spf;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * 字面量 IPv4/IPv6 解析与 CIDR 前缀匹配，不依赖 DNS。
 */
final class IpAddresses {
    private IpAddresses() {
    }

    static byte[] parse(String text) {
        if (text == null) {
            return null;
        }
        return text.indexOf(':') >= 0 ? parseIpv6(text) : parseIpv4(text);
    }

    static byte[] parseIpv4(String text) {
        if (text == null) {
            return null;
        }
        String[] parts = text.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            String part = parts[i];
            if (part.isEmpty() || part.length() > 3) {
                return null;
            }
            for (int j = 0; j < part.length(); j++) {
                if (!Character.isDigit(part.charAt(j))) {
                    return null;
                }
            }
            int value = Integer.parseInt(part);
            if (value > 255 || (part.length() > 1 && part.charAt(0) == '0')) {
                return null;
            }
            bytes[i] = (byte) value;
        }
        return bytes;
    }

    static byte[] parseIpv6(String text) {
        if (text == null || text.indexOf(':') < 0) {
            return null;
        }
        String value = text;
        int percent = value.indexOf('%');
        if (percent >= 0) {
            value = value.substring(0, percent);
        }
        if (value.startsWith("[") || value.endsWith("]")) {
            return null;
        }
        try {
            InetAddress address = InetAddress.getByName(value);
            if (address instanceof Inet6Address && !(address instanceof Inet4Address)) {
                return address.getAddress();
            }
        } catch (UnknownHostException e) {
            return null;
        }
        return null;
    }

    static boolean prefixMatch(byte[] candidate, byte[] network, int prefixLength) {
        if (candidate.length != network.length || prefixLength < 0
                || prefixLength > network.length * 8) {
            return false;
        }
        int fullBytes = prefixLength / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (candidate[i] != network[i]) {
                return false;
            }
        }
        int remaining = prefixLength % 8;
        if (remaining > 0) {
            int mask = 0xFF << (8 - remaining);
            return (candidate[fullBytes] & mask) == (network[fullBytes] & mask);
        }
        return true;
    }
}

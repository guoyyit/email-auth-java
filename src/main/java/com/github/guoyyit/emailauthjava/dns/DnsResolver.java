package com.github.guoyyit.emailauthjava.dns;

public interface DnsResolver {
    DnsResult resolve(String domain, RecordType type);
}

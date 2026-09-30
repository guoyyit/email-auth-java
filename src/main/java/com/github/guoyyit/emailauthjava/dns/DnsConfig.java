package com.github.guoyyit.emailauthjava.dns;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;

@Configuration
public class DnsConfig {
    @Bean
    public MapBackedDnsResolver mapBackedDnsResolver() {
        return new MapBackedDnsResolver(new HashMap<>());
    }

    @Bean
    public DnsResolver dnsResolver(MapBackedDnsResolver mapBackedDnsResolver, AuthProperties properties) {
        return new CachingDnsResolver(mapBackedDnsResolver, properties);
    }
}

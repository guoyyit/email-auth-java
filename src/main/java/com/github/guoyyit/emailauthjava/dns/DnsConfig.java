package com.github.guoyyit.emailauthjava.dns;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PreDestroy;
import java.util.HashMap;

@Configuration
public class DnsConfig {
    private TimedDnsResolver timedDnsResolver;

    @Bean
    public MapBackedDnsResolver mapBackedDnsResolver() {
        return new MapBackedDnsResolver(new HashMap<>());
    }

    @Bean
    public TimedDnsResolver timedDnsResolver(MapBackedDnsResolver mapBackedDnsResolver,
                                             AuthProperties properties) {
        this.timedDnsResolver = new TimedDnsResolver(mapBackedDnsResolver, properties);
        return this.timedDnsResolver;
    }

    @Bean
    public DnsResolver dnsResolver(TimedDnsResolver timedDnsResolver, AuthProperties properties) {
        return new CachingDnsResolver(timedDnsResolver, properties);
    }

    @PreDestroy
    void shutdownResolverPool() {
        if (timedDnsResolver != null) {
            timedDnsResolver.close();
        }
    }
}

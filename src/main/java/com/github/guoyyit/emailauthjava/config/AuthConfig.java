package com.github.guoyyit.emailauthjava.config;

import com.github.guoyyit.emailauthjava.dkim.DkimEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.DmarcEvaluator;
import com.github.guoyyit.emailauthjava.dmarc.OrganizationalDomain;
import com.github.guoyyit.emailauthjava.dns.DnsCache;
import com.github.guoyyit.emailauthjava.dns.DnsResolver;
import com.github.guoyyit.emailauthjava.dns.InMemoryDnsResolver;
import com.github.guoyyit.emailauthjava.eval.AuthService;
import com.github.guoyyit.emailauthjava.mail.MailParser;
import com.github.guoyyit.emailauthjava.report.AggregateStore;
import com.github.guoyyit.emailauthjava.report.ReportGenerator;
import com.github.guoyyit.emailauthjava.spf.SpfEvaluator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Bean 装配。默认提供空的内存 DNS 解析器（不依赖真实网络）；
 * 接入方只需提供自己的 {@link DnsResolver} Bean 即可覆盖默认值。
 */
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthConfig {

    @Bean
    @ConditionalOnMissingBean
    public DnsResolver dnsResolver() {
        return new InMemoryDnsResolver();
    }

    @Bean
    public DnsCache dnsCache(DnsResolver dnsResolver, AuthProperties properties) {
        return new DnsCache(dnsResolver, properties);
    }

    @Bean
    public MailParser mailParser(AuthProperties properties) {
        return new MailParser(properties);
    }

    @Bean
    public SpfEvaluator spfEvaluator(DnsCache dnsCache, AuthProperties properties) {
        return new SpfEvaluator(dnsCache, properties);
    }

    @Bean
    public DkimEvaluator dkimEvaluator(DnsCache dnsCache, AuthProperties properties) {
        return new DkimEvaluator(dnsCache, properties);
    }

    @Bean
    public OrganizationalDomain organizationalDomain(AuthProperties properties) {
        return new OrganizationalDomain(properties);
    }

    @Bean
    public DmarcEvaluator dmarcEvaluator(DnsCache dnsCache, AuthProperties properties,
                                         OrganizationalDomain organizationalDomain) {
        return new DmarcEvaluator(dnsCache, properties, organizationalDomain);
    }

    @Bean
    public AggregateStore aggregateStore(AuthProperties properties) {
        return new AggregateStore(properties);
    }

    @Bean
    public ReportGenerator reportGenerator(AuthProperties properties) {
        return new ReportGenerator(properties.getReport().getReportReceiver());
    }

    @Bean
    public AuthService authService(MailParser mailParser, SpfEvaluator spfEvaluator,
                                   DkimEvaluator dkimEvaluator, DmarcEvaluator dmarcEvaluator,
                                   AggregateStore aggregateStore, DnsCache dnsCache) {
        return new AuthService(mailParser, spfEvaluator, dkimEvaluator, dmarcEvaluator,
                aggregateStore, dnsCache);
    }
}

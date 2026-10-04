package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dns.CachingDnsResolver;
import com.github.guoyyit.emailauthjava.dns.DnsResult;
import com.github.guoyyit.emailauthjava.dns.DnsStatus;
import com.github.guoyyit.emailauthjava.dns.MapBackedDnsResolver;
import com.github.guoyyit.emailauthjava.dns.RecordType;
import com.github.guoyyit.emailauthjava.dns.TimedDnsResolver;
import com.github.guoyyit.emailauthjava.spf.SpfEvaluator;
import com.github.guoyyit.emailauthjava.spf.SpfStatus;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SpfTimeoutIntegrationTest {

    @Test
    void timeoutConfigTruncatesSlowSpfLookupAndDefaultRestores() {
        AuthProperties properties = new AuthProperties();
        properties.getDns().setTimeoutCacheTtlSeconds(0L);
        MapBackedDnsResolver backend = new MapBackedDnsResolver(new HashMap<>());
        backend.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ip4:192.0.2.1 -all"));
        TimedDnsResolver timed = new TimedDnsResolver(backend, properties);
        CachingDnsResolver caching = new CachingDnsResolver(timed, properties);
        SpfEvaluator evaluator = new SpfEvaluator(caching, properties);

        // 默认 3000ms 下正常返回。
        assertThat(evaluator.evaluate("h", "1.2.3.4", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);

        // 调小超时并让底层 TXT 查询变慢：必须被截断为 temperror，且快速返回。
        properties.getDns().setTimeoutMillis(50);
        MapBackedDnsResolver slow = new MapBackedDnsResolver(new HashMap<>()) {
            @Override
            public DnsResult resolveAt(String domain, RecordType type, long version) {
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return super.resolveAt(domain, type, version);
            }
        };
        slow.put("example.com", RecordType.TXT, DnsStatus.OK,
                List.of("v=spf1 ip4:192.0.2.1 -all"));
        TimedDnsResolver slowTimed = new TimedDnsResolver(slow, properties);
        CachingDnsResolver slowCaching = new CachingDnsResolver(slowTimed, properties);
        SpfEvaluator slowEvaluator = new SpfEvaluator(slowCaching, properties);

        long begin = System.nanoTime();
        SpfStatus status = slowEvaluator.evaluate("h", "1.2.3.4", "a@example.com").getStatus();
        long elapsedMillis = (System.nanoTime() - begin) / 1_000_000;
        assertThat(status).isEqualTo(SpfStatus.TEMPERROR);
        assertThat(elapsedMillis).isLessThan(1000);

        // 恢复默认值后，快路径重新正常工作（不再误判超时）。
        properties.getDns().setTimeoutMillis(3000);
        assertThat(evaluator.evaluate("h", "1.2.3.4", "a@example.com").getStatus())
                .isEqualTo(SpfStatus.FAIL);

        timed.close();
        slowTimed.close();
    }
}

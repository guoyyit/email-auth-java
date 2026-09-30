package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.report.AggregateBucket;
import com.github.guoyyit.emailauthjava.report.AggregateKey;
import com.github.guoyyit.emailauthjava.report.AggregateStore;
import com.github.guoyyit.emailauthjava.report.ReportGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AggregateStoreTest {

    private AuthProperties properties(Path dir) {
        AuthProperties properties = new AuthProperties();
        properties.getReport().setStoreDir(dir.resolve("aggregate").toString());
        return properties;
    }

    @Test
    void sameMessageCountedOnceWithinPeriod(@TempDir Path dir) {
        AggregateStore store = new AggregateStore(properties(dir));
        AggregateKey key = new AggregateKey(
                "<id@x>", "1.2.3.4", "example.com", Instant.now());
        assertTrue(store.record(key, Instant.now(), "fail", "example.com",
                "none", null, "reject"));
        assertEquals(false, store.record(key, Instant.now(), "fail", "example.com",
                "none", null, "reject"));
        List<AggregateBucket> buckets = store.bucketsFor("example.com");
        assertEquals(1, buckets.size());
        assertEquals(1, buckets.get(0).getCount());
    }

    @Test
    void dataSurvivesRestart(@TempDir Path dir) {
        AuthProperties props = properties(dir);
        AggregateStore first = new AggregateStore(props);
        first.record(new AggregateKey("<persist@x>", "9.9.9.9", "example.com", Instant.now()),
                Instant.now(), "fail", "example.com", "pass", "example.com", "quarantine");

        AggregateStore second = new AggregateStore(props);
        List<AggregateBucket> buckets = second.bucketsFor("example.com");
        assertEquals(1, buckets.size());
        assertEquals(1, buckets.get(0).getCount());
        assertEquals("9.9.9.9", buckets.get(0).getKey().getSourceIp());
    }

    @Test
    void restartDoesNotDoubleCountDuplicates(@TempDir Path dir) {
        AuthProperties props = properties(dir);
        AggregateKey key = new AggregateKey("<dup@x>", "5.5.5.5", "example.com", Instant.now());
        AggregateStore first = new AggregateStore(props);
        first.record(key, Instant.now(), "fail", "example.com", "none", null, "reject");

        AggregateStore second = new AggregateStore(props);
        assertEquals(false, second.record(key, Instant.now(), "fail", "example.com",
                "none", null, "reject"));
        assertEquals(1, second.bucketsFor("example.com").get(0).getCount());
    }

    @Test
    void generatesValidXmlReport(@TempDir Path dir) {
        AggregateStore store = new AggregateStore(properties(dir));
        store.record(new AggregateKey("<r@x>", "203.0.113.7", "example.com", Instant.now()),
                Instant.now(), "fail", "example.com", "fail", "example.com", "reject");
        List<AggregateBucket> buckets = store.bucketsFor("example.com");
        String xml = new ReportGenerator("receiver.example").generateXml(
                "example.com", "rid", Instant.now().minusSeconds(3600), Instant.now(), buckets);
        assertTrue(xml.contains("<feedback>"));
        assertTrue(xml.contains("<source_ip>203.0.113.7</source_ip>"));
        assertTrue(xml.contains("<disposition>reject</disposition>"));
        assertTrue(xml.contains("<header_from>example.com</header_from>"));
    }

    @Test
    void commitClearsBuckets(@TempDir Path dir) {
        AggregateStore store = new AggregateStore(properties(dir));
        store.record(new AggregateKey("<c@x>", "1.1.1.1", "example.com", Instant.now()),
                Instant.now(), "fail", "example.com", "none", null, "reject");
        store.markReported("example.com");
        assertEquals(0, store.bucketsFor("example.com").size());
    }
}

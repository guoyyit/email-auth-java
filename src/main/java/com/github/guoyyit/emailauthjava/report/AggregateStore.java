package com.github.guoyyit.emailauthjava.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.emailauthjava.config.AuthProperties;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 聚合反馈数据存储：内存聚合 + 磁盘持久化（每条事件 fsync）。
 * 重启后从日志恢复未提交数据；同一邮件（周期内）去重。
 * 报告周期按 UTC 日划分，键为 policyDomain|date。
 */
public class AggregateStore {

    private final AuthProperties properties;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<StorageKey, BucketState> store = new ConcurrentHashMap<>();

    public AggregateStore(AuthProperties properties) {
        this.properties = properties;
        recover();
    }

    /**
     * 记录一封邮件；返回 true 表示新计入，false 表示周期内重复而被忽略。
     */
    public boolean record(AggregateKey key, Instant seen, String spfResult, String spfDomain,
                          String dkimResult, String dkimDomain, String disposition) {
        StorageKey storageKey = new StorageKey(
                normalizeDomain(key.getFromDomain()), utcDate(seen));
        BucketState state = store.computeIfAbsent(storageKey, BucketState::new);
        synchronized (state) {
            if (state.keys.containsKey(dedupeIdentity(key))) {
                return false;
            }
            PersistedEvent event = new PersistedEvent(
                    key.getMessageId(), key.getSourceIp(), key.getFromDomain(),
                    seen.toEpochMilli(), spfResult, spfDomain, dkimResult, dkimDomain, disposition);
            appendDurably(storageKey, event);
            AggregateBucket bucket = state.buckets.computeIfAbsent(
                    key.getSourceIp(), ip -> new AggregateBucket(
                            new AggregateKey(
                                    key.getMessageId(), key.getSourceIp(),
                                    key.getFromDomain(), key.getFirstSeen())));
            bucket.record(seen, spfResult, spfDomain, dkimResult, dkimDomain, disposition);
            state.keys.put(dedupeIdentity(key), Boolean.TRUE);
            return true;
        }
    }

    /** 某发件域当前周期（今天）未提交的聚合桶。 */
    public List<AggregateBucket> bucketsFor(String policyDomain) {
        StorageKey key = new StorageKey(normalizeDomain(policyDomain),
                utcDate(Instant.now()));
        BucketState state = store.get(key);
        if (state == null) {
            return List.of();
        }
        synchronized (state) {
            return List.copyOf(state.buckets.values());
        }
    }

    /** 标记某域当前周期报告已生成（提交后清空内存与日志）。 */
    public void markReported(String policyDomain) {
        StorageKey key = new StorageKey(normalizeDomain(policyDomain),
                utcDate(Instant.now()));
        BucketState state = store.remove(key);
        if (state == null) {
            return;
        }
        synchronized (state) {
            try {
                Files.deleteIfExists(logPath(key));
            } catch (IOException ex) {
                throw new ReportPersistenceException("failed to delete report log", ex);
            }
        }
    }

    private void appendDurably(StorageKey storageKey, PersistedEvent event) {
        if (!properties.getReport().isEnabled()) {
            return;
        }
        try {
            Path directory = Path.of(properties.getReport().getStoreDir());
            Files.createDirectories(directory);
            Path logFile = directory.resolve(fileName(storageKey));
            byte[] payload = (mapper.writeValueAsString(event) + "\n")
                    .getBytes(StandardCharsets.UTF_8);
            try (OutputStream output = Files.newOutputStream(logFile,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND)) {
                output.write(payload);
                output.flush();
                if (output instanceof java.io.FileOutputStream fileOutput) {
                    fileOutput.getFD().sync();
                }
            }
        } catch (IOException ex) {
            throw new ReportPersistenceException("failed to persist aggregate event", ex);
        }
    }

    private void recover() {
        if (!properties.getReport().isEnabled()) {
            return;
        }
        Path directory = Path.of(properties.getReport().getStoreDir());
        if (!Files.isDirectory(directory)) {
            return;
        }
        try (var stream = Files.list(directory)) {
            stream.filter(path -> path.getFileName().toString().endsWith(".log"))
                    .forEach(this::recoverFile);
        } catch (IOException ex) {
            throw new ReportPersistenceException("failed to recover aggregate data", ex);
        }
    }

    private void recoverFile(Path file) {
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                PersistedEvent event = mapper.readValue(line, PersistedEvent.class);
                Instant seen = Instant.ofEpochMilli(event.seenEpochMillis);
                AggregateKey key = new AggregateKey(
                        event.messageId, event.sourceIp, event.fromDomain, seen);
                StorageKey storageKey = new StorageKey(
                        normalizeDomain(event.fromDomain), utcDate(seen));
                BucketState state = store.computeIfAbsent(storageKey, BucketState::new);
                synchronized (state) {
                    if (state.keys.putIfAbsent(dedupeIdentity(key), Boolean.TRUE) != null) {
                        continue;
                    }
                    AggregateBucket bucket = state.buckets.computeIfAbsent(
                            event.sourceIp, ip -> new AggregateBucket(key));
                    bucket.record(seen, event.spfResult, event.spfDomain,
                            event.dkimResult, event.dkimDomain, event.disposition);
                }
            }
        } catch (IOException ex) {
            throw new ReportPersistenceException("corrupt aggregate log: " + file, ex);
        }
    }

    private Path logPath(StorageKey key) {
        return Path.of(properties.getReport().getStoreDir())
                .resolve(fileName(key));
    }

    private static String fileName(StorageKey key) {
        return "aggregate-" + key.policyDomain() + "-" + key.date() + ".log";
    }

    private static String dedupeIdentity(AggregateKey key) {
        return String.join("|",
                nullToEmpty(key.getMessageId()),
                nullToEmpty(key.getSourceIp()),
                nullToEmpty(key.getFromDomain()));
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String normalizeDomain(String domain) {
        if (domain == null) {
            return "_unknown";
        }
        return domain.trim().toLowerCase(Locale.ROOT);
    }

    private static String utcDate(Instant instant) {
        return java.time.LocalDate.ofInstant(instant, java.time.ZoneOffset.UTC).toString();
    }

    private record StorageKey(String policyDomain, String date) {
    }

    private static final class BucketState {
        private final StorageKey key;
        private final Map<String, AggregateBucket> buckets = new ConcurrentHashMap<>();
        private final Map<String, Boolean> keys = new ConcurrentHashMap<>();

        private BucketState(StorageKey key) {
            this.key = key;
        }
    }

    private static final class PersistedEvent {
        public String messageId;
        public String sourceIp;
        public String fromDomain;
        public long seenEpochMillis;
        public String spfResult;
        public String spfDomain;
        public String dkimResult;
        public String dkimDomain;
        public String disposition;

        PersistedEvent() {
        }

        PersistedEvent(String messageId, String sourceIp, String fromDomain, long seenEpochMillis,
                       String spfResult, String spfDomain, String dkimResult,
                       String dkimDomain, String disposition) {
            this.messageId = messageId;
            this.sourceIp = sourceIp;
            this.fromDomain = fromDomain;
            this.seenEpochMillis = seenEpochMillis;
            this.spfResult = spfResult;
            this.spfDomain = spfDomain;
            this.dkimResult = dkimResult;
            this.dkimDomain = dkimDomain;
            this.disposition = disposition;
        }
    }
}

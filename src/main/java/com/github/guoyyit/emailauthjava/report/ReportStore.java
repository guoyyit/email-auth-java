package com.github.guoyyit.emailauthjava.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dkim.DkimStatus;
import com.github.guoyyit.emailauthjava.dmarc.DmarcResult;
import com.github.guoyyit.emailauthjava.service.EvaluationResult;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 按 DMARC 策略域聚合未通过认证的邮件。
 * 内存映射 + JSON 文件持久化（临时文件 + 原子移动），重启后自动恢复，未提交数据不丢失；
 * 同一 messageId 在一个报告周期内只计入一次。
 */
@Component
public class ReportStore {
    private final AuthProperties properties;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<String, ReportAggregate> aggregates = new ConcurrentHashMap<>();
    private final Path storageDir;

    public ReportStore(AuthProperties properties) {
        this.properties = properties;
        this.storageDir = Path.of(properties.getReport().getStoragePath());
        load();
    }

    public void record(String sourceIp, EvaluationResult result) {
        if (result == null || result.getDmarc() == null
                || result.getMessageId() == null) {
            return;
        }
        DmarcResult dmarc = result.getDmarc();
        boolean passed = dmarc.isSpfAligned() || dmarc.isDkimAligned();
        if (passed) {
            return;
        }
        String domain = dmarc.getPolicyDomain();
        if (domain == null) {
            domain = "unknown";
        }
        long now = System.currentTimeMillis();
        ReportAggregate aggregate = aggregates.compute(domain, (key, existing) -> {
            long interval = properties.getReport().getIntervalSeconds() * 1000L;
            if (existing == null || now >= existing.getPeriodEnd()) {
                existing = newAggregate(key, now, interval);
            }
            return existing;
        });
        ReportEntry entry = toEntry(sourceIp, result, now);
        boolean added;
        synchronized (aggregate) {
            added = aggregate.add(entry);
        }
        if (added) {
            persist(domain, aggregate);
        }
    }

    public String flushDueReport(String domain) {
        ReportAggregate aggregate = aggregates.get(domain);
        if (aggregate == null || aggregate.entryList().isEmpty()) {
            return null;
        }
        boolean due = System.currentTimeMillis() >= aggregate.getPeriodEnd();
        if (!due) {
            return null;
        }
        String xml = new AggregateReportGenerator().generateXml(domain, aggregate.entryList());
        archive(domain, aggregate, xml);
        long interval = properties.getReport().getIntervalSeconds() * 1000L;
        ReportAggregate fresh = newAggregate(domain, System.currentTimeMillis(), interval);
        aggregates.put(domain, fresh);
        persist(domain, fresh);
        return xml;
    }

    public ReportAggregate peek(String domain) {
        return aggregates.get(domain);
    }

    private ReportAggregate newAggregate(String domain, long now, long interval) {
        ReportAggregate aggregate = new ReportAggregate();
        aggregate.setDomain(domain);
        aggregate.setPeriodStart(now);
        aggregate.setPeriodEnd(now + interval);
        return aggregate;
    }

    private ReportEntry toEntry(String sourceIp, EvaluationResult result, long now) {
        ReportEntry entry = new ReportEntry();
        entry.setMessageId(result.getMessageId());
        entry.setSourceIp(sourceIp);
        entry.setHeaderFrom(result.getHeaderFrom());
        entry.setTimestamp(now);
        if (result.getSpf() != null) {
            entry.setSpfStatus(result.getSpf().getStatus().name().toLowerCase());
        }
        List<DkimResult> dkim = result.getDkim();
        if (dkim != null && !dkim.isEmpty()) {
            DkimResult best = dkim.stream()
                    .min(Comparator.comparingInt(result2 -> statusRank(result2.getStatus())))
                    .orElse(dkim.get(0));
            entry.setDkimStatus(best.getStatus().name().toLowerCase());
        }
        DmarcResult dmarc = result.getDmarc();
        entry.setSpfAligned(Boolean.toString(dmarc.isSpfAligned()));
        entry.setDkimAligned(Boolean.toString(dmarc.isDkimAligned()));
        entry.setDisposition(dmarc.getDisposition().name().toLowerCase());
        return entry;
    }

    private int statusRank(DkimStatus status) {
        return switch (status) {
            case PASS -> 0;
            case NONE -> 1;
            case TEMPERROR -> 2;
            case FAIL -> 3;
            case PERMERROR -> 4;
        };
    }

    private synchronized void persist(String domain, ReportAggregate aggregate) {
        try {
            Files.createDirectories(storageDir);
            Path target = aggregateFile(domain);
            Path temp = target.resolveSibling(target.getFileName() + ".tmp");
            byte[] payload = objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsBytes(aggregate);
            Files.write(temp, payload);
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to persist report aggregate", e);
        }
    }

    private void archive(String domain, ReportAggregate aggregate, String xml) {
        try {
            Path archiveDir = storageDir.resolve("archived");
            Files.createDirectories(archiveDir);
            String fileName = domain + "-" + aggregate.getPeriodStart() + ".xml";
            Files.writeString(archiveDir.resolve(fileName), xml);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to archive report", e);
        }
    }

    private void load() {
        try {
            if (!Files.isDirectory(storageDir)) {
                return;
            }
            try (var paths = Files.list(storageDir)) {
                paths.filter(path -> path.getFileName().toString().endsWith(".json"))
                        .forEach(this::loadFile);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("failed to load report aggregates", e);
        }
    }

    private void loadFile(Path file) {
        try {
            ReportAggregate aggregate = objectMapper.readValue(file.toFile(),
                    ReportAggregate.class);
            if (aggregate.getDomain() != null) {
                aggregates.put(aggregate.getDomain(), aggregate);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read " + file, e);
        }
    }

    private Path aggregateFile(String domain) {
        return storageDir.resolve(domain.replaceAll("[^a-z0-9._-]", "_") + ".json");
    }
}

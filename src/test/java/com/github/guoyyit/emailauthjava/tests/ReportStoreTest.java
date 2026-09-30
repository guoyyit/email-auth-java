package com.github.guoyyit.emailauthjava.tests;

import com.github.guoyyit.emailauthjava.config.AuthProperties;
import com.github.guoyyit.emailauthjava.dkim.DkimResult;
import com.github.guoyyit.emailauthjava.dkim.DkimStatus;
import com.github.guoyyit.emailauthjava.dmarc.DmarcDisposition;
import com.github.guoyyit.emailauthjava.dmarc.DmarcResult;
import com.github.guoyyit.emailauthjava.report.AggregateReportGenerator;
import com.github.guoyyit.emailauthjava.report.ReportStore;
import com.github.guoyyit.emailauthjava.service.EvaluationResult;
import com.github.guoyyit.emailauthjava.spf.SpfResult;
import com.github.guoyyit.emailauthjava.spf.SpfStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ReportStoreTest {

    @TempDir
    Path tempDir;

    @Test
    void deduplicatesSameMessageWithinPeriod() {
        ReportStore store = new ReportStore(properties());
        store.record("1.2.3.4", failedResult("id-1", "example.com"));
        store.record("1.2.3.4", failedResult("id-1", "example.com"));
        store.record("5.6.7.8", failedResult("id-2", "example.com"));

        assertThat(store.peek("example.com").entryList()).hasSize(2);
    }

    @Test
    void ignoresAuthenticatedMail() {
        ReportStore store = new ReportStore(properties());
        EvaluationResult result = result("id-1", "example.com", true);
        store.record("1.2.3.4", result);
        assertThat(store.peek("example.com")).isNull();
    }

    @Test
    void survivesRestartAndGeneratesXml() {
        AuthProperties properties = properties();
        ReportStore first = new ReportStore(properties);
        first.record("1.2.3.4", failedResult("id-9", "example.com"));

        ReportStore second = new ReportStore(properties);
        assertThat(second.peek("example.com").entryList()).hasSize(1);

        String xml = new AggregateReportGenerator().generateXml("example.com",
                second.peek("example.com").entryList());
        assertThat(xml).contains("<feedback", "<source_ip>1.2.3.4</source_ip>",
                "<disposition>reject</disposition>", "<result>fail</result>");
    }

    private AuthProperties properties() {
        AuthProperties properties = new AuthProperties();
        properties.getReport().setStoragePath(tempDir.resolve("reports").toString());
        return properties;
    }

    private EvaluationResult failedResult(String messageId, String domain) {
        return result(messageId, domain, false);
    }

    private EvaluationResult result(String messageId, String domain, boolean aligned) {
        EvaluationResult result = new EvaluationResult();
        result.setMessageId(messageId);
        result.setHeaderFrom("user@" + domain);
        result.setSpf(new SpfResult(aligned ? SpfStatus.PASS : SpfStatus.FAIL,
                aligned ? "pass" : "fail", domain));
        result.setDkim(List.of(new DkimResult(
                aligned ? DkimStatus.PASS : DkimStatus.FAIL, "sel", domain,
                aligned ? "ok" : "bad")));
        result.setDmarc(new DmarcResult(
                aligned ? DmarcDisposition.NONE : DmarcDisposition.REJECT,
                aligned, aligned, domain,
                List.of(aligned ? "authenticated" : "disposition=reject")));
        return result;
    }
}

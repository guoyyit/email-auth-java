package com.github.guoyyit.emailauthjava.web;

import com.github.guoyyit.emailauthjava.report.ReportStore;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/reports")
public class ReportController {
    private final ReportStore reportStore;

    public ReportController(ReportStore reportStore) {
        this.reportStore = reportStore;
    }

    @PostMapping(path = "/{domain}/flush", produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> flush(@PathVariable String domain) {
        String xml = reportStore.flushDueReport(domain);
        if (xml == null) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.ok(xml);
    }
}

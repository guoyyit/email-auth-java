package com.github.guoyyit.emailauthjava.report;

import org.springframework.stereotype.Component;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.StringWriter;
import java.util.List;

/**
 * 生成 RFC 7489 聚合反馈报告风格的 XML（feedback/feedback_metadata/policy_published/record）。
 */
@Component
public class AggregateReportGenerator {
    private static final String NS = "http://dmarc.org/dmarc-xml/0.1";

    public String generateXml(String domain, List<ReportEntry> records) {
        long now = System.currentTimeMillis() / 1000L;
        long start = records.stream().mapToLong(ReportEntry::getTimestamp).min().orElse(0L) / 1000L;
        long end = records.stream().mapToLong(ReportEntry::getTimestamp).max().orElse(0L) / 1000L;
        StringWriter stringWriter = new StringWriter();
        try {
            XMLStreamWriter writer = XMLOutputFactory.newFactory()
                    .createXMLStreamWriter(stringWriter);
            writer.writeStartDocument("UTF-8", "1.0");
            writer.writeCharacters("\n");
            writer.writeStartElement("feedback");
            writer.writeDefaultNamespace(NS);
            element(writer, "version", "1.0");
            writeMetadata(writer, domain, now, start, end);
            for (ReportEntry record : records) {
                writeRecord(writer, record);
            }
            writer.writeEndElement();
            writer.writeEndDocument();
            writer.flush();
        } catch (XMLStreamException e) {
            throw new IllegalStateException("failed to generate report xml", e);
        }
        return stringWriter.toString();
    }

    private void writeMetadata(XMLStreamWriter writer, String domain, long reportId,
                               long start, long end) throws XMLStreamException {
        writer.writeStartElement("report_metadata");
        element(writer, "org_name", domain);
        element(writer, "email", "noreply@" + domain);
        element(writer, "report_id", Long.toString(reportId));
        writer.writeStartElement("date_range");
        element(writer, "begin", Long.toString(start));
        element(writer, "end", Long.toString(end));
        writer.writeEndElement();
        writer.writeEndElement();

        writer.writeStartElement("policy_published");
        element(writer, "domain", domain);
        element(writer, "adkim", "r");
        element(writer, "aspf", "r");
        element(writer, "p", "none");
        element(writer, "sp", "none");
        element(writer, "pct", "100");
        writer.writeEndElement();
    }

    private void writeRecord(XMLStreamWriter writer, ReportEntry record) throws XMLStreamException {
        writer.writeStartElement("record");
        writer.writeStartElement("row");
        element(writer, "source_ip", nullSafe(record.getSourceIp()));
        element(writer, "count", "1");
        writer.writeStartElement("policy_evaluated");
        element(writer, "disposition", nullSafe(record.getDisposition()));
        element(writer, "dkim", alignedWord(record.getDkimAligned()));
        element(writer, "spf", alignedWord(record.getSpfAligned()));
        writer.writeEndElement();
        writer.writeEndElement();

        writer.writeStartElement("identifiers");
        element(writer, "header_from", nullSafe(record.getHeaderFrom()));
        writer.writeEndElement();

        writer.writeStartElement("auth_results");
        writer.writeStartElement("dkim");
        element(writer, "domain", nullSafe(record.getHeaderFrom()));
        element(writer, "result", nullSafe(record.getDkimStatus()));
        writer.writeEndElement();
        writer.writeStartElement("spf");
        element(writer, "domain", nullSafe(record.getHeaderFrom()));
        element(writer, "result", nullSafe(record.getSpfStatus()));
        writer.writeEndElement();
        writer.writeEndElement();

        writer.writeEndElement();
    }

    private String alignedWord(String value) {
        return "true".equals(value) ? "pass" : "fail";
    }

    private String nullSafe(String value) {
        return value == null ? "" : value;
    }

    private void element(XMLStreamWriter writer, String name, String value)
            throws XMLStreamException {
        writer.writeStartElement(name);
        writer.writeCharacters(value);
        writer.writeEndElement();
    }

    public static class ReportRecord {
    }
}

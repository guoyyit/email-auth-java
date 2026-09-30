package com.github.guoyyit.emailauthjava.report;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * 按 RFC 7489 反馈报告格式生成聚合 XML。
 */
public class ReportGenerator {

    private final String reportReceiver;

    public ReportGenerator(String reportReceiver) {
        this.reportReceiver = reportReceiver;
    }

    public String generateXml(String policyDomain, String reportId, Instant rangeBegin,
                              Instant rangeEnd, List<AggregateBucket> buckets) {
        StringBuilder xml = new StringBuilder(4096);
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<feedback>\n");
        xml.append("  <report_metadata>\n");
        xml.append("    <org_name>").append(escape(reportReceiver)).append("</org_name>\n");
        xml.append("    <email>").append(escape("noreply@" + reportReceiver)).append("</email>\n");
        xml.append("    <report_id>").append(escape(reportId)).append("</report_id>\n");
        xml.append("    <range>\n");
        xml.append("      <begin>").append(rangeBegin.getEpochSecond()).append("</begin>\n");
        xml.append("      <end>").append(rangeEnd.getEpochSecond()).append("</end>\n");
        xml.append("    </range>\n");
        xml.append("  </report_metadata>\n");
        xml.append("  <policy_published>\n");
        xml.append("    <domain>").append(escape(policyDomain)).append("</domain>\n");
        xml.append("    <adkim>r</adkim>\n");
        xml.append("    <aspf>r</aspf>\n");
        xml.append("    <p>none</p>\n");
        xml.append("    <sp>none</sp>\n");
        xml.append("    <pct>100</pct>\n");
        xml.append("  </policy_published>\n");
        for (AggregateBucket bucket : buckets) {
            xml.append("  <record>\n");
            xml.append("    <row>\n");
            xml.append("      <source_ip>")
                    .append(escape(bucket.getKey().getSourceIp()))
                    .append("</source_ip>\n");
            xml.append("      <count>").append(bucket.getCount()).append("</count>\n");
            xml.append("      <policy_evaluated>\n");
            xml.append("        <disposition>")
                    .append(escape(disposition(bucket.getDisposition())))
                    .append("</disposition>\n");
            xml.append("        <dkim>").append(outcome(bucket.getDkimResult())).append("</dkim>\n");
            xml.append("        <spf>").append(outcome(bucket.getSpfResult())).append("</spf>\n");
            xml.append("      </policy_evaluated>\n");
            xml.append("    </row>\n");
            xml.append("    <identifiers>\n");
            xml.append("      <header_from>")
                    .append(escape(bucket.getKey().getFromDomain()))
                    .append("</header_from>\n");
            xml.append("    </identifiers>\n");
            xml.append("    <auth_results>\n");
            xml.append("      <dkim>\n");
            xml.append("        <domain>")
                    .append(escape(emptyIfNull(bucket.getDkimDomain())))
                    .append("</domain>\n");
            xml.append("        <result>").append(outcome(bucket.getDkimResult())).append("</result>\n");
            xml.append("      </dkim>\n");
            xml.append("      <spf>\n");
            xml.append("        <domain>")
                    .append(escape(emptyIfNull(bucket.getSpfDomain())))
                    .append("</domain>\n");
            xml.append("        <result>").append(outcome(bucket.getSpfResult())).append("</result>\n");
            xml.append("      </spf>\n");
            xml.append("    </auth_results>\n");
            xml.append("  </record>\n");
        }
        xml.append("</feedback>\n");
        return xml.toString();
    }

    private static String disposition(String value) {
        if (value == null) {
            return "none";
        }
        return switch (value.toLowerCase(java.util.Locale.ROOT)) {
            case "reject" -> "reject";
            case "quarantine" -> "quarantine";
            default -> "none";
        };
    }

    private static String outcome(String value) {
        if (value == null || value.isBlank()) {
            return "none";
        }
        return value.toLowerCase(java.util.Locale.ROOT);
    }

    private static String emptyIfNull(String value) {
        return value == null ? "" : value;
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '<' -> builder.append("&lt;");
                case '>' -> builder.append("&gt;");
                case '&' -> builder.append("&amp;");
                case '"' -> builder.append("&quot;");
                case '\'' -> builder.append("&apos;");
                default -> builder.append(c);
            }
        }
        return builder.toString();
    }

    static String isoTimestamp(Instant instant) {
        return DateTimeFormatter.ISO_INSTANT.format(instant);
    }
}

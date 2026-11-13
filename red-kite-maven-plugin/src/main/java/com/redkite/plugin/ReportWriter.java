package com.redkite.plugin;

import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.ScanReport;
import com.redkite.core.domain.UpgradeRecommendation;
import com.redkite.core.domain.VulnerabilityFinding;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Writes the machine-readable companion to the HTML report. */
final class ReportWriter {
    private ReportWriter() {}

    static void writeHtml(Path dir, String html) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("redkite-report.html"), html, StandardCharsets.UTF_8);
    }

    static void writeJson(Path dir, ScanReport report) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("redkite-report.json"), toJson(report), StandardCharsets.UTF_8);
    }

    static String toJson(ScanReport report) {
        StringBuilder sb = new StringBuilder("{\n");
        sb.append("  \"scanId\": ").append(str(report.scanId())).append(",\n");
        sb.append("  \"complete\": ").append(report.complete()).append(",\n");
        sb.append("  \"message\": ").append(str(report.completenessMessage())).append(",\n");
        sb.append("  \"components\": [");
        String sep = "\n";
        for (ScanComponent c : report.components()) {
            sb.append(sep).append("    {\"groupId\": ").append(str(c.coordinate().groupId()))
              .append(", \"artifactId\": ").append(str(c.coordinate().artifactId()))
              .append(", \"version\": ").append(str(c.version()))
              .append(", \"scope\": ").append(str(String.valueOf(c.scope())))
              .append(", \"direct\": ").append(c.direct())
              .append(", \"snapshot\": ").append(c.snapshot()).append('}');
            sep = ",\n";
        }
        sb.append("\n  ],\n  \"vulnerabilities\": [");
        sep = "\n";
        for (VulnerabilityFinding v : report.vulnerabilityFindings()) {
            sb.append(sep).append("    {\"advisory\": ").append(str(v.advisoryId()))
              .append(", \"severity\": ").append(str(v.severity()))
              .append(", \"groupId\": ").append(str(v.coordinate().groupId()))
              .append(", \"artifactId\": ").append(str(v.coordinate().artifactId()))
              .append(", \"affectedVersion\": ").append(str(v.affectedVersion()))
              .append(", \"fixedVersion\": ").append(str(v.fixedVersion()))
              .append(", \"cves\": [");
            String s2 = "";
            for (String cve : v.cves()) { sb.append(s2).append(str(cve)); s2 = ", "; }
            sb.append("]}");
            sep = ",\n";
        }
        sb.append("\n  ],\n  \"recommendations\": [");
        sep = "\n";
        for (UpgradeRecommendation r : report.recommendations()) {
            sb.append(sep).append("    {\"groupId\": ").append(str(r.coordinate().groupId()))
              .append(", \"artifactId\": ").append(str(r.coordinate().artifactId()))
              .append(", \"from\": ").append(str(r.currentVersion()))
              .append(", \"to\": ").append(str(r.targetVersion()))
              .append(", \"reason\": ").append(str(String.valueOf(r.reason())))
              .append(", \"risk\": ").append(str(String.valueOf(r.riskLevel()))).append('}');
            sep = ",\n";
        }
        return sb.append("\n  ]\n}\n").toString();
    }

    static String str(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder("\"");
        for (char ch : s.toCharArray()) {
            switch (ch) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> { if (ch < 0x20) sb.append(String.format("\\u%04x", (int) ch)); else sb.append(ch); }
            }
        }
        return sb.append('"').toString();
    }
}

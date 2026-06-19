package com.redkite.core.domain;

public enum AdvisorySeverity {
    NONE, UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL;

    public static AdvisorySeverity fromCvssScore(double score) {
        if (score == 0.0) return NONE;
        if (score < 4.0) return LOW;
        if (score < 7.0) return MEDIUM;
        if (score < 9.0) return HIGH;
        return CRITICAL;
    }

    public static AdvisorySeverity fromString(String s) {
        if (s == null || s.isBlank()) return UNKNOWN;
        return switch (s.trim().toUpperCase()) {
            case "CRITICAL" -> CRITICAL;
            case "HIGH" -> HIGH;
            case "MEDIUM", "MODERATE" -> MEDIUM;
            case "LOW" -> LOW;
            case "NONE", "INFORMATIONAL" -> NONE;
            default -> UNKNOWN;
        };
    }

    public AdvisorySeverity max(AdvisorySeverity other) {
        return this.ordinal() >= other.ordinal() ? this : other;
    }

    public boolean requiresRemediation() {
        return this != NONE;
    }

    public String label() {
        return switch (this) {
            case CRITICAL -> "Critical";
            case HIGH -> "High";
            case MEDIUM -> "Medium";
            case LOW -> "Low";
            case UNKNOWN -> "Unknown";
            case NONE -> "None";
        };
    }

    public String icon() {
        return switch (this) {
            case CRITICAL -> "☢";
            case HIGH -> "☠";
            case MEDIUM -> "⚠";
            case LOW -> "ℹ";
            case UNKNOWN -> "?";
            case NONE -> "✓";
        };
    }
}

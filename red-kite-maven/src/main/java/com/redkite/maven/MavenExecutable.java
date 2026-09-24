package com.redkite.maven;

/**
 * The {@code mvn} executable every subprocess-invoking class in this package runs. Defaults to
 * {@code mvn} ({@code mvn.cmd} on Windows) from the {@code PATH}; the {@code redkite.mvn} system
 * property overrides it with an explicit path, e.g. to pick a specific Maven installation.
 */
public final class MavenExecutable {
    public static final String PROPERTY = "redkite.mvn";

    private MavenExecutable() {}

    public static String resolve() {
        String configured = System.getProperty(PROPERTY);
        if (configured != null && !configured.isBlank()) return configured;
        return System.getProperty("os.name", "").toLowerCase().contains("win") ? "mvn.cmd" : "mvn";
    }
}

package com.redkite.maven;

/**
 * The {@code mvn} executable every subprocess-invoking class in this package runs. Defaults to
 * {@code mvn} ({@code mvn.cmd} on Windows) from the {@code PATH}; the {@code redkite.mvn} system
 * property overrides it with an explicit path, e.g. to pick a specific Maven installation.
 */
public final class MavenExecutable {
    public static final String PROPERTY = "redkite.mvn";

    private static final java.util.regex.Pattern JVM_BANNER =
            java.util.regex.Pattern.compile("^Picked up (JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JDK_JAVA_OPTIONS):.*");

    private MavenExecutable() {}

    /** Whether {@code line} is the notice a JVM prints to stderr when one of those environment
     *  variables is set (e.g. for a corporate truststore). It is not Maven output, and the runners
     *  merge stderr into the captured output, so they drop it. */
    public static boolean isJvmBanner(String line) {
        return line != null && JVM_BANNER.matcher(line).matches();
    }

    public static String resolve() {
        String configured = System.getProperty(PROPERTY);
        if (configured != null && !configured.isBlank()) return configured;
        return System.getProperty("os.name", "").toLowerCase().contains("win") ? "mvn.cmd" : "mvn";
    }
}

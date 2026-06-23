package com.redkite.maven;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Runs {@code mvn enforcer:enforce} against a Maven project and returns the raw output.
 */
public class EnforcerRunner {

    private static final Logger LOGGER = Logger.getLogger(EnforcerRunner.class.getName());

    public record EnforcerRunResult(boolean passed, String rawOutput, String errorDetail) {
        public static EnforcerRunResult passed(String output) {
            return new EnforcerRunResult(true, output, null);
        }

        public static EnforcerRunResult failed(String output) {
            return new EnforcerRunResult(false, output, null);
        }

        public static EnforcerRunResult unavailable(String reason) {
            return new EnforcerRunResult(false, "", reason);
        }
    }

    /**
     * @param projectRoot root of the Maven project
     * @param pomPath     specific POM to target (may be the root pom.xml or a temp copy)
     */
    public EnforcerRunResult run(Path projectRoot, Path pomPath) {
        String mvn = System.getProperty("os.name", "").toLowerCase().contains("win") ? "mvn.cmd" : "mvn";
        Path settings = MavenSettingsReader.resolveSettingsFile(projectRoot);

        EnforcerRunResult result = execute(mvn, settings, projectRoot, pomPath, "enforcer:enforce");
        if (result.errorDetail() == null && isNoRulesConfigured(result.rawOutput())) {
            // Rules are bound to a lifecycle phase, not configured for direct invocation.
            // Fall back to verify which triggers the full lifecycle including enforcer.
            LOGGER.info(() -> "enforcer:enforce reported no rules — falling back to mvn verify -DskipTests for " + pomPath);
            result = execute(mvn, settings, projectRoot, pomPath, "verify", "-DskipTests");
        }
        return result;
    }

    private EnforcerRunResult execute(String mvn, Path settings, Path projectRoot, Path pomPath, String... goals) {
        List<String> command = new ArrayList<>();
        command.add(mvn);
        if (settings != null && MavenSettingsReader.isProjectLocalSettings(settings, projectRoot)) {
            LOGGER.info(() -> "Passing -s " + settings + " to enforcer run");
            command.add("-s");
            command.add(settings.toString());
        }
        command.add("-f");
        command.add(pomPath.toString());
        command.add("--no-transfer-progress");
        command.addAll(List.of(goals));

        LOGGER.info(() -> "Running: " + String.join(" ", command));
        try {
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exit = process.waitFor();
            if (exit == 0) {
                LOGGER.info(() -> "Enforcer run passed for " + pomPath);
                return EnforcerRunResult.passed(output);
            } else {
                LOGGER.info(() -> "Enforcer run failed (exit=" + exit + ") for " + pomPath);
                return EnforcerRunResult.failed(output);
            }
        } catch (IOException | InterruptedException e) {
            LOGGER.warning(() -> "Could not run enforcer: " + e.getMessage());
            return EnforcerRunResult.unavailable(e.getMessage());
        }
    }

    private static boolean isNoRulesConfigured(String output) {
        if (output == null) return false;
        String lower = output.toLowerCase();
        return lower.contains("no rules are configured")
                || lower.contains("no rules configured");
    }
}

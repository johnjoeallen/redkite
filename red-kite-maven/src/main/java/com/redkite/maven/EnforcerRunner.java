package com.redkite.maven;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * Runs {@code mvn enforcer:enforce} against a Maven project and returns the raw output.
 */
public class EnforcerRunner {

    private static final Logger LOGGER = Logger.getLogger(EnforcerRunner.class.getName());

    public record EnforcerRunResult(boolean passed, String rawOutput, String errorDetail, boolean usedVerifyFallback) {
        public static EnforcerRunResult passed(String output) {
            return new EnforcerRunResult(true, output, null, false);
        }

        public static EnforcerRunResult failed(String output) {
            return new EnforcerRunResult(false, output, null, false);
        }

        public static EnforcerRunResult unavailable(String reason) {
            return new EnforcerRunResult(false, "", reason, false);
        }
    }

    /**
     * @param projectRoot      root of the Maven project
     * @param pomPath          specific POM to target (may be the root pom.xml or a temp copy)
     * @param skipDirectEnforce when true, skip enforcer:enforce and go straight to verify -DskipTests
     *                         (use this when a prior run already established that rules are lifecycle-bound)
     */
    public EnforcerRunResult run(Path projectRoot, Path pomPath, boolean skipDirectEnforce) {
        return run(projectRoot, pomPath, skipDirectEnforce, null);
    }

    /** Same as {@link #run(Path, Path, boolean)}, but invokes {@code onLine} (if non-null) with
     *  each line of output as it's produced, so a caller can show a live tail while it runs. */
    public EnforcerRunResult run(Path projectRoot, Path pomPath, boolean skipDirectEnforce, Consumer<String> onLine) {
        String mvn = System.getProperty("os.name", "").toLowerCase().contains("win") ? "mvn.cmd" : "mvn";
        Path settings = MavenSettingsReader.resolveSettingsFile(projectRoot);

        if (skipDirectEnforce) {
            LOGGER.info(() -> "Skipping enforcer:enforce (known lifecycle-bound) — running mvn verify -DskipTests for " + pomPath);
            EnforcerRunResult r = execute(mvn, settings, projectRoot, pomPath, onLine, "verify", "-DskipTests");
            return new EnforcerRunResult(r.passed(), r.rawOutput(), r.errorDetail(), true);
        }

        EnforcerRunResult result = execute(mvn, settings, projectRoot, pomPath, onLine, "enforcer:enforce");
        if (result.errorDetail() == null && isNoRulesConfigured(result.rawOutput())) {
            // Rules are bound to a lifecycle phase, not configured for direct invocation.
            // Fall back to verify which triggers the full lifecycle including enforcer.
            LOGGER.info(() -> "enforcer:enforce reported no rules — falling back to mvn verify -DskipTests for " + pomPath);
            result = execute(mvn, settings, projectRoot, pomPath, onLine, "verify", "-DskipTests");
            return new EnforcerRunResult(result.passed(), result.rawOutput(), result.errorDetail(), true);
        }
        return result;
    }

    public EnforcerRunResult run(Path projectRoot, Path pomPath) {
        return run(projectRoot, pomPath, false, null);
    }

    private EnforcerRunResult execute(String mvn, Path settings, Path projectRoot, Path pomPath,
                                       Consumer<String> onLine, String... goals) {
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
            String output = readOutput(process, onLine);
            int exit = process.waitFor();
            ValidationRunner.appendLog(projectRoot, "enforcer (" + String.join(" ", goals) + ")", command, output);
            if (exit == 0) {
                LOGGER.info(() -> "Enforcer run passed for " + pomPath);
                return EnforcerRunResult.passed(output);
            } else {
                LOGGER.info(() -> "Enforcer exited " + exit + " for " + pomPath + " (violations or no rules configured)");
                return EnforcerRunResult.failed(output);
            }
        } catch (IOException | InterruptedException e) {
            LOGGER.warning(() -> "Could not run enforcer: " + e.getMessage());
            ValidationRunner.appendLog(projectRoot, "enforcer (" + String.join(" ", goals) + ")", command, e.getMessage());
            return EnforcerRunResult.unavailable(e.getMessage());
        }
    }

    /** Reads a process's (merged stdout/stderr) output to completion, line by line, invoking
     *  {@code onLine} for each line as it arrives and returning the full text joined with {@code \n}. */
    private static String readOutput(Process process, Consumer<String> onLine) throws IOException {
        StringBuilder all = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                all.append(line).append('\n');
                if (onLine != null) onLine.accept(line);
            }
        }
        return all.toString();
    }

    private static boolean isNoRulesConfigured(String output) {
        if (output == null) return false;
        String lower = output.toLowerCase();
        return lower.contains("no rules are configured")
                || lower.contains("no rules configured");
    }
}

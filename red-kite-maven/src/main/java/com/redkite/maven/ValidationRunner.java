package com.redkite.maven;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Runs {@code mvn clean install} (and optionally {@code spring-boot:run}) against a Maven project
 * to validate that it builds and starts successfully.
 */
public class ValidationRunner {

    private static final Logger LOGGER = Logger.getLogger(ValidationRunner.class.getName());
    private static final Pattern SPRING_STARTED = Pattern.compile("Started .+ in [\\d.]+ seconds");
    private static final Pattern TOMCAT_STARTED = Pattern.compile("Tomcat started on port");
    private static final String SPRING_BOOT_PLUGIN = "spring-boot-maven-plugin";

    public record ValidationResult(boolean passed, String phase, String rawOutput, String failureSignature) {}

    /** Runs {@code mvn clean install} and returns the result. */
    public ValidationResult validate(Path projectRoot, Path pomPath) {
        return validate(projectRoot, pomPath, List.of(), Map.of());
    }

    /**
     * Runs {@code mvn clean install} and returns the result.
     *
     * @param extraMavenArgs extra arguments appended to the {@code mvn} command (e.g. {@code -Pdev},
     *                       {@code -Dspring.profiles.active=dev})
     * @param extraEnv       extra environment variables set on the spawned process
     */
    public ValidationResult validate(Path projectRoot, Path pomPath, List<String> extraMavenArgs, Map<String, String> extraEnv) {
        String mvn = isMvnCmd();
        Path settings = MavenSettingsReader.resolveSettingsFile(projectRoot);
        List<String> command = buildCommand(mvn, settings, projectRoot, pomPath, extraMavenArgs,
                "clean", "install", "-DskipTests", "-Denforcer.skip=true");
        LOGGER.info(() -> "Validation build: " + String.join(" ", command));
        try {
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().putAll(extraEnv);
            Process process = builder.start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exit = process.waitFor();
            boolean passed = exit == 0;
            if (passed) {
                LOGGER.info(() -> "Validation build passed for " + pomPath);
            } else {
                LOGGER.warning(() -> "Validation build failed for " + pomPath + " (exit " + exit + "). Full output:\n" + output);
                saveFailedPom(pomPath);
            }
            return new ValidationResult(passed, "build", output, passed ? null : extractSignature(output));
        } catch (IOException | InterruptedException e) {
            LOGGER.warning(() -> "Validation build could not run: " + e.getMessage());
            saveFailedPom(pomPath);
            return new ValidationResult(false, "build", "", e.getMessage());
        }
    }

    /**
     * Runs {@code mvn clean install} then, if {@code spring-boot-maven-plugin} is detected in the
     * root POM, also runs {@code mvn spring-boot:run} and waits for the startup signal or timeout.
     * The spawned process is always killed before returning.
     */
    public ValidationResult validateWithStartup(Path projectRoot, Path pomPath, int timeoutSeconds) {
        return validateWithStartup(projectRoot, pomPath, timeoutSeconds, List.of(), Map.of());
    }

    /**
     * Runs {@code mvn clean install} then, if {@code spring-boot-maven-plugin} is detected in the
     * root POM, also runs {@code mvn spring-boot:run} and waits for the startup signal or timeout.
     * The spawned process is always killed before returning.
     *
     * @param extraMavenArgs extra arguments appended to every {@code mvn} invocation (build and
     *                       startup) — e.g. Maven profiles via {@code -P} or {@code -D} properties
     * @param extraEnv       extra environment variables set on the spawned processes
     */
    public ValidationResult validateWithStartup(Path projectRoot, Path pomPath, int timeoutSeconds,
                                                 List<String> extraMavenArgs, Map<String, String> extraEnv) {
        ValidationResult buildResult = validate(projectRoot, pomPath, extraMavenArgs, extraEnv);
        if (!buildResult.passed()) return buildResult;

        String pomContent;
        try {
            pomContent = Files.readString(pomPath, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return buildResult;
        }
        if (!pomContent.contains(SPRING_BOOT_PLUGIN)) {
            LOGGER.info(() -> "No " + SPRING_BOOT_PLUGIN + " detected in " + pomPath + "; skipping startup validation");
            return buildResult;
        }

        LOGGER.info(() -> "Running startup validation (spring-boot:run) for " + pomPath
                + " with timeout " + timeoutSeconds + "s");
        String mvn = isMvnCmd();
        Path settings = MavenSettingsReader.resolveSettingsFile(projectRoot);
        List<String> command = buildCommand(mvn, settings, projectRoot, pomPath, extraMavenArgs, "spring-boot:run");
        LOGGER.info(() -> "Startup validation build: " + String.join(" ", command));

        try {
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().putAll(extraEnv);
            Process process = builder.start();

            StringBuffer startupOutput = new StringBuffer();
            AtomicBoolean started = new AtomicBoolean(false);

            Thread readerThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        startupOutput.append(line).append('\n');
                        if (SPRING_STARTED.matcher(line).find() || TOMCAT_STARTED.matcher(line).find()) {
                            started.set(true);
                            break;
                        }
                    }
                } catch (IOException ignored) {}
            }, "rk-startup-reader");
            readerThread.setDaemon(true);
            readerThread.start();
            readerThread.join((long) timeoutSeconds * 1000);
            process.destroyForcibly();
            process.waitFor();
            readerThread.join(5000L);

            String output = startupOutput.toString();
            boolean passed = started.get();
            if (passed) {
                LOGGER.info(() -> "Startup validation passed for " + pomPath);
            } else {
                LOGGER.warning(() -> "Startup validation failed/timed-out for " + pomPath + ". Full output:\n" + output);
                saveFailedPom(pomPath);
            }
            return new ValidationResult(passed, "startup", output, passed ? null : extractSignature(output));
        } catch (IOException | InterruptedException e) {
            LOGGER.warning(() -> "Startup validation could not run: " + e.getMessage());
            saveFailedPom(pomPath);
            return new ValidationResult(false, "startup", "", e.getMessage());
        }
    }

    /**
     * Copies the given POM to a sibling {@code pom.failed} file for later analysis, overwriting any
     * previous one. Best-effort: failures to save are logged but never thrown.
     */
    private static void saveFailedPom(Path pomPath) {
        Path failedPath = pomPath.resolveSibling("pom.failed");
        try {
            Files.copy(pomPath, failedPath, StandardCopyOption.REPLACE_EXISTING);
            LOGGER.info(() -> "Saved failing POM to " + failedPath);
        } catch (IOException e) {
            LOGGER.warning(() -> "Could not save failing POM to " + failedPath + ": " + e.getMessage());
        }
    }

    /**
     * Attempts to attribute a build/startup failure to a specific dependency by scanning the Maven
     * output for resolution error patterns. Returns {@code "groupId:artifactId"} on a strong match,
     * or {@code null} if the failure cannot be attributed.
     */
    public static String attributeFailure(String rawOutput) {
        if (rawOutput == null || rawOutput.isEmpty()) return null;
        for (String marker : List.of("Could not resolve artifact", "Could not find artifact")) {
            int idx = rawOutput.indexOf(marker);
            if (idx >= 0) {
                String after = rawOutput.substring(idx + marker.length()).stripLeading();
                int end = indexOfAny(after, " \n\r\t");
                String artifact = end > 0 ? after.substring(0, end) : after;
                if (artifact.contains(":")) return toGroupArtifact(artifact);
            }
        }
        return null;
    }

    private static String toGroupArtifact(String coords) {
        String[] parts = coords.split(":");
        return parts.length >= 2 ? parts[0] + ":" + parts[1] : null;
    }

    private static int indexOfAny(String s, String chars) {
        for (int i = 0; i < s.length(); i++) {
            if (chars.indexOf(s.charAt(i)) >= 0) return i;
        }
        return -1;
    }

    static String extractSignature(String output) {
        if (output == null || output.isEmpty()) return null;
        for (String line : output.split("\n")) {
            String t = line.trim();
            if (t.startsWith("[ERROR]") && t.length() > "[ERROR]".length() + 1) return t;
        }
        int ex = output.indexOf("Exception");
        if (ex >= 0) {
            int lineStart = output.lastIndexOf('\n', ex) + 1;
            int lineEnd = output.indexOf('\n', ex);
            if (lineEnd > lineStart) return output.substring(lineStart, lineEnd).trim();
        }
        return output.length() > 500 ? output.substring(output.length() - 500).trim() : output.trim();
    }

    private static String isMvnCmd() {
        return System.getProperty("os.name", "").toLowerCase().contains("win") ? "mvn.cmd" : "mvn";
    }

    private static List<String> buildCommand(String mvn, Path settings, Path projectRoot, Path pomPath,
                                              List<String> extraMavenArgs, String... goals) {
        List<String> command = new ArrayList<>();
        command.add(mvn);
        if (settings != null && MavenSettingsReader.isProjectLocalSettings(settings, projectRoot)) {
            command.add("-s");
            command.add(settings.toString());
        }
        command.add("-f");
        command.add(pomPath.toString());
        command.add("--no-transfer-progress");
        for (String goal : goals) command.add(goal);
        command.addAll(extraMavenArgs);
        return command;
    }
}

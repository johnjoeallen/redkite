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
    private static final String SPRING_BOOT_PLUGIN = "spring-boot-maven-plugin";

    public record ValidationResult(boolean passed, String phase, String rawOutput, String failureSignature) {}

    /**
     * What a validation run actually checks. {@code RUN} is the default and the only mode that
     * ever attempts the {@code spring-boot:run} startup check — {@code VERIFY} and {@code TEST}
     * always stop at the build/test phase, for a project where starting the app for real isn't
     * practical but running its own tests still is.
     */
    public enum Mode {
        /** {@code mvn clean install} (tests skipped by default, see
         *  {@link ValidationOptions#skipTests()}), then, if {@code spring-boot-maven-plugin} is
         *  present, {@code spring-boot:run} — today's default behavior. Adapts to the project:
         *  a startup check for a Spring Boot project, build-only otherwise. */
        RUN,
        /** {@code mvn clean verify} (tests included) — the full lifecycle through {@code verify},
         *  covering anything bound to that phase (e.g. integration tests via failsafe). Never
         *  attempts a startup check. */
        VERIFY,
        /** {@code mvn clean test} (unit tests only, no packaging) — lighter than {@code VERIFY}.
         *  Never attempts a startup check. */
        TEST
    }

    /**
     * Extra configuration for a validation run, sourced from a project's own
     * {@code .redkite/config.yml} (see {@link ProjectConfigFile}).
     *
     * @param mavenArgs    extra arguments appended to every {@code mvn} invocation (build and, for
     *                     a Spring Boot project in {@link Mode#RUN}, the startup check) — e.g.
     *                     Maven profiles via {@code -P} or {@code -D} properties
     * @param env          extra environment variables set on the spawned processes
     * @param mode         which lifecycle phase (and whether a startup check ever runs) — see
     *                     {@link Mode}
     * @param springBootArgs extra arguments appended only to the {@code spring-boot:run} startup
     *                       check, on top of {@code mavenArgs} — never used for the plain build
     *                       check, since they're meaningless outside a Spring Boot startup (e.g.
     *                       {@code -Dspring-boot.run.profiles=...})
     * @param skipTests    only applies to {@link Mode#RUN} (default {@code true}, today's existing
     *                     behavior — {@code -DskipTests}). {@link Mode#VERIFY} and {@link Mode#TEST}
     *                     always run tests regardless of this flag, since running tests is the
     *                     entire reason to pick one of those modes over {@code RUN}.
     */
    public record ValidationOptions(List<String> mavenArgs, Map<String, String> env, Mode mode,
                                     List<String> springBootArgs, boolean skipTests) {
        public static final ValidationOptions DEFAULT = new ValidationOptions(List.of(), Map.of(), Mode.RUN, List.of(), true);
    }

    /** Runs {@code mvn clean install} and returns the result. */
    public ValidationResult validate(Path projectRoot, Path pomPath) {
        return validate(projectRoot, pomPath, ValidationOptions.DEFAULT);
    }

    /** Runs the build/test check appropriate to {@link ValidationOptions#mode()} and returns the
     *  result. */
    public ValidationResult validate(Path projectRoot, Path pomPath, ValidationOptions options) {
        String mvn = isMvnCmd();
        Path settings = MavenSettingsReader.resolveSettingsFile(projectRoot);
        List<String> command = switch (options.mode()) {
            case VERIFY -> buildCommand(mvn, settings, projectRoot, pomPath, options.mavenArgs(),
                    "clean", "verify", "-Denforcer.skip=true");
            case TEST -> buildCommand(mvn, settings, projectRoot, pomPath, options.mavenArgs(),
                    "clean", "test", "-Denforcer.skip=true");
            case RUN -> options.skipTests()
                    ? buildCommand(mvn, settings, projectRoot, pomPath, options.mavenArgs(),
                            "clean", "install", "-DskipTests", "-Denforcer.skip=true")
                    : buildCommand(mvn, settings, projectRoot, pomPath, options.mavenArgs(),
                            "clean", "install", "-Denforcer.skip=true");
        };
        LOGGER.info(() -> "Validation build: " + String.join(" ", command));
        try {
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().putAll(options.env());
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
        return validateWithStartup(projectRoot, pomPath, timeoutSeconds, ValidationOptions.DEFAULT);
    }

    /**
     * Runs the build/test check (see {@link #validate}) then, if {@link ValidationOptions#mode()}
     * is {@link Mode#RUN} and {@code spring-boot-maven-plugin} is detected in the root POM, also
     * runs {@code mvn spring-boot:run} and waits for the startup signal or timeout. The spawned
     * process is always killed before returning.
     *
     * <p>In {@link Mode#VERIFY} or {@link Mode#TEST}, the startup check never runs at all,
     * regardless of whether the project is Spring Boot — validation is the build/test check alone,
     * for a project where starting the app isn't practical but its own test suite is still a
     * meaningful gate.
     */
    public ValidationResult validateWithStartup(Path projectRoot, Path pomPath, int timeoutSeconds,
                                                 ValidationOptions options) {
        ValidationResult buildResult = validate(projectRoot, pomPath, options);
        if (!buildResult.passed()) return buildResult;
        if (options.mode() != Mode.RUN) {
            Mode mode = options.mode();
            LOGGER.info(() -> "Mode " + mode + " configured for " + pomPath + "; skipping startup validation");
            return buildResult;
        }

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

        // Run the app on a random verified-free port so the check never collides with another
        // instance — the app's default port may be held by the developer's own running copy, or
        // by an orphan from a previous validation.
        int port;
        try {
            port = findFreePort();
        } catch (IOException e) {
            LOGGER.warning(() -> "Could not allocate a free port for startup validation: " + e.getMessage());
            return new ValidationResult(false, "startup", "", "Could not allocate a free port: " + e.getMessage());
        }
        LOGGER.info(() -> "Running startup validation (spring-boot:run, port " + port + ") for " + pomPath
                + " with timeout " + timeoutSeconds + "s");
        String mvn = isMvnCmd();
        Path settings = MavenSettingsReader.resolveSettingsFile(projectRoot);
        List<String> startupArgs = new java.util.ArrayList<>(options.mavenArgs());
        startupArgs.addAll(options.springBootArgs());
        List<String> command = buildCommand(mvn, settings, projectRoot, pomPath, startupArgs,
                "spring-boot:run", "-Dspring-boot.run.arguments=--server.port=" + port);
        LOGGER.info(() -> "Startup validation build: " + String.join(" ", command));

        try {
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().putAll(options.env());
            Process process = builder.start();

            StringBuffer startupOutput = new StringBuffer();
            AtomicBoolean started = new AtomicBoolean(false);

            Thread readerThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        startupOutput.append(line).append('\n');
                        if (SPRING_STARTED.matcher(line).find()) {
                            started.set(true);
                            break;
                        }
                    }
                } catch (IOException ignored) {}
            }, "rk-startup-reader");
            readerThread.setDaemon(true);
            readerThread.start();
            readerThread.join((long) timeoutSeconds * 1000);
            killProcessTree(process);
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
     * Allocates a random free port. Binding to port 0 makes the OS hand out an unused ephemeral
     * port — the successful bind IS the verification that nothing is listening on it; the socket
     * is closed immediately so the app under validation can claim it.
     */
    private static int findFreePort() throws IOException {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        }
    }

    /**
     * Forcibly terminates the process AND all of its descendants, then waits for them to die.
     * Destroying only the top-level process is not enough: on Windows, killing the {@code mvn.cmd}
     * wrapper leaves the forked Java process (the Spring Boot app under {@code spring-boot:run})
     * running — it keeps its web server port bound, and the NEXT validation's startup check then
     * fails with "Port already in use".
     */
    private static void killProcessTree(Process process) throws InterruptedException {
        // Capture descendants BEFORE killing the parent — once the parent is gone the tree
        // relationship is broken and descendants() returns nothing.
        List<ProcessHandle> descendants = process.descendants().toList();
        descendants.forEach(ProcessHandle::destroyForcibly);
        process.destroyForcibly();
        process.waitFor();
        long deadline = System.currentTimeMillis() + 10_000;
        for (ProcessHandle descendant : descendants) {
            while (descendant.isAlive() && System.currentTimeMillis() < deadline) {
                Thread.sleep(100);
            }
        }
        List<ProcessHandle> survivors = descendants.stream().filter(ProcessHandle::isAlive).toList();
        if (!survivors.isEmpty()) {
            LOGGER.warning(() -> "Startup validation: " + survivors.size()
                    + " child process(es) did not terminate within 10s of being killed"
                    + " — the app may still be holding its port");
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

package com.redkite.maven;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Reads a project's own {@code .redkite/project.cfg} — build validation settings checked into the
 * project itself, rather than entered through RedKite's UI and stored in RedKite's own database.
 * Lets a project declare, once, the extra Maven arguments, activated profile(s), and environment
 * variables its build (and, for Spring Boot projects, its startup) validation needs — a project
 * that requires a specific profile to build or start would otherwise always fail apply validation.
 *
 * <p>The file is a restricted YAML subset — flat {@code key: value} lines plus one nested map
 * (indented {@code KEY: value} lines under {@code env:}) — parsed by hand rather than pulling in a
 * full YAML library, since that's the entire shape this file will ever need. A line starting with
 * {@code #} (after leading whitespace) or a blank line is ignored. Values may optionally be
 * wrapped in matching single or double quotes; unrecognized top-level keys are ignored, not an
 * error, so a newer/older RedKite version reading an unfamiliar file degrades gracefully.
 *
 * <pre>{@code
 * mavenArgs: -Dfoo=bar
 * profile: dev
 * springProfiles: dev,local
 * env:
 *   SPRING_PROFILES_ACTIVE: dev
 *   DB_HOST: localhost
 * }</pre>
 */
public final class ProjectConfigFile {
    private static final Logger LOGGER = Logger.getLogger(ProjectConfigFile.class.getName());

    /** Path to the config file, relative to a project's root directory. */
    public static final String RELATIVE_PATH = ".redkite/project.cfg";

    public record ProjectConfig(String mavenArgs, String profile, String springProfiles, Map<String, String> env) {
        public static final ProjectConfig EMPTY = new ProjectConfig(null, null, null, Map.of());

        /** Every setting folded into one Maven argument list, in a stable order: {@code mavenArgs}
         *  tokens first, then {@code -P<profile>}, then the Spring Boot profile-activation flag —
         *  the shape {@link com.redkite.maven.ValidationRunner} already accepts, so the caller
         *  doesn't need to know these came from three separate fields. */
        public List<String> toMavenArgs() {
            java.util.List<String> args = new java.util.ArrayList<>();
            if (mavenArgs != null && !mavenArgs.isBlank()) {
                for (String part : mavenArgs.trim().split("\\s+")) {
                    if (!part.isEmpty()) args.add(part);
                }
            }
            if (profile != null && !profile.isBlank()) {
                args.add("-P" + profile.trim());
            }
            if (springProfiles != null && !springProfiles.isBlank()) {
                args.add("-Dspring-boot.run.profiles=" + springProfiles.trim());
            }
            return List.copyOf(args);
        }
    }

    private ProjectConfigFile() {
    }

    /** Reads {@code <projectRoot>/.redkite/project.cfg}, or {@link ProjectConfig#EMPTY} if it
     *  doesn't exist or fails to parse (logged, never thrown — a malformed config file shouldn't
     *  block analysis or validation from running at all). */
    public static ProjectConfig load(Path projectRoot) {
        Path configPath = projectRoot.resolve(RELATIVE_PATH);
        if (!Files.exists(configPath)) return ProjectConfig.EMPTY;
        try {
            return parse(Files.readString(configPath, StandardCharsets.UTF_8));
        } catch (IOException e) {
            LOGGER.warning(() -> "Failed to read " + configPath + ": " + e.getMessage());
            return ProjectConfig.EMPTY;
        }
    }

    static ProjectConfig parse(String content) {
        String mavenArgs = null, profile = null, springProfiles = null;
        Map<String, String> env = new LinkedHashMap<>();
        String currentTopKey = null;

        for (String rawLine : content.split("\n", -1)) {
            String line = rawLine.stripTrailing();
            String trimmed = line.strip();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue;

            boolean indented = line.length() > trimmed.length();
            int colon = trimmed.indexOf(':');
            if (colon < 0) continue; // not a key: value line — ignore rather than fail the whole file
            String key = trimmed.substring(0, colon).strip();
            String value = unquote(trimmed.substring(colon + 1).strip());

            if (indented && "env".equals(currentTopKey)) {
                if (!key.isEmpty()) env.put(key, value);
                continue;
            }

            currentTopKey = key;
            switch (key) {
                case "mavenArgs" -> mavenArgs = value;
                case "profile" -> profile = value;
                case "springProfiles" -> springProfiles = value;
                case "env" -> { /* value (if any) on the same line as "env:" is ignored — only its indented children are read */ }
                default -> LOGGER.fine(() -> "Ignoring unrecognized project.cfg key: " + key);
            }
        }
        return new ProjectConfig(mavenArgs, profile, springProfiles, Map.copyOf(env));
    }

    private static String unquote(String value) {
        if (value.length() >= 2) {
            char first = value.charAt(0), last = value.charAt(value.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                return value.substring(1, value.length() - 1);
            }
        }
        return value;
    }
}

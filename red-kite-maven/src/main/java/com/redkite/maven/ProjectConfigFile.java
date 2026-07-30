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
 * Reads a project's own {@code .redkite/config.yml} — build validation settings checked into the
 * project itself, rather than entered through RedKite's UI and stored in RedKite's own database.
 * Lets a project declare, once, the extra Maven arguments, activated profile, environment
 * variables, validation mode, and Spring Boot-specific settings its build (and, for Spring Boot
 * projects, its startup) validation needs — a project that requires a specific profile to build or
 * start would otherwise always fail apply validation.
 *
 * <p>The file is a restricted YAML subset — flat {@code key: value} lines plus nested maps
 * (indented {@code KEY: value} lines under {@code env:} or {@code springBoot:}) — parsed by hand
 * rather than pulling in a full YAML library, since that's the entire shape this file will ever
 * need. A line starting with {@code #} (after leading whitespace) or a blank line is ignored.
 * Values may optionally be wrapped in matching single or double quotes; unrecognized top-level
 * keys are ignored, not an error, so a newer/older RedKite version reading an unfamiliar file
 * degrades gracefully.
 *
 * <p>{@code mavenArgs}/{@code profile}/{@code env} apply to every validation RedKite runs for the
 * project — the plain build check, and, for a Spring Boot project in {@code mode: run}, the
 * {@code spring-boot:run} startup check too. {@code springBoot.profiles} applies only to the
 * startup check, since it's meaningless outside {@code spring-boot:run} — it's kept in its own
 * section rather than a flat {@code springProfiles} key specifically to make that scope obvious.
 * {@code mode} picks the Maven lifecycle phase (and whether a startup check ever runs at all) —
 * see {@link ValidationRunner.Mode}.
 *
 * <pre>{@code
 * mavenArgs: -Dfoo=bar
 * profile: dev
 * mode: verify
 * env:
 *   DB_HOST: localhost
 * springBoot:
 *   profiles: dev,local
 * }</pre>
 */
public final class ProjectConfigFile {
    private static final Logger LOGGER = Logger.getLogger(ProjectConfigFile.class.getName());

    /** Path to the config file, relative to a project's root directory. */
    public static final String RELATIVE_PATH = ".redkite/config.yml";

    public record ProjectConfig(String mavenArgs, String profile, ValidationRunner.Mode mode,
                                 Map<String, String> env, String springBootProfiles) {
        public static final ProjectConfig EMPTY = new ProjectConfig(null, null, ValidationRunner.Mode.RUN, Map.of(), null);

        /** {@code mavenArgs} and {@code profile} folded into one list, in a stable order — applies
         *  to every validation RedKite runs for this project. Does not include
         *  {@link #springBootProfiles()}, which only ever applies to the {@code spring-boot:run}
         *  startup check specifically; a caller building that command appends
         *  {@link #springBootArgs()} on top of this. */
        public List<String> toBuildArgs() {
            List<String> args = new java.util.ArrayList<>();
            if (mavenArgs != null && !mavenArgs.isBlank()) {
                for (String part : mavenArgs.trim().split("\\s+")) {
                    if (!part.isEmpty()) args.add(part);
                }
            }
            if (profile != null && !profile.isBlank()) {
                args.add("-P" + profile.trim());
            }
            return List.copyOf(args);
        }

        /** Extra arguments that apply only to the {@code spring-boot:run} startup check — appended
         *  on top of {@link #toBuildArgs()}, never used for the plain build check. */
        public List<String> springBootArgs() {
            if (springBootProfiles == null || springBootProfiles.isBlank()) return List.of();
            return List.of("-Dspring-boot.run.profiles=" + springBootProfiles.trim());
        }
    }

    private ProjectConfigFile() {
    }

    /** Reads {@code <projectRoot>/.redkite/config.yml}, or {@link ProjectConfig#EMPTY} if it
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
        String mavenArgs = null, profile = null, springBootProfiles = null;
        ValidationRunner.Mode mode = ValidationRunner.Mode.RUN;
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

            if (indented && currentTopKey != null) {
                if (key.isEmpty()) continue;
                switch (currentTopKey) {
                    case "env" -> env.put(key, value);
                    case "springBoot" -> {
                        if ("profiles".equals(key)) springBootProfiles = value;
                    }
                    default -> { /* an indented line under a top key with no nested sections — ignore */ }
                }
                continue;
            }

            currentTopKey = key;
            switch (key) {
                case "mavenArgs" -> mavenArgs = value;
                case "profile" -> profile = value;
                case "mode" -> mode = parseMode(value);
                case "env", "springBoot" -> { /* value (if any) on this line is ignored — only indented children are read */ }
                default -> LOGGER.fine(() -> "Ignoring unrecognized " + RELATIVE_PATH + " key: " + key);
            }
        }
        return new ProjectConfig(mavenArgs, profile, mode, Map.copyOf(env), springBootProfiles);
    }

    /** Case-insensitive; an unrecognized value falls back to {@link ValidationRunner.Mode#RUN},
     *  the default, rather than failing to parse the whole file. */
    private static ValidationRunner.Mode parseMode(String value) {
        for (ValidationRunner.Mode candidate : ValidationRunner.Mode.values()) {
            if (candidate.name().equalsIgnoreCase(value)) return candidate;
        }
        LOGGER.warning(() -> "Unrecognized mode \"" + value + "\" in " + RELATIVE_PATH + " — defaulting to run");
        return ValidationRunner.Mode.RUN;
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

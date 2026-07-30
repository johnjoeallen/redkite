package com.redkite.maven;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.YAMLException;

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
 * <p>Parsed with SnakeYAML (real YAML, not a hand-rolled subset) into its natural
 * {@code Map<String, Object>} representation, then read field-by-field — every accessor tolerates
 * a missing section, an unexpected shape, or a non-string scalar rather than throwing, since a
 * malformed or partially-unfamiliar config file should degrade gracefully, not block validation.
 *
 * <p>Everything lives under one top-level {@code maven:} key. {@code args}/{@code profile}/
 * {@code env} apply to every validation RedKite runs for the project — the plain build check, and,
 * for a Spring Boot project in {@code mode: run}, the {@code spring-boot:run} startup check too.
 * {@code spring.profiles} applies only to the startup check, since it's meaningless outside
 * {@code spring-boot:run} — kept in its own section to make that scope obvious. {@code mode} picks
 * the Maven lifecycle phase (and whether a startup check ever runs at all) — see
 * {@link ValidationRunner.Mode}.
 *
 * <pre>{@code
 * maven:
 *   mode: run
 *   profile: redkite
 *   args:
 *     -Dfoo=bar
 *   env:
 *     DB_HOST: localhost
 *     DB_PASS: pw
 *   spring:
 *     profiles: redkite
 * }</pre>
 */
public final class ProjectConfigFile {
    private static final Logger LOGGER = Logger.getLogger(ProjectConfigFile.class.getName());

    /** Path to the config file, relative to a project's root directory. */
    public static final String RELATIVE_PATH = ".redkite/config.yml";

    public record ProjectConfig(String args, String profile, ValidationRunner.Mode mode,
                                 Map<String, String> env, String springProfiles) {
        public static final ProjectConfig EMPTY = new ProjectConfig(null, null, ValidationRunner.Mode.RUN, Map.of(), null);

        /** {@code args} and {@code profile} folded into one list, in a stable order — applies to
         *  every validation RedKite runs for this project. Does not include
         *  {@link #springProfiles()}, which only ever applies to the {@code spring-boot:run}
         *  startup check specifically; a caller building that command appends
         *  {@link #springBootArgs()} on top of this. */
        public List<String> toBuildArgs() {
            List<String> result = new java.util.ArrayList<>();
            if (args != null && !args.isBlank()) {
                for (String part : args.trim().split("\\s+")) {
                    if (!part.isEmpty()) result.add(part);
                }
            }
            if (profile != null && !profile.isBlank()) {
                result.add("-P" + profile.trim());
            }
            return List.copyOf(result);
        }

        /** Extra arguments that apply only to the {@code spring-boot:run} startup check — appended
         *  on top of {@link #toBuildArgs()}, never used for the plain build check. */
        public List<String> springBootArgs() {
            if (springProfiles == null || springProfiles.isBlank()) return List.of();
            return List.of("-Dspring-boot.run.profiles=" + springProfiles.trim());
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
        Object loaded;
        try {
            loaded = new Yaml().load(content);
        } catch (YAMLException e) {
            LOGGER.warning(() -> "Failed to parse " + RELATIVE_PATH + ": " + e.getMessage());
            return ProjectConfig.EMPTY;
        }
        if (!(loaded instanceof Map<?, ?> root) || !(root.get("maven") instanceof Map<?, ?> maven)) {
            return ProjectConfig.EMPTY;
        }

        String args = asString(maven.get("args"));
        String profile = asString(maven.get("profile"));
        ValidationRunner.Mode mode = parseMode(asString(maven.get("mode")));
        Map<String, String> env = asStringMap(maven.get("env"));
        String springProfiles = maven.get("spring") instanceof Map<?, ?> spring ? asString(spring.get("profiles")) : null;

        return new ProjectConfig(args, profile, mode, env, springProfiles);
    }

    /** {@code null} for a missing key; otherwise the scalar's string form, even if the author
     *  wrote something YAML would otherwise infer as a number or boolean (e.g. an all-digit Maven
     *  profile name) — this file only ever means "these are strings", regardless of what YAML's
     *  own type inference would have guessed. */
    private static String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static Map<String, String> asStringMap(Object value) {
        if (!(value instanceof Map<?, ?> map)) return Map.of();
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (entry.getKey() != null && entry.getValue() != null) {
                result.put(String.valueOf(entry.getKey()), String.valueOf(entry.getValue()));
            }
        }
        return Map.copyOf(result);
    }

    /** Case-insensitive; a missing or unrecognized value falls back to
     *  {@link ValidationRunner.Mode#RUN}, the default. */
    private static ValidationRunner.Mode parseMode(String value) {
        if (value == null) return ValidationRunner.Mode.RUN;
        for (ValidationRunner.Mode candidate : ValidationRunner.Mode.values()) {
            if (candidate.name().equalsIgnoreCase(value)) return candidate;
        }
        LOGGER.warning(() -> "Unrecognized mode \"" + value + "\" in " + RELATIVE_PATH + " — defaulting to run");
        return ValidationRunner.Mode.RUN;
    }
}

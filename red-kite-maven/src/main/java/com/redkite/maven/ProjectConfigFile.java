package com.redkite.maven;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.YAMLException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Reads a project's own {@code .redkite/settings.yml} — build validation settings checked into the
 * project itself, rather than entered through RedKite's UI and stored in RedKite's own database.
 * {@code .redkite/settings.yaml} is also recognized and takes precedence if, unusually, both exist.
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
 * <p>Everything lives under {@code redkite.maven} — nested under a {@code redkite:} root rather
 * than {@code maven:} directly, leaving room for future, non-Maven config sections alongside it.
 * {@code args}/{@code profile}/{@code env} apply to every validation RedKite runs for the project —
 * the plain build check, and, for a Spring Boot project reaching {@link ValidationRunner.Mode#RUN},
 * the {@code spring-boot:run} startup check too. {@code spring.profiles} applies only to the
 * startup check, since it's meaningless outside {@code spring-boot:run} — kept in its own section
 * to make that scope obvious.
 *
 * <p>{@code mode} is a combination of {@code run}/{@code verify}/{@code test} — written as a single
 * scalar ({@code mode: run}) or a list ({@code mode: [run, test]}) — resolved by
 * {@link #parseModeCombination} into two things: which {@link ValidationRunner.Mode} RedKite runs
 * (the deepest Maven lifecycle phase present — {@code run} beats {@code verify} beats {@code test},
 * since each one's underlying Maven phase already contains the shallower ones), and whether
 * {@code test} appears anywhere in the combination, which decides {@code -DskipTests} uniformly
 * regardless of which {@link ValidationRunner.Mode} was picked — see
 * {@link ValidationRunner.ValidationOptions#enableTests()}. {@code mode: run} alone (the default)
 * skips tests, matching today's existing behavior; {@code mode: [run, test]} runs the same
 * {@code install} goal but with tests enabled; {@code mode: verify} on its own now also skips
 * tests (write {@code mode: [verify, test]} for the traditional "verify with tests" behavior).
 *
 * <p>{@code fullLogs} (default {@code false}) applies to every {@code mvn} invocation regardless of
 * mode — {@code true} omits {@code --no-transfer-progress}, so dependency download/upload activity
 * shows up in the raw build output, useful when a failure looks repository/network-related.
 *
 * <pre>{@code
 * redkite:
 *   maven:
 *     mode: [run, test]
 *     fullLogs: false
 *     profile: redkite-build
 *     args:
 *       - "--batch-mode"
 *       - "--no-transfer-progress"
 *       - "-Dfoo=bar"
 *     env:
 *       DB_HOST: localhost
 *       DB_PASS: pw
 *     spring:
 *       profiles: redkite-local
 * }</pre>
 *
 * {@code args} accepts either form: a real YAML list (as above — each entry is a single argument,
 * so one containing a space is unambiguous) or a single whitespace-separated string
 * ({@code args: --batch-mode -Dfoo=bar}), split the same way the rest of RedKite's argument
 * handling already does. The list form is the one to reach for when an argument's own value needs
 * to contain a space.
 */
public final class ProjectConfigFile {
    private static final Logger LOGGER = Logger.getLogger(ProjectConfigFile.class.getName());

    private static final String DIRECTORY = ".redkite";
    private static final String BASE_NAME = "settings";

    /** Canonical path, relative to a project's root directory — what {@link #ensureDefaultExists}
     *  scaffolds and what's shown when neither form exists. {@code .yaml} (see
     *  {@link #resolveExistingPath}) is equally valid and takes precedence if both are present. */
    public static final String RELATIVE_PATH = DIRECTORY + "/" + BASE_NAME + ".yml";

    private static final String YAML_RELATIVE_PATH = DIRECTORY + "/" + BASE_NAME + ".yaml";

    public record ProjectConfig(List<String> args, String profile, ValidationRunner.Mode mode,
                                 Map<String, String> env, String springProfiles, boolean enableTests, boolean fullLogs) {
        public static final ProjectConfig EMPTY = new ProjectConfig(List.of(), null, ValidationRunner.Mode.RUN, Map.of(), null, false, false);

        /** {@code args} and {@code profile} folded into one list, in a stable order — applies to
         *  every validation RedKite runs for this project. Does not include
         *  {@link #springProfiles()}, which only ever applies to the {@code spring-boot:run}
         *  startup check specifically; a caller building that command appends
         *  {@link #springBootArgs()} on top of this. */
        public List<String> toBuildArgs() {
            List<String> result = new ArrayList<>(args);
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

    /** Written to {@code <projectRoot>/.redkite/settings.yml} by {@link #ensureDefaultExists} when a
     *  project has none — every field commented out, so its presence alone never changes
     *  validation behavior; it's a discoverable, editable starting point, not a live default. */
    private static final String DEFAULT_TEMPLATE = """
            # RedKite build validation settings for this project — see:
            # https://johnjoeallen.github.io/redkite/projects/build-validation/
            #
            # Uncomment and edit whatever this project actually needs; everything below is
            # optional, and this file is never overwritten once it exists.

            #redkite:
            #  maven:
            #    mode: run              # run (default) | verify | test — or a combination, e.g. [run, test]
            #                           # include "test" to run tests; omitted means -DskipTests
            #    fullLogs: false        # true includes dependency transfer logging — default false
            #    profile: my-profile
            #    args:
            #      - "-Dfoo=bar"
            #    env:
            #      KEY: value
            #    spring:
            #      profiles: my-spring-profile
            """;

    private ProjectConfigFile() {
    }

    /** Writes {@link #DEFAULT_TEMPLATE} to {@code <projectRoot>/.redkite/settings.yml} if neither
     *  that file nor {@code settings.yaml} already exists — so a project gets a discoverable, fully
     *  commented-out starting point the first time RedKite scans it, without ever overwriting
     *  anything already there (including a file the project has deliberately left empty).
     *  Best-effort: a failure to write is logged, never thrown — scaffolding a config file must
     *  never block a scan. */
    public static void ensureDefaultExists(Path projectRoot) {
        if (resolveExistingPath(projectRoot) != null) return;
        Path configPath = projectRoot.resolve(RELATIVE_PATH);
        try {
            Files.createDirectories(configPath.getParent());
            Files.writeString(configPath, DEFAULT_TEMPLATE, StandardCharsets.UTF_8);
            LOGGER.info(() -> "Created default " + RELATIVE_PATH + " for " + projectRoot);
        } catch (IOException e) {
            LOGGER.warning(() -> "Could not create default " + RELATIVE_PATH + " for " + projectRoot + ": " + e.getMessage());
        }
    }

    /** The project's actual config file, if either form exists — {@code settings.yaml} takes
     *  precedence over {@code settings.yml} on the rare occasion both are present. {@code null} if
     *  neither exists. */
    public static Path resolveExistingPath(Path projectRoot) {
        Path yaml = projectRoot.resolve(YAML_RELATIVE_PATH);
        if (Files.exists(yaml)) return yaml;
        Path yml = projectRoot.resolve(RELATIVE_PATH);
        return Files.exists(yml) ? yml : null;
    }

    /** Reads {@code <projectRoot>/.redkite/settings.yaml} or {@code settings.yml} (see
     *  {@link #resolveExistingPath}), or {@link ProjectConfig#EMPTY} if neither exists or fails to
     *  parse (logged, never thrown — a malformed config file shouldn't block analysis or
     *  validation from running at all). */
    public static ProjectConfig load(Path projectRoot) {
        Path configPath = resolveExistingPath(projectRoot);
        if (configPath == null) return ProjectConfig.EMPTY;
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
        if (!(loaded instanceof Map<?, ?> root)
                || !(root.get("redkite") instanceof Map<?, ?> redkite)
                || !(redkite.get("maven") instanceof Map<?, ?> maven)) {
            return ProjectConfig.EMPTY;
        }

        List<String> args = asArgList(maven.get("args"));
        String profile = asString(maven.get("profile"));
        Set<ValidationRunner.Mode> modeTokens = parseModeCombination(maven.get("mode"));
        ValidationRunner.Mode mode = modeTokens.contains(ValidationRunner.Mode.RUN) ? ValidationRunner.Mode.RUN
                : modeTokens.contains(ValidationRunner.Mode.VERIFY) ? ValidationRunner.Mode.VERIFY
                : ValidationRunner.Mode.TEST;
        boolean enableTests = modeTokens.contains(ValidationRunner.Mode.TEST);
        Map<String, String> env = asStringMap(maven.get("env"));
        String springProfiles = maven.get("spring") instanceof Map<?, ?> spring ? asString(spring.get("profiles")) : null;
        boolean fullLogs = asBoolean(maven.get("fullLogs"), false);

        return new ProjectConfig(args, profile, mode, env, springProfiles, enableTests, fullLogs);
    }

    /** Accepts either a real YAML list (each entry becomes one argument as-is) or a single
     *  whitespace-separated scalar string (split the same way the rest of RedKite's argument
     *  handling already does) — see the class doc for when each form is worth reaching for. */
    private static List<String> asArgList(Object value) {
        if (value instanceof List<?> list) {
            List<String> result = new ArrayList<>();
            for (Object item : list) {
                if (item != null && !String.valueOf(item).isBlank()) result.add(String.valueOf(item));
            }
            return List.copyOf(result);
        }
        String scalar = asString(value);
        if (scalar == null || scalar.isBlank()) return List.of();
        List<String> result = new ArrayList<>();
        for (String part : scalar.trim().split("\\s+")) {
            if (!part.isEmpty()) result.add(part);
        }
        return List.copyOf(result);
    }

    /** {@code null} for a missing key; otherwise the scalar's string form, even if the author
     *  wrote something YAML would otherwise infer as a number or boolean (e.g. an all-digit Maven
     *  profile name) — this file only ever means "these are strings", regardless of what YAML's
     *  own type inference would have guessed. */
    private static String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    /** {@code null} falls back to {@code defaultValue}; SnakeYAML already parses an unquoted
     *  {@code true}/{@code false} scalar into a real {@link Boolean}, so this only needs to handle
     *  that and the string form for a quoted value like {@code fullLogs: "false"}. Anything else
     *  unrecognized also falls back to {@code defaultValue} rather than failing the whole file. */
    private static boolean asBoolean(Object value, boolean defaultValue) {
        if (value instanceof Boolean bool) return bool;
        if (value == null) return defaultValue;
        String s = String.valueOf(value).trim();
        if ("true".equalsIgnoreCase(s)) return true;
        if ("false".equalsIgnoreCase(s)) return false;
        LOGGER.warning(() -> "Unrecognized boolean value \"" + s + "\" in " + RELATIVE_PATH + " — defaulting to " + defaultValue);
        return defaultValue;
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

    /** Parses {@code mode} into the set of {@code run}/{@code verify}/{@code test} tokens it names —
     *  a real YAML list ({@code mode: [run, test]}), or a single scalar, itself either one token
     *  ({@code mode: verify}) or several separated by commas and/or whitespace
     *  ({@code mode: run, test}). Case-insensitive; unrecognized tokens are logged and ignored
     *  rather than failing the whole file. A missing key, or a value with no recognizable tokens at
     *  all, falls back to {@code {RUN}} — {@link ValidationRunner.Mode#RUN} with tests skipped,
     *  today's existing default. */
    private static Set<ValidationRunner.Mode> parseModeCombination(Object value) {
        List<String> tokens;
        if (value instanceof List<?> list) {
            tokens = new ArrayList<>();
            for (Object item : list) {
                if (item != null) tokens.add(String.valueOf(item));
            }
        } else {
            String scalar = asString(value);
            tokens = scalar == null ? List.of() : List.of(scalar.trim().split("[,\\s]+"));
        }

        Set<ValidationRunner.Mode> result = EnumSet.noneOf(ValidationRunner.Mode.class);
        for (String token : tokens) {
            if (token.isBlank()) continue;
            ValidationRunner.Mode matched = null;
            for (ValidationRunner.Mode candidate : ValidationRunner.Mode.values()) {
                if (candidate.name().equalsIgnoreCase(token.trim())) {
                    matched = candidate;
                    break;
                }
            }
            if (matched != null) {
                result.add(matched);
            } else {
                LOGGER.warning(() -> "Unrecognized mode token \"" + token + "\" in " + RELATIVE_PATH + " — ignoring");
            }
        }
        if (result.isEmpty()) result.add(ValidationRunner.Mode.RUN);
        return result;
    }
}

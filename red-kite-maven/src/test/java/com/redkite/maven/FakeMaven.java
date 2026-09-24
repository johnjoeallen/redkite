package com.redkite.maven;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;

/**
 * A stand-in {@code mvn} executable for tests: a shell script, installed through the
 * {@code redkite.mvn} system property, that records its arguments and replays canned output and
 * an exit code per goal. Output can also be keyed by the directory of the {@code -f} POM, so a
 * multi-module scan can give each module its own dependency tree.
 */
final class FakeMaven implements AutoCloseable {
    private final Path dir;
    private final String previous;

    private FakeMaven(Path dir) {
        this.dir = dir;
        this.previous = System.getProperty(MavenExecutable.PROPERTY);
    }

    static FakeMaven install(Path dir) throws IOException {
        Files.createDirectories(dir);
        Path script = dir.resolve("mvn");
        Files.writeString(script, """
                #!/bin/sh
                D='%s'
                echo "$@" >> "$D/calls.log"
                G=""
                POM=""
                PREV=""
                for a in "$@"; do
                  case "$a" in
                    dependency:tree|enforcer:enforce|verify|install|test|spring-boot:run) G="$a";;
                  esac
                  if [ "$PREV" = "-f" ]; then POM="$a"; fi
                  PREV="$a"
                done
                G=$(echo "$G" | tr ':' '_')
                M=$(basename "$(dirname "$POM")")
                if [ -n "$POM" ] && [ -f "$POM" ]; then cp "$POM" "$D/last-pom.xml"; ls -a "$(dirname "$POM")" > "$D/last-pom-dir.txt"; fi
                if [ -f "$D/$G@$M.out" ]; then cat "$D/$G@$M.out"; elif [ -f "$D/$G.out" ]; then cat "$D/$G.out"; fi
                if [ -f "$D/$G.sleep" ]; then sleep "$(cat "$D/$G.sleep")"; fi
                if [ -f "$D/$G@$M.exit" ]; then exit "$(cat "$D/$G@$M.exit")"; fi
                if [ -f "$D/$G.exit" ]; then exit "$(cat "$D/$G.exit")"; fi
                exit 0
                """.formatted(dir.toAbsolutePath()));
        Files.setPosixFilePermissions(script, PosixFilePermissions.fromString("rwxr-xr-x"));
        FakeMaven fake = new FakeMaven(dir);
        System.setProperty(MavenExecutable.PROPERTY, script.toAbsolutePath().toString());
        return fake;
    }

    /** Canned output for {@code goal} (e.g. {@code "dependency:tree"}) from every module. */
    FakeMaven output(String goal, String text) throws IOException {
        Files.writeString(dir.resolve(fileName(goal, null) + ".out"), text);
        return this;
    }

    /** Canned output for {@code goal} from the module whose directory is named {@code module}. */
    FakeMaven output(String goal, String module, String text) throws IOException {
        Files.writeString(dir.resolve(fileName(goal, module) + ".out"), text);
        return this;
    }

    FakeMaven exit(String goal, int code) throws IOException {
        Files.writeString(dir.resolve(fileName(goal, null) + ".exit"), String.valueOf(code));
        return this;
    }

    FakeMaven exit(String goal, String module, int code) throws IOException {
        Files.writeString(dir.resolve(fileName(goal, module) + ".exit"), String.valueOf(code));
        return this;
    }

    FakeMaven sleep(String goal, int seconds) throws IOException {
        Files.writeString(dir.resolve(fileName(goal, null) + ".sleep"), String.valueOf(seconds));
        return this;
    }

    /** The POM passed with {@code -f} to the most recent invocation, as it was at that moment. */
    String lastPom() throws IOException {
        return Files.readString(dir.resolve("last-pom.xml"));
    }

    /** Directory entries next to the POM passed to the most recent invocation. */
    List<String> lastPomDirEntries() throws IOException {
        return Files.readAllLines(dir.resolve("last-pom-dir.txt"));
    }

    /** Each invocation's arguments, one line per call. */
    List<String> calls() throws IOException {
        Path log = dir.resolve("calls.log");
        return Files.exists(log) ? Files.readAllLines(log) : List.of();
    }

    private static String fileName(String goal, String module) {
        String g = goal.replace(':', '_');
        return module == null ? g : g + "@" + module;
    }

    @Override
    public void close() {
        if (previous == null) System.clearProperty(MavenExecutable.PROPERTY);
        else System.setProperty(MavenExecutable.PROPERTY, previous);
    }
}

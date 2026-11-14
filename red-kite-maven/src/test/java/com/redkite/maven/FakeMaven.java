package com.redkite.maven;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.net.URISyntaxException;
import java.util.List;

/**
 * A stand-in {@code mvn} executable for tests: a launcher for {@link FakeMavenMain}, installed through the
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
        Path script = writeLauncher(dir, FakeMavenMain.class);
        FakeMaven fake = new FakeMaven(dir);
        System.setProperty(MavenExecutable.PROPERTY, script.toAbsolutePath().toString());
        return fake;
    }

    /**
     * Writes an {@code mvn} (Unix) or {@code mvn.cmd} (Windows) wrapper in {@code dir} that runs
     * {@code mainClass} on the current JVM, passing {@code dir} and then its own arguments. Test code
     * is Java so nothing depends on a POSIX shell or file permissions.
     */
    static Path writeLauncher(Path dir, Class<?> mainClass) throws IOException {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        String classes;
        try {
            classes = Path.of(mainClass.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        } catch (URISyntaxException e) {
            throw new IOException(e);
        }
        boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
        Path script = dir.resolve(windows ? "mvn.cmd" : "mvn");
        if (windows) {
            Files.writeString(script, "@echo off\r\n\"" + java + "\" -cp \"" + classes + "\" " + mainClass.getName()
                    + " \"" + dir.toAbsolutePath() + "\" %*\r\nexit /b %ERRORLEVEL%\r\n");
        } else {
            Files.writeString(script, "#!/bin/sh\nexec '" + java + "' -cp '" + classes + "' " + mainClass.getName()
                    + " '" + dir.toAbsolutePath() + "' \"$@\"\n");
            Files.setPosixFilePermissions(script, PosixFilePermissions.fromString("rwxr-xr-x"));
        }
        return script;
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

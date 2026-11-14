package com.redkite.maven;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * The behaviour of the stand-in {@code mvn} installed by {@link FakeMaven}. It is a Java program
 * (launched by a tiny {@code mvn}/{@code mvn.cmd} wrapper) rather than a shell script so the tests
 * run the same on Windows and Unix. First argument: the fake's state directory; the rest are the
 * arguments Maven was called with.
 */
public final class FakeMavenMain {
    private static final Set<String> GOALS =
            Set.of("dependency:tree", "enforcer:enforce", "verify", "install", "test", "spring-boot:run");

    private FakeMavenMain() {}

    public static void main(String[] args) throws Exception {
        Path dir = Path.of(args[0]);
        List<String> mvnArgs = List.of(args).subList(1, args.length);
        Files.writeString(dir.resolve("calls.log"), String.join(" ", mvnArgs) + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);

        String goal = "";
        Path pom = null;
        String prev = "";
        for (String a : mvnArgs) {
            if (GOALS.contains(a)) goal = a;
            if (prev.equals("-f")) pom = Path.of(a);
            prev = a;
        }
        goal = goal.replace(':', '_');
        String module = pom == null || pom.getParent() == null || pom.getParent().getFileName() == null
                ? "" : pom.getParent().getFileName().toString();
        if (pom != null && Files.isRegularFile(pom)) {
            Files.copy(pom, dir.resolve("last-pom.xml"), StandardCopyOption.REPLACE_EXISTING);
            try (Stream<Path> entries = Files.list(pom.toAbsolutePath().getParent())) {
                Files.write(dir.resolve("last-pom-dir.txt"),
                        Stream.concat(Stream.of(".", ".."), entries.map(p -> p.getFileName().toString())).sorted().toList());
            }
        }
        Path moduleOut = dir.resolve(goal + "@" + module + ".out");
        Path out = dir.resolve(goal + ".out");
        if (Files.exists(moduleOut)) print(moduleOut);
        else if (Files.exists(out)) print(out);
        Path sleep = dir.resolve(goal + ".sleep");
        if (Files.exists(sleep)) Thread.sleep((long) (Double.parseDouble(Files.readString(sleep).trim()) * 1000));
        for (Path exit : new Path[] {dir.resolve(goal + "@" + module + ".exit"), dir.resolve(goal + ".exit")}) {
            if (Files.exists(exit)) System.exit(Integer.parseInt(Files.readString(exit).trim()));
        }
        System.exit(0);
    }

    private static void print(Path file) throws IOException {
        System.out.print(Files.readString(file));
        System.out.flush();
    }
}

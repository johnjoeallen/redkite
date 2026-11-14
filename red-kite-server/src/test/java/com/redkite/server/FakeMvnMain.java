package com.redkite.server;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Set;

/**
 * Behaviour of the fake {@code mvn} used by {@link ServerFixture}. A Java program (started by a
 * small {@code mvn}/{@code mvn.cmd} wrapper) so the tests run on Windows as well as Unix. First
 * argument: the fake's state directory; the rest are Maven's arguments.
 */
public final class FakeMvnMain {
    private static final Set<String> GOALS =
            Set.of("dependency:tree", "enforcer:enforce", "verify", "install", "test", "spring-boot:run");

    private FakeMvnMain() {}

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
        Path rules = dir.resolve(goal + ".rules");
        if (Files.exists(rules) && pom != null && Files.isRegularFile(pom)) {
            String pomText = Files.readString(pom);
            for (String line : Files.readAllLines(rules)) {
                String[] parts = line.split("\\|", 3);
                if (parts.length == 3 && !parts[0].isEmpty() && pomText.contains(parts[0])) {
                    System.out.print(Files.readString(dir.resolve(parts[2])));
                    System.out.flush();
                    System.exit(Integer.parseInt(parts[1]));
                }
            }
        }
        Path out = dir.resolve(goal + ".out");
        if (Files.exists(out)) {
            System.out.print(Files.readString(out));
            System.out.flush();
        }
        Path sleep = dir.resolve(goal + ".sleep");
        if (Files.exists(sleep)) Thread.sleep((long) (Double.parseDouble(Files.readString(sleep).trim()) * 1000));
        Path exit = dir.resolve(goal + ".exit");
        if (Files.exists(exit)) System.exit(Integer.parseInt(Files.readString(exit).trim()));
        System.exit(0);
    }
}

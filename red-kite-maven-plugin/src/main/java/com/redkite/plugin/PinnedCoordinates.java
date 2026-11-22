package com.redkite.plugin;

import com.redkite.maven.RemediationApplier;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Stream;

/** Finds the dependencies a user has pinned with a {@code redkite:user-pin} marker in any project POM. */
final class PinnedCoordinates {
    private PinnedCoordinates() {}

    /** {@code groupId:artifactId} of every pinned dependency; unreadable POMs are skipped. */
    static Set<String> find(Path root, java.util.Collection<String> excludes) {
        return find(root, false, excludes);
    }

    /** {@code groupId:artifactId} of every dependency held by a RedKite-managed pin. */
    static Set<String> findRedkitePins(Path root, java.util.Collection<String> excludes) {
        return find(root, true, excludes);
    }

    private static Set<String> find(Path root, boolean redkite, java.util.Collection<String> excludeDirs) {
        Set<String> pinned = new LinkedHashSet<>();
        RemediationApplier applier = new RemediationApplier();
        com.redkite.maven.ScanExcludes excludes = com.redkite.maven.ScanExcludes.of(excludeDirs);
        try (Stream<Path> files = Files.walk(root)) {
            files.filter(p -> p.getFileName().toString().equals("pom.xml"))
                    .filter(p -> !excludes.excludes(root, p))
                    .filter(p -> {
                        Path rel = root.relativize(p);
                        for (Path part : rel) {
                            String n = part.toString();
                            if (n.equals("target") || n.equals(".git") || n.equals("node_modules")) return false;
                        }
                        return true;
                    })
                    .forEach(p -> {
                        try {
                            String content = Files.readString(p);
                            pinned.addAll(redkite ? applier.findRedkitePinnedCoordinates(content)
                                    : applier.findUserPinnedCoordinates(content));
                        } catch (IOException | RuntimeException ignored) {
                            // a POM we cannot read or parse simply contributes no pins
                        }
                    });
        } catch (IOException ignored) {
            // no pins found
        }
        return pinned;
    }
}

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
    static Set<String> find(Path root) {
        Set<String> pinned = new LinkedHashSet<>();
        RemediationApplier applier = new RemediationApplier();
        try (Stream<Path> files = Files.walk(root)) {
            files.filter(p -> p.getFileName().toString().equals("pom.xml"))
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
                            pinned.addAll(applier.findUserPinnedCoordinates(Files.readString(p)));
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

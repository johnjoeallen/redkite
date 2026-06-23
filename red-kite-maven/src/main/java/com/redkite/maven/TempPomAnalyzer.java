package com.redkite.maven;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Logger;

/**
 * Creates a temporary POM copy with all RedKite-managed remediations stripped,
 * then runs the enforcer against it to detect what conflicts exist without RedKite's help.
 *
 * <p>This allows RedKite to re-detect conflicts even after applying exclusions,
 * so stale remediations can be identified.
 */
public class TempPomAnalyzer {

    private static final Logger LOGGER = Logger.getLogger(TempPomAnalyzer.class.getName());

    private final RemediationApplier applier = new RemediationApplier();
    private final EnforcerRunner runner = new EnforcerRunner();

    /**
     * Runs the enforcer against a stripped copy of {@code pomPath}.
     * The original POM is not modified.
     */
    public EnforcerRunner.EnforcerRunResult runWithoutRemediations(Path projectRoot, Path pomPath)
            throws IOException {
        String content = Files.readString(pomPath, StandardCharsets.UTF_8);
        String stripped = applier.stripRedkiteRemediations(content);

        if (stripped.equals(content)) {
            // No redkite content to strip — run directly
            return runner.run(projectRoot, pomPath);
        }

        // Must sit next to the real pom.xml so relative <module> paths resolve correctly
        Path tempPom = pomPath.resolveSibling(".redkite-temp-pom.xml");
        try {
            Files.writeString(tempPom, stripped, StandardCharsets.UTF_8);
            LOGGER.info(() -> "Running enforcer against stripped temp POM: " + tempPom);
            return runner.run(projectRoot, tempPom);
        } finally {
            Files.deleteIfExists(tempPom);
        }
    }
}

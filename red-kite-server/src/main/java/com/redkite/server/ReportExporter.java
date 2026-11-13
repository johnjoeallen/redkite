package com.redkite.server;

import com.redkite.core.domain.AdvisorySeverity;
import com.redkite.core.domain.RecommendationReason;
import com.redkite.core.domain.ScanInput;
import com.redkite.core.domain.ScanReport;
import com.redkite.core.domain.UpgradeRecommendation;
import com.redkite.core.service.AdvisoryClassifier;
import com.redkite.maven.MavenProjectScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Headless entry point used by the RedKite Maven plugin: runs the same analysis as the server
 * (dependency scan, Maven Central metadata, OSV vulnerabilities, licenses, recommendations),
 * and records it in the local H2 database.
 */
public final class ReportExporter {
    private ReportExporter() {}

    /** The outcome of one headless analysis. */
    public record Result(String scanId, ScanReport report, List<Remediation> remediations) {}

    /**
     * A version RedKite recommends to clear a vulnerable dependency's CVEs, with what is left over
     * at that version. {@code residualSeverity} is the worst vulnerability still present at
     * {@code targetVersion} ({@link AdvisorySeverity#NONE} when it is clean), and {@code sameMajor}
     * says whether the target stays on the dependency's current major version.
     */
    public record Remediation(String groupId, String artifactId, String currentVersion, String targetVersion,
                              RecommendationReason reason, AdvisorySeverity residualSeverity, boolean sameMajor) {}

    /** The default local database URL: a plugin-only database shared by all projects, kept apart from
     *  the server's {@code ~/.redkite/redkite} so the two never contend for the file lock. AUTO_SERVER
     *  lets parallel builds on one machine share it. */
    public static String defaultJdbcUrl() {
        Path dataDir = Path.of(System.getProperty("user.home"), ".redkite", "plugin");
        return "jdbc:h2:" + dataDir.resolve("redkite")
                + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;AUTO_SERVER=TRUE";
    }

    /**
     * @param projectRoot   directory containing the root {@code pom.xml}
     * @param jdbcUrl       H2 database to cache metadata and record the scan in
     * @param runEnforcer   also run the dependency-convergence analysis (several extra Maven runs)
     * @param allowMajor    allow major-version upgrade recommendations
     * @param progress      receives coarse progress messages
     * @param mavenOutput   receives each line of Maven output produced by the scan (may be null)
     */
    public static Result analyse(Path projectRoot, String jdbcUrl, boolean runEnforcer, boolean allowMajor,
                                 Consumer<String> progress, Consumer<String> mavenOutput) throws IOException {
        Path root = projectRoot.toAbsolutePath().normalize();
        if (!Files.exists(root.resolve("pom.xml"))) {
            throw new IOException("No pom.xml found at " + root);
        }
        Store store = Store.connect(jdbcUrl, "sa", "");
        store.reconfigureForProject(root);
        ScanInput input = new MavenProjectScanner(allowMajor).scan(root, progress, mavenOutput);
        ScanReport report = store.ingest(input, progress);
        if (runEnforcer) {
            new EnforcerAnalysis(store).runEnforcerCheck(root, report.scanId(), progress,
                    mavenOutput != null ? mavenOutput : line -> {});
        }
        return new Result(report.scanId(), report, remediations(store, report));
    }

    /** One entry per CVE-driven recommendation, with the residual severity looked up (cached) at its target. */
    private static List<Remediation> remediations(Store store, ScanReport report) {
        List<Remediation> out = new ArrayList<>();
        for (UpgradeRecommendation r : report.recommendations()) {
            if (r.reason() != RecommendationReason.CVE_FIX && r.reason() != RecommendationReason.CVE_FIX_DOWNGRADE
                    && r.reason() != RecommendationReason.CVE_BEST_EFFORT) {
                continue;
            }
            AdvisorySeverity residual = AdvisoryClassifier.highest(
                    store.vulnerabilityProvider.vulnerabilities(r.coordinate(), r.targetVersion()));
            out.add(new Remediation(r.coordinate().groupId(), r.coordinate().artifactId(), r.currentVersion(),
                    r.targetVersion(), r.reason(), residual,
                    Versions.major(r.currentVersion()) == Versions.major(r.targetVersion())));
        }
        return out;
    }
}

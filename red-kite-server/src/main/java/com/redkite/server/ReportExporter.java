package com.redkite.server;

import com.redkite.core.domain.ScanInput;
import com.redkite.core.domain.ScanReport;
import com.redkite.maven.MavenProjectScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

/**
 * Headless entry point used by the RedKite Maven plugin: runs the same analysis as the server
 * (dependency scan, Maven Central metadata, OSV vulnerabilities, licenses, recommendations),
 * records it in the local H2 database, and renders the same analysis page as a static report.
 */
public final class ReportExporter {
    private ReportExporter() {}

    /** The outcome of one headless analysis. */
    public record Result(String scanId, ScanReport report, String html) {}

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
        Path prefs = Path.of(System.getProperty("user.home"), ".redkite", "preferences.properties");
        Pages pages = new Pages(prefs);
        PageHandlers handlers = new PageHandlers(store, pages,
                new ScanPageRenderer(store, new ComponentCardRenderer(store.vulnerabilityProvider)),
                new EnforcerSectionRenderer(store, new EnforcerAnalysis(store)),
                new LogModalRenderer(store, new EnforcerAnalysis(store)));
        return new Result(report.scanId(), report, handlers.renderScanPage(report.scanId(), false));
    }
}

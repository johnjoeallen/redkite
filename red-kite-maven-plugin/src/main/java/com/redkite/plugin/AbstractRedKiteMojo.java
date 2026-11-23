package com.redkite.plugin;

import com.redkite.server.ReportExporter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import org.apache.maven.plugin.AbstractMojo;
import java.util.List;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Shared parameters and the analyse-and-write step for the RedKite goals. */
abstract class AbstractRedKiteMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    MavenProject project;

    /** Skip RedKite entirely. */
    @Parameter(property = "redkite.skip", defaultValue = "false")
    boolean skip;

    /** Also write a JSON copy of the report to {@code outputDirectory}. Off by default: the plugin
     *  writes no report files unless asked. */
    @Parameter(property = "redkite.jsonReport", defaultValue = "false")
    boolean jsonReport;

    /** Directory the JSON report is written to when {@code jsonReport} is true. */
    @Parameter(property = "redkite.outputDirectory", defaultValue = "${project.build.directory}/redkite")
    File outputDirectory;

    /** Keep a persistent cache of Maven Central and OSV lookups between builds. Disabled by default:
     *  each build then uses a throwaway in-memory database, queries the sources afresh and leaves
     *  nothing on disk. When enabled, {@code databaseUrl} (or the default plugin database) is used.
     *  When not set explicitly ({@code -Dredkite.cache} or POM configuration), the {@code RK_CACHE}
     *  environment variable decides: {@code RK_CACHE=true} enables it, so a developer can turn the cache
     *  on locally while CI, where the variable is unset, keeps it off. */
    @Parameter(property = "redkite.cache")
    Boolean cache;

    /** Whether the persistent cache is on: the explicit setting wins, then {@code RK_CACHE}, then off. */
    boolean cacheEnabled() {
        return cache != null ? cache : "true".equalsIgnoreCase(System.getenv("RK_CACHE"));
    }

    /** H2 database holding the metadata cache and scan history; only used when {@code cache} is true. Defaults to a plugin-only database
     *  shared by all projects (<code>~/.redkite/plugin/redkite</code>), separate from the server's. */
    @Parameter(property = "redkite.db.url",
            defaultValue = "jdbc:h2:${user.home}/.redkite/plugin/redkite;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;AUTO_SERVER=TRUE")
    String databaseUrl;

    /** Also run the dependency-convergence (enforcer) analysis. Slower: several extra Maven runs. */
    @Parameter(property = "redkite.enforcer", defaultValue = "false")
    boolean enforcer;

    /** Allow major-version upgrade recommendations. */
    @Parameter(property = "redkite.allowMajorUpgrades", defaultValue = "false")
    boolean allowMajorUpgrades;

    /** List plain "newer version exists" updates for transitive dependencies too. Off by default:
     *  nothing in the project forces them to move, so the server's Outdated count leaves them out. */
    @Parameter(property = "redkite.showTransitives", defaultValue = "false")
    boolean showTransitives;

    /** Print the text report to the build log. */
    @Parameter(property = "redkite.consoleReport", defaultValue = "true")
    boolean consoleReport;

    /** Show progress while analysing: a live status line on a terminal, one log line per phase elsewhere. */
    @Parameter(property = "redkite.progress", defaultValue = "true")
    boolean showProgress;

    /** Directories, relative to the project root, whose POMs are not analysed (test fixtures, samples). */
    @Parameter(property = "redkite.excludes")
    java.util.List<String> excludes;

    /** Vulnerabilities the project accepts until a date. Each entry needs an {@code advisory} and an {@code until}
     *  date (yyyy-MM-dd, inclusive); {@code coordinate} and {@code reason} are optional. After the date the
     *  vulnerability is reported again. */
    @Parameter
    java.util.List<AcceptedRisk> acceptedRisks;

    @Parameter(defaultValue = "${session}", readonly = true)
    MavenSession session;

    /** Warn when an accepted risk ends within this many days. 0 turns the warning off. */
    @Parameter(property = "redkite.warnExpiringWithin", defaultValue = "30")
    int warnExpiringWithin;

    /** Today, for deciding whether an accepted risk has expired; overridden in tests. */
    java.time.LocalDate today() {
        return java.time.LocalDate.now();
    }

    abstract void execute(ReportExporter.Result result) throws MojoFailureException;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("RedKite is skipped.");
            return;
        }
        List<String> invalid = AcceptedRisks.validate(acceptedRisks);
        if (!invalid.isEmpty()) {
            throw new MojoExecutionException("Invalid RedKite configuration: " + String.join("; ", invalid));
        }
        ReportExporter.Result result;
        // RedKite's analysis classes log every component at INFO; keep that out of the build log
        // unless Maven is running with -X.
        java.util.logging.Logger rk = java.util.logging.Logger.getLogger("com.redkite");
        java.util.logging.Level previous = rk.getLevel();
        rk.setLevel(getLog().isDebugEnabled() ? java.util.logging.Level.INFO : java.util.logging.Level.WARNING);
        try {
            Path root = project.getBasedir().toPath();
            String url = !cacheEnabled() ? ReportExporter.inMemoryJdbcUrl()
                    : databaseUrl != null && !databaseUrl.isBlank() ? databaseUrl : ReportExporter.defaultJdbcUrl();
            getLog().info("RedKite analysing " + root + (cacheEnabled() ? " (cache " + url + ")" : " (cache disabled)"));
            boolean animate = showProgress && ProgressLine.shouldAnimate(
                    session == null || session.getRequest().isInteractiveMode(), getLog().isDebugEnabled(),
                    ProgressLine.stdoutIsTerminal(), System.getenv("CI"), System.getenv("TERM"));
            boolean unicode = !System.getProperty("os.name", "").toLowerCase().contains("win");
            try (ProgressLine progress = new ProgressLine(animate, System.out,
                    msg -> getLog().info(msg), unicode)) {
                progress.start();
                result = ReportExporter.analyse(root, url, enforcer, allowMajorUpgrades,
                        msg -> { getLog().debug(msg); if (showProgress) progress.update(msg); },
                        line -> getLog().debug(line), excludes);
            }
            AcceptedRisks.Result split = AcceptedRisks.apply(result.report(), acceptedRisks, today(), warnExpiringWithin);
            for (AcceptedRisks.Entry e : split.expired()) {
                getLog().warn("RedKite: the accepted risk " + e.risk() + " expired on " + e.until() + "; it is reported again.");
            }
            for (AcceptedRisks.Entry e : split.expiringSoon()) {
                getLog().warn("RedKite: the accepted risk " + e.risk() + " expires " + AcceptedRisks.remaining(today(), e.until())
                        + " (" + e.until() + "); decide whether to extend it or fix the vulnerability.");
            }
            for (AcceptedRisk r : split.unmatched()) {
                getLog().warn("RedKite: the accepted risk " + r + " matches no vulnerability; remove it from acceptedRisks.");
            }
            ReportExporter.Result full = result;
            result = AcceptedRisks.filter(result, split);
            String text = TextReport.render(result.report(), showTransitives, PinnedCoordinates.find(root, excludes),
                    PinnedCoordinates.findRedkitePins(root, excludes), buildPomPaths(root), split, today());
            if (consoleReport) {
                getLog().info(System.lineSeparator() + text);
            }
            if (jsonReport) {
                Path out = outputDirectory.toPath();
                ReportWriter.writeJson(out, full.report());
                getLog().info("RedKite JSON report written to " + out.resolve("redkite-report.json"));
            }
        } catch (IOException | RuntimeException e) {
            throw new MojoExecutionException("RedKite analysis failed: " + e.getMessage(), e);
        } finally {
            rk.setLevel(previous);
        }
        execute(result);
    }

    /** Project-relative paths of the POMs in this build, or null when the session is unavailable. */
    private java.util.Set<String> buildPomPaths(Path root) {
        if (session == null || session.getProjects() == null) return null;
        java.util.Set<String> out = new java.util.LinkedHashSet<>();
        for (org.apache.maven.project.MavenProject p : session.getProjects()) {
            if (p.getFile() == null) continue;
            out.add(root.toAbsolutePath().normalize().relativize(p.getFile().toPath().toAbsolutePath().normalize())
                    .toString().replace('\\', '/'));
        }
        return out;
    }
}

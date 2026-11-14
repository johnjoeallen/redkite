package com.redkite.plugin;

import com.redkite.server.ReportExporter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import org.apache.maven.plugin.AbstractMojo;
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
     *  nothing on disk. When enabled, {@code databaseUrl} (or the default plugin database) is used. */
    @Parameter(property = "redkite.cache", defaultValue = "false")
    boolean cache;

    /** H2 database holding the metadata cache and scan history; only used when {@code cache} is true. Defaults to a plugin-only database
     *  shared by all projects (<code>~/.redkite/plugin/redkite</code>), separate from the server's. */
    @Parameter(property = "redkite.db.url")
    String databaseUrl;

    /** Also run the dependency-convergence (enforcer) analysis. Slower: several extra Maven runs. */
    @Parameter(property = "redkite.enforcer", defaultValue = "false")
    boolean enforcer;

    /** Allow major-version upgrade recommendations. */
    @Parameter(property = "redkite.allowMajorUpgrades", defaultValue = "false")
    boolean allowMajorUpgrades;

    /** Print the text report to the build log. */
    @Parameter(property = "redkite.consoleReport", defaultValue = "true")
    boolean consoleReport;

    /** Show progress while analysing: a live status line on a terminal, one log line per phase elsewhere. */
    @Parameter(property = "redkite.progress", defaultValue = "true")
    boolean showProgress;

    @Parameter(defaultValue = "${session}", readonly = true)
    MavenSession session;

    abstract void execute(ReportExporter.Result result) throws MojoFailureException;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("RedKite is skipped.");
            return;
        }
        ReportExporter.Result result;
        // RedKite's analysis classes log every component at INFO; keep that out of the build log
        // unless Maven is running with -X.
        java.util.logging.Logger rk = java.util.logging.Logger.getLogger("com.redkite");
        java.util.logging.Level previous = rk.getLevel();
        rk.setLevel(getLog().isDebugEnabled() ? java.util.logging.Level.INFO : java.util.logging.Level.WARNING);
        try {
            Path root = project.getBasedir().toPath();
            String url = !cache ? ReportExporter.inMemoryJdbcUrl()
                    : databaseUrl != null && !databaseUrl.isBlank() ? databaseUrl : ReportExporter.defaultJdbcUrl();
            getLog().info("RedKite analysing " + root + (cache ? " (cache " + url + ")" : " (cache disabled)"));
            boolean animate = showProgress && ProgressLine.shouldAnimate(
                    session == null || session.getRequest().isInteractiveMode(), getLog().isDebugEnabled(),
                    ProgressLine.stdoutIsTerminal(), System.getenv("CI"), System.getenv("TERM"));
            boolean unicode = !System.getProperty("os.name", "").toLowerCase().contains("win");
            try (ProgressLine progress = new ProgressLine(animate, System.out,
                    msg -> getLog().info(msg), unicode)) {
                progress.start();
                result = ReportExporter.analyse(root, url, enforcer, allowMajorUpgrades,
                        msg -> { getLog().debug(msg); if (showProgress) progress.update(msg); },
                        line -> getLog().debug(line));
            }
            String text = TextReport.render(result.report());
            if (consoleReport) {
                getLog().info(System.lineSeparator() + text);
            }
            if (jsonReport) {
                Path out = outputDirectory.toPath();
                ReportWriter.writeJson(out, result.report());
                getLog().info("RedKite JSON report written to " + out.resolve("redkite-report.json"));
            }
        } catch (IOException | RuntimeException e) {
            throw new MojoExecutionException("RedKite analysis failed: " + e.getMessage(), e);
        } finally {
            rk.setLevel(previous);
        }
        execute(result);
    }
}

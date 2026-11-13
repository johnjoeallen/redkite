package com.redkite.plugin;

import com.redkite.server.ReportExporter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

/** Shared parameters and the analyse-and-write step for the RedKite goals. */
abstract class AbstractRedKiteMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    MavenProject project;

    /** Skip RedKite entirely. */
    @Parameter(property = "redkite.skip", defaultValue = "false")
    boolean skip;

    /** Directory the JSON report is written to. */
    @Parameter(property = "redkite.outputDirectory", defaultValue = "${project.build.directory}/redkite")
    File outputDirectory;

    /** H2 database holding the metadata cache and scan history. Defaults to a plugin-only database
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
            String url = databaseUrl != null && !databaseUrl.isBlank() ? databaseUrl : ReportExporter.defaultJdbcUrl();
            getLog().info("RedKite analysing " + root + " (database " + url + ")");
            result = ReportExporter.analyse(root, url, enforcer, allowMajorUpgrades,
                    msg -> getLog().debug(msg), line -> getLog().debug(line));
            Path out = outputDirectory.toPath();
            ReportWriter.writeJson(out, result.report());
            String text = TextReport.render(result.report());
            if (consoleReport) {
                getLog().info(System.lineSeparator() + text);
            }
            getLog().info("RedKite JSON report written to " + out.resolve("redkite-report.json"));
        } catch (IOException | RuntimeException e) {
            throw new MojoExecutionException("RedKite analysis failed: " + e.getMessage(), e);
        } finally {
            rk.setLevel(previous);
        }
        execute(result);
    }
}

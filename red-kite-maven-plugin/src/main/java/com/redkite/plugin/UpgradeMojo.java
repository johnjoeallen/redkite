package com.redkite.plugin;

import com.redkite.server.ReportExporter;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;

/**
 * Upgrades exactly the dependencies you name, the command-line counterpart of the server's "Apply
 * selected": {@code -Dredkite.upgrades=groupId:artifactId[:version],...}. A direct dependency is upgraded
 * where it is declared; a transitive one is pinned in the root POM. No version means RedKite's recommended
 * one. This is the only upgrade goal that changes a pinned dependency, and it keeps the pin at the new version.
 */
@Mojo(name = "upgrade", aggregator = true, requiresProject = true, requiresDependencyResolution = ResolutionScope.NONE, threadSafe = false)
public class UpgradeMojo extends PomChangeMojo {
    /** Upgrades to apply: comma-separated {@code groupId:artifactId} (recommended version) or
     *  {@code groupId:artifactId:version}. Required. */
    @Parameter(property = "redkite.upgrades")
    String upgrades;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            super.execute();
            return;
        }
        // Fail fast on a missing or malformed argument, before the slow analysis.
        if (parse(upgrades).isEmpty()) {
            throw new MojoFailureException("Say which dependencies to upgrade: -Dredkite.upgrades=groupId:artifactId[:version],... "
                    + "(no version means the recommended one; a transitive dependency is pinned). "
                    + "To upgrade everything RedKite recommends use redkite:upgrade-all, for CVE fixes only redkite:upgrade-cve.");
        }
        super.execute();
    }

    @Override
    void execute(ReportExporter.Result result) throws MojoFailureException {
        change(result, parse(upgrades), false, java.util.Set.of(), java.util.Set.of());
    }
}

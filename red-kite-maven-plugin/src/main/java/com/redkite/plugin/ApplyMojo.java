package com.redkite.plugin;

import com.redkite.server.PomUpgrader;
import com.redkite.server.ReportExporter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

/**
 * Changes the project's POMs for the dependencies you name, the command-line counterpart of the
 * server's "Apply selected":
 * <ul>
 *   <li>{@code -Dredkite.upgrades=groupId:artifactId[:version],...} upgrades a direct dependency where it is
 *       declared, or pins a transitive one in the root POM. No version means RedKite's recommended one.
 *   <li>{@code -Dredkite.drop=groupId:artifactId,...} drops RedKite's pin for those dependencies again.
 * </ul>
 * {@code -Dredkite.dryRun=true} shows the change without writing anything. Run {@code redkite:report}
 * first to see what is recommended.
 */
@Mojo(name = "apply", aggregator = true, requiresProject = true, requiresDependencyResolution = ResolutionScope.NONE, threadSafe = false)
public class ApplyMojo extends AbstractRedKiteMojo {
    /** Upgrades to apply: comma-separated {@code groupId:artifactId} (recommended version) or
     *  {@code groupId:artifactId:version}. A transitive dependency is pinned. */
    @Parameter(property = "redkite.upgrades")
    String upgrades;

    /** Pins to drop: comma-separated {@code groupId:artifactId}. Needs no analysis. */
    @Parameter(property = "redkite.drop")
    String drop;

    /** Show what would change and write nothing. */
    @Parameter(property = "redkite.dryRun", defaultValue = "false")
    boolean dryRun;

    /** Parses {@code g:a[:v],g:a[:v]} into {@code g:a -> v} (null when no version was given). */
    static Map<String, String> parse(String spec) throws MojoFailureException {
        Map<String, String> out = new LinkedHashMap<>();
        if (spec == null) return out;
        for (String item : spec.split(",")) {
            String s = item.trim();
            if (s.isEmpty()) continue;
            String[] p = s.split(":", -1);
            if (p.length < 2 || p.length > 3 || p[0].isBlank() || p[1].isBlank() || (p.length == 3 && p[2].isBlank())) {
                throw new MojoFailureException("Bad upgrade '" + s + "': expected groupId:artifactId or groupId:artifactId:version");
            }
            out.put(p[0].trim() + ":" + p[1].trim(), p.length == 3 ? p[2].trim() : null);
        }
        return out;
    }

    /** Parses {@code g:a,g:a} (no versions) into a set. */
    static Set<String> parseCoordinates(String spec) throws MojoFailureException {
        Set<String> out = new LinkedHashSet<>();
        if (spec == null) return out;
        for (String item : spec.split(",")) {
            String s = item.trim();
            if (s.isEmpty()) continue;
            String[] p = s.split(":", -1);
            if (p.length != 2 || p[0].isBlank() || p[1].isBlank()) {
                throw new MojoFailureException("Bad pin '" + s + "': expected groupId:artifactId");
            }
            out.add(p[0].trim() + ":" + p[1].trim());
        }
        return out;
    }

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            super.execute();
            return;
        }
        // Fail fast on a missing or malformed argument, before any slow analysis.
        Map<String, String> wanted = parse(upgrades);
        Set<String> drops = parseCoordinates(drop);
        if (wanted.isEmpty() && drops.isEmpty()) {
            throw new MojoFailureException("Say what to change: -Dredkite.upgrades=groupId:artifactId[:version],... "
                    + "(no version means the recommended one; a transitive dependency is pinned) and/or "
                    + "-Dredkite.drop=groupId:artifactId,... to drop pins. Run redkite:report to see what is recommended.");
        }
        for (String coord : drops) {
            if (wanted.containsKey(coord)) {
                throw new MojoFailureException(coord + " is both upgraded and dropped, pick one.");
            }
        }
        if (wanted.isEmpty()) {
            apply(null); // dropping pins needs no analysis
        } else {
            super.execute();
        }
    }

    @Override
    void execute(ReportExporter.Result result) throws MojoFailureException {
        apply(result);
    }

    private void apply(ReportExporter.Result result) throws MojoFailureException {
        Path root = project.getBasedir().toPath();
        PomUpgrader.Plan plan;
        try {
            plan = PomUpgrader.plan(root, pomFiles(), result, parse(upgrades), parseCoordinates(drop));
        } catch (IOException e) {
            throw new MojoFailureException("RedKite could not prepare the changes: " + e.getMessage(), e);
        }
        for (String problem : plan.problems()) getLog().warn("Skipped " + problem);
        for (PomUpgrader.Change c : plan.changes().stream().distinct().toList()) {
            String verb = c.pin() ? (dryRun ? "Would pin " : "Pinning ") : (dryRun ? "Would upgrade " : "Upgrading ");
            getLog().info(verb + c.groupId() + ":" + c.artifactId() + " " + c.currentVersion() + " -> " + c.targetVersion());
        }
        for (String coord : plan.dropped()) {
            getLog().info((dryRun ? "Would drop the pin for " : "Dropping the pin for ") + coord);
        }
        if (plan.patchedPoms().isEmpty()) {
            if (plan.problems().isEmpty()) {
                getLog().info("RedKite: nothing to change, the requested versions are already in place.");
                return;
            }
            throw new MojoFailureException("RedKite: none of the requested changes could be applied.");
        }
        if (dryRun) {
            getLog().info("RedKite dry run: would modify " + String.join(", ", plan.patchedPoms().keySet()) + " (nothing written).");
        } else {
            try {
                PomUpgrader.write(root, plan);
            } catch (IOException e) {
                throw new MojoFailureException("RedKite could not write the POMs: " + e.getMessage(), e);
            }
            getLog().info("RedKite modified " + String.join(", ", plan.patchedPoms().keySet())
                    + ". Review the diff, then run your build to validate it.");
        }
        if (!plan.problems().isEmpty()) {
            throw new MojoFailureException(plan.problems().size() + " requested change(s) could not be applied, see the warnings above.");
        }
    }

    /** The root POM plus every module POM in the build, so pin counts and drops cover the whole project. */
    private List<Path> pomFiles() {
        List<Path> out = new ArrayList<>();
        if (session != null && session.getProjects() != null) {
            for (MavenProject p : session.getProjects()) {
                if (p.getFile() != null) out.add(p.getFile().toPath());
            }
        }
        return out;
    }
}

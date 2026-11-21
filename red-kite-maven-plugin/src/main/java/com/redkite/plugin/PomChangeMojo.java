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
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

/** Shared by the goals that edit POMs: plans the change, logs it, and writes it unless {@code dryRun}. */
abstract class PomChangeMojo extends AbstractRedKiteMojo {
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
                throw new MojoFailureException("Bad dependency '" + s + "': expected groupId:artifactId");
            }
            out.add(p[0].trim() + ":" + p[1].trim());
        }
        return out;
    }

    /** Plans, logs and (unless {@code dryRun}) writes. {@code result} may be null when no upgrades are requested. */
    void change(ReportExporter.Result result, Map<String, String> requested, boolean bulk,
                Set<String> drops, Set<String> unpins) throws MojoFailureException {
        Path root = project.getBasedir().toPath();
        PomUpgrader.Plan plan;
        try {
            plan = PomUpgrader.plan(root, pomFiles(), result, requested, bulk, drops, unpins);
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
        for (String coord : plan.unpinned()) {
            getLog().info((dryRun ? "Would unpin " : "Unpinning ") + coord + " (the version stays)");
        }
        if (plan.patchedPoms().isEmpty()) {
            if (plan.problems().isEmpty()) {
                getLog().info("RedKite: nothing to change.");
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

    /** The root POM plus every module POM in the build, so pin counts and removals cover the whole project. */
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

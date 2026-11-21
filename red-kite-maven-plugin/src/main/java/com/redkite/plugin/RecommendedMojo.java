package com.redkite.plugin;

import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;

/**
 * Upgrades every direct dependency to RedKite's recommended version, in one go. A SNAPSHOT dependency, one with no
 * declaration in a POM and a transitive one are left alone; pin a transitive dependency with
 * {@code redkite:apply -Dredkite.upgrades=groupId:artifactId}. {@code -Dredkite.drop} keeps the named dependencies out,
 * and {@code -Dredkite.dryRun=true} shows the change without writing anything.
 */
@Mojo(name = "recommended", aggregator = true, requiresProject = true, requiresDependencyResolution = ResolutionScope.NONE, threadSafe = false)
public class RecommendedMojo extends ApplyMojo {
    public RecommendedMojo() {
        recommended = true;
    }
}

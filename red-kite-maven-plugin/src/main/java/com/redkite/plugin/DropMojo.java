package com.redkite.plugin;

import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;

/**
 * Drops RedKite's pin for the dependencies named by {@code -Dredkite.pins=groupId:artifactId,...}: the marked
 * {@code <dependencyManagement>} entry is removed (and the block around it if that leaves it empty), so the
 * dependency is no longer forced to a version. Use {@code redkite:unpin} to keep the version but release the protection.
 */
@Mojo(name = "drop", aggregator = true, requiresProject = true, requiresDependencyResolution = ResolutionScope.NONE, threadSafe = false)
public class DropMojo extends PinGoalMojo {
    @Override
    void remove(Set<String> coordinates) throws MojoFailureException {
        change(null, Map.of(), false, coordinates, Set.of());
    }
}

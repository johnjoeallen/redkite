package com.redkite.plugin;

import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;

/**
 * Releases the user pin on the dependencies named by {@code -Dredkite.pins=groupId:artifactId,...}: the version
 * stays exactly as it is, but it is no longer protected, so {@code redkite:upgrade-all} and
 * {@code redkite:upgrade-cve} may move it again. Use {@code redkite:drop} to remove a pin's entry altogether.
 */
@Mojo(name = "unpin", aggregator = true, requiresProject = true, requiresDependencyResolution = ResolutionScope.NONE, threadSafe = false)
public class UnpinMojo extends PinGoalMojo {
    @Override
    void remove(Set<String> coordinates) throws MojoFailureException {
        change(null, Map.of(), false, Set.of(), coordinates);
    }
}

package com.redkite.plugin;

import com.redkite.server.ReportExporter;
import java.util.Set;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Parameter;

/** Shared by the goals that remove pins. They only read and edit POMs, so they run no analysis and are quick. */
abstract class PinGoalMojo extends PomChangeMojo {
    /** Dependencies to release: comma-separated {@code groupId:artifactId}. Required. */
    @Parameter(property = "redkite.pins")
    String pins;

    /** What to do with the named dependencies. */
    abstract void remove(Set<String> coordinates) throws MojoFailureException;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            super.execute();
            return;
        }
        Set<String> coordinates = parseCoordinates(pins);
        if (coordinates.isEmpty()) {
            throw new MojoFailureException("Say which pins: -Dredkite.pins=groupId:artifactId,...");
        }
        remove(coordinates);
    }

    @Override
    void execute(ReportExporter.Result result) {
        // never called: these goals do not analyse
    }
}

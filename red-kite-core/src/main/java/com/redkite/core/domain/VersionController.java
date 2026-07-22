package com.redkite.core.domain;

/**
 * What selected a dependency's resolved version — distinct from {@link DependencyOrigin} (how the
 * dependency entered the graph) and from the editable declaration a fix would change.
 *
 * <p>Every variant in this sealed interface is part of the target model described for RedKite's
 * update analysis. {@link com.redkite.core.service.VersionControllerResolver} — the only producer
 * today — can only populate a subset from what the scanner currently observes: it never reads a
 * parent POM's or an imported BOM's own {@code dependencyManagement}, so {@link ImportedBom},
 * {@link ParentDependencyManagement}, and {@link ParentProperty} are not yet resolvable and are
 * reserved for the provenance stage described in the design notes. Until then, a dependency
 * actually controlled by one of those falls back to {@link DependencyMediation} or
 * {@link Unmanaged} — an honest "we don't yet know", not a guess dressed up as a real answer.
 */
public sealed interface VersionController {

    /** A literal {@code <version>} on the dependency's own declaration. */
    record DirectLiteral() implements VersionController {}

    /** A Maven property this project declares and the dependency's {@code <version>} references. */
    record LocalProperty(String propertyName, String declaringFile) implements VersionController {}

    /** An entry in this project's own (non-imported) {@code <dependencyManagement>}. */
    record LocalDependencyManagement(String declaringFile) implements VersionController {}

    /** A {@code <dependencyManagement>} entry imported via {@code <type>pom</type><scope>import</scope>}. */
    record ImportedBom(String bomCoordinate) implements VersionController {}

    /** A parent POM's own {@code <dependencyManagement>} entry. */
    record ParentDependencyManagement(String parentCoordinate) implements VersionController {}

    /** A property declared by a parent POM (rather than the project itself). */
    record ParentProperty(String propertyName, String parentCoordinate) implements VersionController {}

    /** A {@code <pluginManagement>} entry controlling a build plugin's version. */
    record PluginManagement(String declaringFile) implements VersionController {}

    /** No explicit management found anywhere inspected so far — Maven's nearest-wins dependency
     *  mediation picked the resolved version. Always a transitive dependency. */
    record DependencyMediation() implements VersionController {}

    /** Nothing controls this version — RedKite has no explicit declaration to point to. Distinct
     *  from {@link DependencyMediation}: this is direct or otherwise not a mediation outcome. */
    record Unmanaged() implements VersionController {}
}

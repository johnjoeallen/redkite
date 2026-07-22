package com.redkite.core.domain;

/**
 * What selected a dependency's resolved version — distinct from {@link DependencyOrigin} (how the
 * dependency entered the graph) and from the editable declaration a fix would change.
 *
 * <p>Every variant in this sealed interface is part of the target model described for RedKite's
 * update analysis. {@link com.redkite.core.service.VersionControllerResolver} populates
 * {@link ImportedBom} and {@link ParentDependencyManagement} using red-kite-maven's provenance
 * resolver (fetching and recursively walking the parent chain and imported BOMs); a dependency
 * that resolver couldn't reach (fetch failure, or genuinely nothing manages it) falls back to
 * {@link DependencyMediation} or {@link Unmanaged} — an honest "we don't know", not a guess.
 * {@link ParentProperty} remains reserved: distinguishing "a property defined by a parent" from
 * "a property defined by the project" needs tracking where each property is textually declared,
 * which the current resolver doesn't do (see its class-level javadoc's noted simplification).
 */
public sealed interface VersionController {

    /** A literal {@code <version>} on the dependency's own declaration. */
    record DirectLiteral() implements VersionController {}

    /** A Maven property this project declares and the dependency's {@code <version>} references. */
    record LocalProperty(String propertyName, String declaringFile) implements VersionController {}

    /** An entry in this project's own (non-imported) {@code <dependencyManagement>}. */
    record LocalDependencyManagement(String declaringFile) implements VersionController {}

    /** A {@code <dependencyManagement>} entry imported via {@code <type>pom</type><scope>import</scope>}.
     *  {@code propertyName} is non-null when the BOM's own managed entry is itself a property
     *  reference — e.g. Spring Boot's BOM managing {@code logback-classic} via its own
     *  {@code ${logback.version}} — since that same property name is exactly what a project-level
     *  override (a {@link LocalProperty} elsewhere) also controls; null for a literal entry. */
    record ImportedBom(String bomCoordinate, String propertyName) implements VersionController {
        public ImportedBom(String bomCoordinate) {
            this(bomCoordinate, null);
        }
    }

    /** A parent POM's own {@code <dependencyManagement>} entry. {@code propertyName} follows the
     *  same rule as {@link ImportedBom#propertyName()}. */
    record ParentDependencyManagement(String parentCoordinate, String propertyName) implements VersionController {
        public ParentDependencyManagement(String parentCoordinate) {
            this(parentCoordinate, null);
        }
    }

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

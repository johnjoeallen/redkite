package com.redkite.core.domain;

public enum VersionSource {
    LITERAL,
    PROPERTY,
    /** Resolved via the parent POM chain's own {@code dependencyManagement} — populated by
     *  provenance resolution (fetching/parsing the parent chain), not by reading the project's
     *  own POM alone. */
    PARENT_MANAGED,
    /** The project's own (non-imported) {@code dependencyManagement} entry. Despite the name,
     *  this is never evidence of an imported BOM — see {@code VersionController.ImportedBom}'s
     *  javadoc in red-kite-core. */
    BOM_MANAGED,
    /** Resolved via a BOM imported (directly or transitively) by the project's or an ancestor
     *  POM's {@code dependencyManagement} — populated by provenance resolution, distinct from
     *  {@link #BOM_MANAGED}'s project-local, non-imported entries. */
    PLATFORM_MANAGED,
    UNKNOWN
}

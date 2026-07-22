package com.redkite.core.service;

import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.VersionController;
import com.redkite.core.domain.VersionSource;

/**
 * Derives a {@link VersionController} from a {@link ScanComponent} — what selected the resolved
 * version, kept separate from how the dependency entered the graph
 * ({@link DependencyOriginClassifier}).
 *
 * <p>This only maps signals the scanner records on {@link ScanComponent}
 * ({@link ScanComponent#versionSource()}, {@link ScanComponent#owningVersionControlPoint()}), not
 * parent/BOM content itself — the actual fetching and recursive resolution happens in
 * red-kite-maven's provenance resolver, which encodes its result back onto the component using
 * {@link VersionSource#PARENT_MANAGED}/{@link VersionSource#PLATFORM_MANAGED} plus an
 * {@code owningVersionControlPoint} of the form {@code "<coordinate>#<propertyName-or-literal>"}
 * — the same {@code "<declaringFile>#<name>"} shape already used for local properties, just with
 * a parent/BOM coordinate standing in for a local file. A dependency provenance resolution
 * couldn't reach (fetch failed, or truly unmanaged anywhere) still resolves honestly to
 * {@link VersionController.DependencyMediation} (transitive) or {@link VersionController.Unmanaged}
 * (direct) rather than a guess.
 */
public final class VersionControllerResolver {
    private VersionControllerResolver() {
    }

    public static VersionController resolve(ScanComponent component) {
        VersionSource source = component.versionSource();
        String owning = component.owningVersionControlPoint();

        if (source == VersionSource.LITERAL) {
            return new VersionController.DirectLiteral();
        }
        if (source == VersionSource.PROPERTY) {
            return new VersionController.LocalProperty(propertyName(owning), declaringFile(owning));
        }
        if (source == VersionSource.BOM_MANAGED) {
            // Despite the enum's name, this is a project-owned dependencyManagement entry read
            // straight out of the module's own POM — not evidence of an imported BOM. See
            // VersionController.ImportedBom's javadoc for why the two must stay distinct.
            return new VersionController.LocalDependencyManagement(declaringFile(owning));
        }
        if (source == VersionSource.PARENT_MANAGED) {
            return new VersionController.ParentDependencyManagement(declaringFile(owning), provenancePropertyName(owning));
        }
        if (source == VersionSource.PLATFORM_MANAGED) {
            return new VersionController.ImportedBom(declaringFile(owning), provenancePropertyName(owning));
        }
        return component.direct() ? new VersionController.Unmanaged() : new VersionController.DependencyMediation();
    }

    private static String propertyName(String owningVersionControlPoint) {
        if (owningVersionControlPoint == null) return null;
        int hash = owningVersionControlPoint.indexOf('#');
        return hash >= 0 ? owningVersionControlPoint.substring(hash + 1) : null;
    }

    /** Same "part after #" extraction as {@link #propertyName}, but for
     *  PARENT_MANAGED/PLATFORM_MANAGED components — where red-kite-maven's provenance resolver
     *  writes the literal sentinel {@code "literal"} (not a real property name) when the managed
     *  entry it found wasn't a property reference. */
    private static String provenancePropertyName(String owningVersionControlPoint) {
        String name = propertyName(owningVersionControlPoint);
        return "literal".equals(name) ? null : name;
    }

    private static String declaringFile(String owningVersionControlPoint) {
        if (owningVersionControlPoint == null) return null;
        int hash = owningVersionControlPoint.indexOf('#');
        return hash >= 0 ? owningVersionControlPoint.substring(0, hash) : owningVersionControlPoint;
    }
}

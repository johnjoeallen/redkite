package com.redkite.core.service;

import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.VersionController;
import com.redkite.core.domain.VersionSource;

/**
 * Derives a {@link VersionController} from a {@link ScanComponent} — what selected the resolved
 * version, kept separate from how the dependency entered the graph
 * ({@link DependencyOriginClassifier}).
 *
 * <p>This only maps signals the scanner already records today
 * ({@link ScanComponent#versionSource()}, {@link ScanComponent#owningVersionControlPoint()}); it
 * does not itself inspect parent POMs or imported BOMs. Until a later stage adds that, a
 * dependency truly controlled by a parent's or an imported BOM's {@code dependencyManagement}
 * resolves here to {@link VersionController.DependencyMediation} (transitive) or
 * {@link VersionController.Unmanaged} (direct) — an honest "not yet known", not a guess.
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
            // Reserved: the scanner never assigns this today (no parent-POM provenance yet).
            // Handled defensively so this resolver keeps working the day it does.
            return new VersionController.ParentDependencyManagement(declaringFile(owning));
        }
        return component.direct() ? new VersionController.Unmanaged() : new VersionController.DependencyMediation();
    }

    private static String propertyName(String owningVersionControlPoint) {
        if (owningVersionControlPoint == null) return null;
        int hash = owningVersionControlPoint.indexOf('#');
        return hash >= 0 ? owningVersionControlPoint.substring(hash + 1) : null;
    }

    private static String declaringFile(String owningVersionControlPoint) {
        if (owningVersionControlPoint == null) return null;
        int hash = owningVersionControlPoint.indexOf('#');
        return hash >= 0 ? owningVersionControlPoint.substring(0, hash) : owningVersionControlPoint;
    }
}

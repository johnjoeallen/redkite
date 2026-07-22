package com.redkite.core.service;

import com.redkite.core.domain.DependencyOrigin;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.ScanComponent;

/**
 * Derives {@link DependencyOrigin} from a {@link ScanComponent} — how the dependency entered the
 * graph, kept separate from what controls its version ({@link VersionControllerResolver}).
 *
 * <p>{@link DependencyOrigin#IMPORTED_BOM}, {@link DependencyOrigin#PLATFORM}, and
 * {@link DependencyOrigin#PROFILE_DERIVED} are never produced here: the red-kite-maven scanner
 * doesn't parse BOM imports or track profile activation yet, so there's nothing in
 * {@link ScanComponent} today those three could be derived from.
 */
public final class DependencyOriginClassifier {
    private DependencyOriginClassifier() {
    }

    /** Matches the declarationPath the red-kite-maven scanner writes for the synthetic component
     *  it creates to represent an external parent POM. Duplicated as a literal here rather than a
     *  cross-module dependency, since red-kite-core doesn't depend on red-kite-maven. */
    private static final String PARENT_DECLARATION_PATH = "/project/parent";

    public static DependencyOrigin classify(ScanComponent component) {
        if (component.scope() == DependencyScope.PLUGIN_BUILD) {
            return DependencyOrigin.PLUGIN;
        }
        if (PARENT_DECLARATION_PATH.equals(component.declarationPath())) {
            return DependencyOrigin.PARENT;
        }
        return component.direct() ? DependencyOrigin.DIRECT : DependencyOrigin.TRANSITIVE;
    }
}

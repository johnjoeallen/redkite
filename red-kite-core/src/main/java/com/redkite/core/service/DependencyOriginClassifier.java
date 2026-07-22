package com.redkite.core.service;

import com.redkite.core.domain.DependencyOrigin;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.ScanComponent;

/**
 * Derives {@link DependencyOrigin} from a {@link ScanComponent} — how the dependency entered the
 * graph, kept separate from what controls its version ({@link VersionControllerResolver}).
 *
 * <p>{@link DependencyOrigin#PLATFORM} and {@link DependencyOrigin#PROFILE_DERIVED} are never
 * produced here: the red-kite-maven scanner doesn't track platform membership or profile
 * activation yet, so there's nothing in {@link ScanComponent} today either could be derived from.
 */
public final class DependencyOriginClassifier {
    private DependencyOriginClassifier() {
    }

    /** Matches the declarationPath the red-kite-maven scanner writes for the synthetic component
     *  it creates to represent an external parent POM. Duplicated as a literal here rather than a
     *  cross-module dependency, since red-kite-core doesn't depend on red-kite-maven. */
    private static final String PARENT_DECLARATION_PATH = "/project/parent";

    /** Matches the declarationPath prefix the scanner gives a {@code <dependencyManagement>}
     *  entry that's a BOM import ({@code <type>pom</type><scope>import</scope>}), as opposed to a
     *  plain managed-version entry. Same cross-module-literal reasoning as
     *  {@link #PARENT_DECLARATION_PATH}. */
    private static final String BOM_IMPORT_DECLARATION_MARKER = "dependency[import:";

    public static DependencyOrigin classify(ScanComponent component) {
        if (component.scope() == DependencyScope.PLUGIN_BUILD) {
            return DependencyOrigin.PLUGIN;
        }
        if (PARENT_DECLARATION_PATH.equals(component.declarationPath())) {
            return DependencyOrigin.PARENT;
        }
        if (component.declarationPath() != null && component.declarationPath().contains(BOM_IMPORT_DECLARATION_MARKER)) {
            return DependencyOrigin.IMPORTED_BOM;
        }
        return component.direct() ? DependencyOrigin.DIRECT : DependencyOrigin.TRANSITIVE;
    }
}

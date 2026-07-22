package com.redkite.core.service;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.DependencyOrigin;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.VersionSource;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DependencyOriginClassifierTest {

    private static final ComponentCoordinate COORD = new ComponentCoordinate("example", "library");

    private static ScanComponent component(boolean direct, DependencyScope scope, String declarationPath) {
        return new ScanComponent(1L, COORD, "1.0.0", scope, direct, VersionSource.LITERAL,
                "pom.xml", declarationPath, Map.of(), false, "pom.xml#dependency", "pom.xml");
    }

    @Test
    void directDependencyIsOriginDirect() {
        ScanComponent c = component(true, DependencyScope.COMPILE, "/project/dependencies/dependency[example:library]");
        assertEquals(DependencyOrigin.DIRECT, DependencyOriginClassifier.classify(c));
    }

    @Test
    void treeDiscoveredNonDirectDependencyIsOriginTransitive() {
        ScanComponent c = component(false, DependencyScope.COMPILE, "/project/dependency-tree/dependency[example:library]");
        assertEquals(DependencyOrigin.TRANSITIVE, DependencyOriginClassifier.classify(c));
    }

    @Test
    void buildPluginIsOriginPlugin() {
        ScanComponent c = component(true, DependencyScope.PLUGIN_BUILD, "/project/build/plugins/plugin[example:library]");
        assertEquals(DependencyOrigin.PLUGIN, DependencyOriginClassifier.classify(c));
    }

    @Test
    void externalParentComponentIsOriginParent() {
        ScanComponent c = component(true, DependencyScope.COMPILE, "/project/parent");
        assertEquals(DependencyOrigin.PARENT, DependencyOriginClassifier.classify(c));
    }

    @Test
    void bomImportDependencyManagementEntryIsOriginImportedBom() {
        ScanComponent c = component(true, DependencyScope.COMPILE,
                "/project/dependencyManagement/dependencies/dependency[import:example:library]");
        assertEquals(DependencyOrigin.IMPORTED_BOM, DependencyOriginClassifier.classify(c));
    }

    @Test
    void plainDependencyManagementEntryIsNotOriginImportedBom() {
        ScanComponent c = component(true, DependencyScope.COMPILE,
                "/project/dependencyManagement/dependencies/dependency[example:library]");
        assertEquals(DependencyOrigin.DIRECT, DependencyOriginClassifier.classify(c));
    }
}

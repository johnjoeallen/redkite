package com.redkite.core.service;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.core.domain.DependencyScope;
import com.redkite.core.domain.ScanComponent;
import com.redkite.core.domain.VersionController;
import com.redkite.core.domain.VersionSource;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class VersionControllerResolverTest {

    private static final ComponentCoordinate COORD = new ComponentCoordinate("example", "library");

    private static ScanComponent component(boolean direct, VersionSource source, String owningVersionControlPoint) {
        return new ScanComponent(1L, COORD, "1.2.0", DependencyScope.COMPILE, direct, source,
                "pom.xml", "/project/dependencies/dependency[example:library]", Map.of(),
                false, owningVersionControlPoint, "pom.xml");
    }

    @Test
    void directDependencyWithLiteralVersionIsDirectLiteral() {
        ScanComponent c = component(true, VersionSource.LITERAL, "pom.xml#dependency");
        assertEquals(new VersionController.DirectLiteral(), VersionControllerResolver.resolve(c));
    }

    @Test
    void propertyBackedVersionIsLocalPropertyWithNameAndFile() {
        ScanComponent c = component(true, VersionSource.PROPERTY, "pom.xml#library.version");
        VersionController controller = VersionControllerResolver.resolve(c);
        assertEquals(new VersionController.LocalProperty("library.version", "pom.xml"), controller);
    }

    @Test
    void localDependencyManagementEntryIsLocalDependencyManagementNotBom() {
        // The scanner's VersionSource.BOM_MANAGED name is historical — it really means "this
        // project's own dependencyManagement", never an imported BOM. The resolved
        // VersionController must say so explicitly rather than repeat the misleading name.
        ScanComponent c = component(true, VersionSource.BOM_MANAGED, "pom.xml#dependencyManagement");
        VersionController controller = VersionControllerResolver.resolve(c);
        assertEquals(new VersionController.LocalDependencyManagement("pom.xml"), controller);
        assertFalse(controller instanceof VersionController.ImportedBom);
    }

    @Test
    void transitiveWithUnknownSourceIsDependencyMediation() {
        ScanComponent c = component(false, VersionSource.UNKNOWN, "pom.xml#dependencyTree");
        assertEquals(new VersionController.DependencyMediation(), VersionControllerResolver.resolve(c));
    }

    @Test
    void directWithUnknownSourceIsUnmanagedNotMediation() {
        ScanComponent c = component(true, VersionSource.UNKNOWN, null);
        assertEquals(new VersionController.Unmanaged(), VersionControllerResolver.resolve(c));
    }
}

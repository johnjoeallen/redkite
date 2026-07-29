package com.redkite.maven;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LicenseResolverTest {

    private static String pomWithLicense(String licenseName) {
        return "<project><licenses><license><name>" + licenseName + "</name></license></licenses></project>";
    }

    private static String pomWithParent(String parentGroupId, String parentArtifactId, String parentVersion) {
        return "<project><parent><groupId>" + parentGroupId + "</groupId><artifactId>" + parentArtifactId
                + "</artifactId><version>" + parentVersion + "</version></parent></project>";
    }

    @Test
    void licenseDeclaredOnTheArtifactsOwnPomIsUsed() {
        FakePomSource source = new FakePomSource()
                .with("org.example", "lib", "1.0.0", pomWithLicense("Apache-2.0"));
        LicenseResolver resolver = new LicenseResolver(source);

        assertEquals(List.of("Apache-2.0"), resolver.resolve("org.example", "lib", "1.0.0"));
    }

    @Test
    void multipleLicensesOnTheSameArtifactAreAllReturned() {
        String xml = "<project><licenses>"
                + "<license><name>EPL-2.0</name></license>"
                + "<license><name>GPL-2.0-with-classpath-exception</name></license>"
                + "</licenses></project>";
        FakePomSource source = new FakePomSource().with("org.example", "dual-licensed", "1.0.0", xml);
        LicenseResolver resolver = new LicenseResolver(source);

        assertEquals(List.of("EPL-2.0", "GPL-2.0-with-classpath-exception"),
                resolver.resolve("org.example", "dual-licensed", "1.0.0"));
    }

    @Test
    void licenseIsInheritedFromParentWhenArtifactPomDeclaresNone() {
        FakePomSource source = new FakePomSource()
                .with("org.example", "lib", "1.0.0", pomWithParent("org.example", "parent-pom", "1.0.0"))
                .with("org.example", "parent-pom", "1.0.0", pomWithLicense("MIT"));
        LicenseResolver resolver = new LicenseResolver(source);

        assertEquals(List.of("MIT"), resolver.resolve("org.example", "lib", "1.0.0"));
    }

    @Test
    void licenseIsInheritedThroughMultipleParentLevels() {
        FakePomSource source = new FakePomSource()
                .with("org.example", "lib", "1.0.0", pomWithParent("org.example", "mid-parent", "1.0.0"))
                .with("org.example", "mid-parent", "1.0.0", pomWithParent("org.example", "root-parent", "1.0.0"))
                .with("org.example", "root-parent", "1.0.0", pomWithLicense("BSD-3-Clause"));
        LicenseResolver resolver = new LicenseResolver(source);

        assertEquals(List.of("BSD-3-Clause"), resolver.resolve("org.example", "lib", "1.0.0"));
    }

    @Test
    void ownLicenseWinsOverParentsEvenWhenParentDeclaresOne() {
        FakePomSource source = new FakePomSource()
                .with("org.example", "lib", "1.0.0",
                        "<project><licenses><license><name>Apache-2.0</name></license></licenses>"
                                + "<parent><groupId>org.example</groupId><artifactId>parent-pom</artifactId>"
                                + "<version>1.0.0</version></parent></project>")
                .with("org.example", "parent-pom", "1.0.0", pomWithLicense("MIT"));
        LicenseResolver resolver = new LicenseResolver(source);

        assertEquals(List.of("Apache-2.0"), resolver.resolve("org.example", "lib", "1.0.0"));
    }

    @Test
    void noLicenseAnywhereInTheChainReturnsEmpty() {
        FakePomSource source = new FakePomSource()
                .with("org.example", "lib", "1.0.0", "<project></project>");
        LicenseResolver resolver = new LicenseResolver(source);

        assertEquals(List.of(), resolver.resolve("org.example", "lib", "1.0.0"));
    }

    @Test
    void unreachableArtifactReturnsEmptyWithoutThrowing() {
        FakePomSource source = new FakePomSource(); // nothing registered — every fetch misses
        LicenseResolver resolver = new LicenseResolver(source);

        assertEquals(List.of(), resolver.resolve("org.example", "unreachable", "1.0.0"));
    }

    @Test
    void unreachableParentStopsTheWalkWithoutThrowing() {
        FakePomSource source = new FakePomSource()
                .with("org.example", "lib", "1.0.0", pomWithParent("org.example", "unreachable-parent", "1.0.0"));
        LicenseResolver resolver = new LicenseResolver(source);

        assertEquals(List.of(), resolver.resolve("org.example", "lib", "1.0.0"));
    }

    @Test
    void parentCycleDoesNotInfiniteLoop() {
        FakePomSource source = new FakePomSource()
                .with("org.example", "a", "1.0.0", pomWithParent("org.example", "b", "1.0.0"))
                .with("org.example", "b", "1.0.0", pomWithParent("org.example", "a", "1.0.0"));
        LicenseResolver resolver = new LicenseResolver(source);

        assertEquals(List.of(), resolver.resolve("org.example", "a", "1.0.0"));
    }
}

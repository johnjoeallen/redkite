package com.redkite.maven;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end (still in-memory, no filesystem/network) proof that {@link FamilyVersionAligner}'s
 * output, once handed to {@link RemediationApplier}, produces a correct, buildable-shape POM —
 * asserting against the generated XML itself rather than either component's internals.
 */
class FamilyPinApplicationTest {

    private static final String JACKSON_GROUP_ID = "com.fasterxml.jackson";
    private static final String JACKSON_BOM_ARTIFACT = "jackson-bom";
    private static final String REASON = "Enforcer dependency convergence fix by RedKite";

    private static ManagedVersionResolver.ManagedVersion bomManaged(String version, String controller) {
        return new ManagedVersionResolver.ManagedVersion(version, controller, "jackson.version", true);
    }

    private static FamilyVersionAligner.BomMemberProbe realJackson2_22_1Probe() {
        return (bomGroupId, bomArtifactId, version) -> Map.of(
                "com.fasterxml.jackson.core:jackson-core", bomManaged("2.22.1", null),
                "com.fasterxml.jackson.core:jackson-databind", bomManaged("2.22.1", null),
                "com.fasterxml.jackson.core:jackson-annotations", bomManaged("2.22", null));
    }

    private static void applyEach(RemediationApplier applier, String[] pom, Map<String, String> pins) {
        for (Map.Entry<String, String> pin : pins.entrySet()) {
            String[] ga = pin.getKey().split(":", 2);
            pom[0] = applier.applyDependencyManagementPin(pom[0], ga[0], ga[1], pin.getValue(), REASON);
        }
    }

    @Test
    void projectManagingJacksonIndividually_producesThreeCorrectLiteralPinsNeverAJackson2_22_1Annotations() {
        // Mirrors the updated convergence-fixture exactly: no BOM import anywhere, nothing declared
        // for Jackson at all — the family's well-known BOM is probed as a fallback.
        Map<String, String> pins = new java.util.LinkedHashMap<>(Map.of(
                "com.fasterxml.jackson.core:jackson-core", "2.22.1",
                "com.fasterxml.jackson.core:jackson-databind", "2.22.1",
                "com.fasterxml.jackson.core:jackson-annotations", "2.22"));

        Map<String, String> aligned = new FamilyVersionAligner(realJackson2_22_1Probe())
                .align(pins, List.of(), Map.of());

        RemediationApplier applier = new RemediationApplier();
        String[] pom = {"<project><dependencies/></project>"};
        applyEach(applier, pom, aligned);

        assertEquals(1, countOccurrences(pom[0], "<artifactId>jackson-core</artifactId>"));
        assertEquals(1, countOccurrences(pom[0], "<artifactId>jackson-databind</artifactId>"));
        assertEquals(1, countOccurrences(pom[0], "<artifactId>jackson-annotations</artifactId>"));
        assertTrue(containsCoordinate(pom[0], "jackson-core", "2.22.1"), "jackson-core must be pinned to 2.22.1");
        assertTrue(containsCoordinate(pom[0], "jackson-databind", "2.22.1"), "jackson-databind must be pinned to 2.22.1");
        assertFalse(containsCoordinate(pom[0], "jackson-annotations", "2.22.1"),
                "jackson-annotations:2.22.1 must never appear anywhere in the generated POM — that artifact does not exist");
        assertTrue(containsCoordinate(pom[0], "jackson-annotations", "2.22"),
                "jackson-annotations must be pinned to its own real version, 2.22");
    }

    @Test
    void projectImportingJacksonBom_bumpsOnlyThePropertyNeverAddsPerMemberEntries() {
        String pom = """
                <project>
                  <properties>
                    <jackson.version>2.21.4</jackson.version>
                  </properties>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>com.fasterxml.jackson</groupId>
                        <artifactId>jackson-bom</artifactId>
                        <version>${jackson.version}</version>
                        <type>pom</type>
                        <scope>import</scope>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """;

        String controller = JACKSON_GROUP_ID + ":" + JACKSON_BOM_ARTIFACT + ":2.21.4";
        Map<String, String> pins = new java.util.LinkedHashMap<>(Map.of(
                "com.fasterxml.jackson.core:jackson-core", "2.22.1",
                "com.fasterxml.jackson.core:jackson-databind", "2.22.1",
                "com.fasterxml.jackson.core:jackson-annotations", "2.22"));
        Map<String, ManagedVersionResolver.ManagedVersion> projectManaged = Map.of(
                "com.fasterxml.jackson.core:jackson-core", bomManaged("2.21.5", controller),
                "com.fasterxml.jackson.core:jackson-databind", bomManaged("2.21.5", controller),
                "com.fasterxml.jackson.core:jackson-annotations", bomManaged("2.21", controller));

        Map<String, String> aligned = new FamilyVersionAligner(realJackson2_22_1Probe())
                .align(pins, List.of(), projectManaged);

        // core+databind land on the BOM's own target version (2.22.1) — collapse to one pin.
        // annotations lands on a DIFFERENT version (2.22) — stays its own pin, on purpose.
        assertEquals(Map.of(
                        JACKSON_GROUP_ID + ":" + JACKSON_BOM_ARTIFACT, "2.22.1",
                        "com.fasterxml.jackson.core:jackson-annotations", "2.22"),
                aligned);

        RemediationApplier applier = new RemediationApplier();
        String[] pomBox = {pom};
        applyEach(applier, pomBox, aligned);
        String updated = pomBox[0];

        assertTrue(updated.contains("<jackson.version>2.22.1</jackson.version>"), "The BOM-driving property must be bumped");
        assertEquals(1, countOccurrences(updated, "<artifactId>jackson-bom</artifactId>"), "Must not duplicate the BOM import entry");
        assertFalse(updated.contains("<artifactId>jackson-core</artifactId>"), "Must not add a per-member entry when the BOM already manages it correctly");
        assertFalse(updated.contains("<artifactId>jackson-databind</artifactId>"));
        // annotations DOES get its own literal entry, since the BOM manages it at a version
        // (2.22) different from what core/databind need — the property alone can't express that.
        assertEquals(1, countOccurrences(updated, "<artifactId>jackson-annotations</artifactId>"));
        assertTrue(containsCoordinate(updated, "jackson-annotations", "2.22"));
        assertFalse(containsCoordinate(updated, "jackson-annotations", "2.22.1"),
                "jackson-annotations:2.22.1 must never appear — that artifact does not exist");
    }

    private static boolean containsCoordinate(String pomXml, String artifactId, String version) {
        String normalized = pomXml.replaceAll("\\s+", " ");
        return normalized.contains("<artifactId>" + artifactId + "</artifactId> <version>" + version + "</version>");
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0, idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) != -1) {
            count++;
            idx += needle.length();
        }
        return count;
    }
}

package com.redkite.server;

import com.redkite.core.domain.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/** Text-level lookups over stored POM XML: dependency-management versions, module names, the root POM. */
final class PomXml {
    private PomXml() {
    }

    static String readFileQuietly(Path path) {
        try {
            return Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }

    /** The root POM's XML from a stored source-POM map (keyed by relative file path). */
    static String rootPomXml(Map<String, String> sourcePoms) {
        String content = sourcePoms.get("pom.xml");
        if (content != null) return content;
        // Fall back to the shallowest pom.xml path
        String bestKey = null;
        for (String key : sourcePoms.keySet()) {
            if (!key.endsWith("pom.xml")) continue;
            if (bestKey == null || key.length() < bestKey.length()) bestKey = key;
        }
        return bestKey != null ? sourcePoms.get(bestKey) : "";
    }

    /** Extracts the pinned version for g:a from an existing <dependencyManagement> block,
     *  resolving a ${...} property reference against this same POM's <properties> block. Returns
     *  null (rather than the raw "${propName}" text) when the entry is property-backed but the
     *  property can't be found here — callers treat this identically to "no pin exists", instead
     *  of mistaking the unresolved reference for a real version and later writing it back into
     *  the property itself, defining it as a reference to itself. */
    static String extractDepMgmtVersion(String pomXml, String groupId, String artifactId) {
        // Simple scan: look for <groupId>G</groupId> / <artifactId>A</artifactId> / <version>V</version>
        // within a <dependencyManagement> block.
        int dmStart = pomXml.indexOf("<dependencyManagement>");
        int dmEnd = pomXml.indexOf("</dependencyManagement>");
        if (dmStart < 0 || dmEnd <= dmStart) return null;
        String dm = pomXml.substring(dmStart, dmEnd);
        // Find each <dependency> block within dep management
        int pos = 0;
        while (true) {
            int depStart = dm.indexOf("<dependency>", pos);
            if (depStart < 0) break;
            int depEnd = dm.indexOf("</dependency>", depStart);
            if (depEnd < 0) break;
            String dep = dm.substring(depStart, depEnd);
            if (dep.contains("<groupId>" + groupId + "</groupId>")
                    && dep.contains("<artifactId>" + artifactId + "</artifactId>")) {
                int vs = dep.indexOf("<version>");
                int ve = dep.indexOf("</version>");
                if (vs >= 0 && ve > vs) return resolvePomPropertyRef(pomXml, dep.substring(vs + 9, ve).trim());
            }
            pos = depEnd + 1;
        }
        return null;
    }

    /** If {@code value} is a {@code ${propName}} reference, resolves it against {@code pomXml}'s
     *  own <properties> block (single level, no chained/inherited resolution); returns it
     *  unchanged if it isn't a reference, or null if the property can't be found here. */
    static String resolvePomPropertyRef(String pomXml, String value) {
        if (value == null || !value.startsWith("${") || !value.endsWith("}")) return value;
        String propName = value.substring(2, value.length() - 1);
        int psStart = pomXml.indexOf("<properties>");
        int psEnd = pomXml.indexOf("</properties>");
        if (psStart < 0 || psEnd <= psStart) return null;
        String props = pomXml.substring(psStart, psEnd);
        String openTag = "<" + propName + ">";
        String closeTag = "</" + propName + ">";
        int os = props.indexOf(openTag);
        if (os < 0) return null;
        int oe = props.indexOf(closeTag, os);
        if (oe < 0) return null;
        return props.substring(os + openTag.length(), oe).trim();
    }

    static String selectRootPomKey(Map<String, String> sourcePoms, String workingTreePath) {
        if (sourcePoms.containsKey("pom.xml")) {
            return "pom.xml";
        }
        String best = null;
        int bestDepth = Integer.MAX_VALUE;
        for (String key : sourcePoms.keySet()) {
            if (key == null || !key.endsWith("pom.xml")) {
                continue;
            }
            int depth = (int) key.chars().filter(ch -> ch == '/').count();
            if (best == null || depth < bestDepth || (depth == bestDepth && key.length() < best.length())) {
                best = key;
                bestDepth = depth;
            }
        }
        if (best != null) {
            return best;
        }
        return sourcePoms.isEmpty() ? null : sourcePoms.keySet().iterator().next();
    }

    static String readIfExists(Path path) {
        try {
            return Files.exists(path) ? Files.readString(path, StandardCharsets.UTF_8) : null;
        } catch (IOException e) {
            return null;
        }
    }

    static Map<String, String> buildModuleArtifactIds(Map<String, String> sourcePoms) {
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : sourcePoms.entrySet()) {
            String artifactId = extractArtifactId(e.getValue());
            result.put(e.getKey(), artifactId != null ? artifactId : modulePathLabel(e.getKey()));
        }
        return result;
    }

    static String modulePathLabel(String mod) {
        if ("pom.xml".equals(mod) || "(root)".equals(mod)) return "(root)";
        if (mod.endsWith("/pom.xml")) return mod.substring(0, mod.length() - 8);
        return mod;
    }

    static String extractArtifactId(String pomXml) {
        int searchFrom = 0;
        int parentEnd = pomXml.indexOf("</parent>");
        if (parentEnd >= 0) searchFrom = parentEnd + 9;
        int start = pomXml.indexOf("<artifactId>", searchFrom);
        if (start < 0) return null;
        int end = pomXml.indexOf("</artifactId>", start);
        if (end < 0) return null;
        return pomXml.substring(start + 12, end).trim();
    }
}

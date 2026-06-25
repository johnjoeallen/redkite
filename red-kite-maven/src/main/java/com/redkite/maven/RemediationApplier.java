package com.redkite.maven;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Applies enforcer-suggested remediations to POM files.
 *
 * <p>RedKite-managed insertions are marked with structured XML comments so they
 * can be identified and reversed:
 * <ul>
 *   <li>Exclusions: {@code <!-- redkite:exclusion groupId="..." artifactId="..." reason="..." -->}
 *   <li>Dependency management pins: {@code <!-- redkite:dependency-management groupId="..." artifactId="..." version="..." reason="..." -->}
 * </ul>
 */
public class RemediationApplier {

    private static final String RK_COMMENT_PREFIX = "<!-- redkite:";
    private static final String EXCLUSION_TAG = "redkite:exclusion";
    private static final String DEP_MGMT_TAG = "redkite:dependency-management";

    // ---- Public API ----

    /**
     * Reads {@code pomPath}, adds an exclusion of {@code excludeGroupId:excludeArtifactId}
     * to every dependency declaration matching {@code parentGroupId:parentArtifactId},
     * and returns the modified POM as a string (does NOT write to disk).
     */
    public String applyExclusion(Path pomPath,
                                 String parentGroupId, String parentArtifactId,
                                 String excludeGroupId, String excludeArtifactId,
                                 String reason) throws IOException {
        String content = Files.readString(pomPath, StandardCharsets.UTF_8);
        return applyExclusion(content, parentGroupId, parentArtifactId,
                excludeGroupId, excludeArtifactId, reason);
    }

    public String applyExclusion(String content,
                                 String parentGroupId, String parentArtifactId,
                                 String excludeGroupId, String excludeArtifactId,
                                 String reason) {
        List<String> lines = toLines(content);
        List<String> result = new ArrayList<>();
        int i = 0;
        while (i < lines.size()) {
            String line = lines.get(i);
            result.add(line);
            // Look for a <dependency> block that matches our parent
            if (isDependencyBlockStart(line)) {
                int blockEnd = findBlockEnd(lines, i, "</dependency>");
                if (blockEnd != -1) {
                    List<String> block = lines.subList(i + 1, blockEnd);
                    if (blockMatchesCoord(block, parentGroupId, parentArtifactId)) {
                        // Is an existing redkite exclusion already present for this artifact?
                        if (!hasRedkiteExclusion(block, excludeGroupId, excludeArtifactId)) {
                            String indent = detectIndent(line);
                            // Add block content through to end, inserting exclusion before </dependency>
                            for (int j = i + 1; j < blockEnd; j++) {
                                result.add(lines.get(j));
                            }
                            result.addAll(buildExclusionBlock(
                                    indent + "  ", excludeGroupId, excludeArtifactId, reason));
                            result.add(lines.get(blockEnd)); // closing </dependency>
                            i = blockEnd + 1;
                            continue;
                        }
                    }
                }
            }
            i++;
        }
        return String.join(System.lineSeparator(), result);
    }

    /**
     * Adds or updates a {@code <dependencyManagement>} entry to pin
     * {@code groupId:artifactId} to {@code version}, and returns the modified POM.
     * Does NOT write to disk.
     */
    public String applyDependencyManagementPin(Path pomPath,
                                               String groupId, String artifactId, String version,
                                               String reason) throws IOException {
        String content = Files.readString(pomPath, StandardCharsets.UTF_8);
        return applyDependencyManagementPin(content, groupId, artifactId, version, reason);
    }

    public String applyDependencyManagementPin(String content,
                                               String groupId, String artifactId, String version,
                                               String reason) {
        version = sanitizeVersion(version);
        List<String> lines = toLines(content);

        // Check if a redkite-managed entry already exists; update it in-place
        int existingComment = findRedkiteDepMgmtComment(lines, groupId, artifactId);
        if (existingComment != -1) {
            return updateDepMgmtVersion(lines, existingComment, version, reason);
        }

        // If <dependencyManagement><dependencies> exists, insert before </dependencies>
        int depMgmtDepsClose = findDepMgmtDepsClose(lines);
        if (depMgmtDepsClose != -1) {
            String indent = detectIndentForClose(lines, depMgmtDepsClose);
            List<String> insertion = buildDepMgmtEntry(indent, groupId, artifactId, version, reason);
            List<String> result = new ArrayList<>(lines.subList(0, depMgmtDepsClose));
            result.addAll(insertion);
            result.addAll(lines.subList(depMgmtDepsClose, lines.size()));
            return String.join(System.lineSeparator(), result);
        }

        // Otherwise insert a full <dependencyManagement> block before </project>
        int projectClose = findLastTag(lines, "</project>");
        if (projectClose == -1) {
            // Fallback: append
            List<String> result = new ArrayList<>(lines);
            result.addAll(buildFullDepMgmtBlock("  ", groupId, artifactId, version, reason));
            return String.join(System.lineSeparator(), result);
        }
        String indent = "  ";
        List<String> result = new ArrayList<>(lines.subList(0, projectClose));
        result.addAll(buildFullDepMgmtBlock(indent, groupId, artifactId, version, reason));
        result.addAll(lines.subList(projectClose, lines.size()));
        return String.join(System.lineSeparator(), result);
    }

    /**
     * Strips all redkite-managed exclusions and dependency-management entries from a POM.
     * Used to create a "clean" temp POM for re-analysis (Stage 4).
     */
    public String stripRedkiteRemediations(String content) {
        List<String> lines = toLines(content);
        List<String> result = new ArrayList<>();
        int i = 0;
        while (i < lines.size()) {
            String line = lines.get(i);
            String stripped = line.strip();

            // Skip redkite comment + following <exclusion> or <dependency> block
            if (stripped.startsWith(RK_COMMENT_PREFIX)) {
                String tag = extractRedkiteTag(stripped);
                if (EXCLUSION_TAG.equals(tag)) {
                    // Skip the comment; also skip the <exclusion>...</exclusion> block that follows
                    i++;
                    if (i < lines.size() && lines.get(i).strip().startsWith("<exclusion")) {
                        int blockEnd = findBlockEnd(lines, i, "</exclusion>");
                        i = blockEnd != -1 ? blockEnd + 1 : i + 1;
                    }
                    // If <exclusions> wrapper becomes empty, remove it too
                    continue;
                } else if (DEP_MGMT_TAG.equals(tag)) {
                    // Skip the comment + the <dependency>...</dependency> block that follows
                    i++;
                    if (i < lines.size() && lines.get(i).strip().startsWith("<dependency")) {
                        int blockEnd = findBlockEnd(lines, i, "</dependency>");
                        i = blockEnd != -1 ? blockEnd + 1 : i + 1;
                    }
                    continue;
                }
            }

            result.add(line);
            i++;
        }
        // Clean up empty <exclusions/> or <exclusions></exclusions> left behind
        return collapseEmptyExclusions(String.join(System.lineSeparator(), result));
    }

    // ---- Builders ----

    private List<String> buildExclusionBlock(String indent,
                                             String groupId, String artifactId, String reason) {
        List<String> out = new ArrayList<>();
        // Ensure <exclusions> wrapper exists — we look for it above; this just adds the entry
        String rkComment = indent + "<!-- " + EXCLUSION_TAG
                + " groupId=\"" + groupId + "\""
                + " artifactId=\"" + artifactId + "\""
                + " reason=\"" + escapeAttr(reason) + "\" -->";
        out.add(indent + "<exclusions>");
        out.add(rkComment);
        out.add(indent + "  <exclusion>");
        out.add(indent + "    <groupId>" + groupId + "</groupId>");
        out.add(indent + "    <artifactId>" + artifactId + "</artifactId>");
        out.add(indent + "  </exclusion>");
        out.add(indent + "</exclusions>");
        return out;
    }

    private List<String> buildDepMgmtEntry(String indent,
                                           String groupId, String artifactId, String version,
                                           String reason) {
        List<String> out = new ArrayList<>();
        String rkComment = indent + "  <!-- " + DEP_MGMT_TAG
                + " groupId=\"" + groupId + "\""
                + " artifactId=\"" + artifactId + "\""
                + " version=\"" + version + "\""
                + " reason=\"" + escapeAttr(reason) + "\" -->";
        out.add(rkComment);
        out.add(indent + "  <dependency>");
        out.add(indent + "    <groupId>" + groupId + "</groupId>");
        out.add(indent + "    <artifactId>" + artifactId + "</artifactId>");
        out.add(indent + "    <version>" + version + "</version>");
        out.add(indent + "  </dependency>");
        return out;
    }

    private List<String> buildFullDepMgmtBlock(String indent,
                                               String groupId, String artifactId, String version,
                                               String reason) {
        List<String> out = new ArrayList<>();
        out.add(indent + "<dependencyManagement>");
        out.add(indent + "  <dependencies>");
        out.addAll(buildDepMgmtEntry(indent + "  ", groupId, artifactId, version, reason));
        out.add(indent + "  </dependencies>");
        out.add(indent + "</dependencyManagement>");
        return out;
    }

    /**
     * Returns G:A:V strings for all entries declared in {@code <dependencyManagement>} sections.
     */
    public List<String> extractDepMgmtEntries(String content) {
        List<String> entries = new ArrayList<>();
        int pos = 0;
        while (true) {
            int s = content.indexOf("<dependencyManagement>", pos);
            if (s < 0) break;
            int e = content.indexOf("</dependencyManagement>", s);
            if (e < 0) break;
            String block = content.substring(s, e);
            int dpos = 0;
            while (true) {
                int ds = block.indexOf("<dependency>", dpos);
                if (ds < 0) break;
                int de = block.indexOf("</dependency>", ds);
                if (de < 0) break;
                String dep = block.substring(ds, de);
                String g = extractSimpleTag(dep, "groupId");
                String a = extractSimpleTag(dep, "artifactId");
                String v = extractSimpleTag(dep, "version");
                if (g != null && a != null && v != null) {
                    entries.add(g + ":" + a + ":" + v);
                }
                dpos = de + 1;
            }
            pos = e + 1;
        }
        return entries;
    }

    /** Returns the number of {@code <!-- redkite:exclusion} markers in content. */
    public int countRedkiteExclusions(String content) {
        int count = 0;
        String marker = "<!-- " + EXCLUSION_TAG;
        int idx = 0;
        while ((idx = content.indexOf(marker, idx)) != -1) {
            count++;
            idx += marker.length();
        }
        return count;
    }

    /** Removes all {@code <dependencyManagement>} blocks from content. */
    public String stripAllDepManagement(String content) {
        List<String> lines = toLines(content);
        List<String> result = new ArrayList<>();
        boolean inDepMgmt = false;
        for (String line : lines) {
            String s = line.strip();
            if (!inDepMgmt && s.equals("<dependencyManagement>")) {
                inDepMgmt = true;
                continue;
            }
            if (inDepMgmt) {
                if (s.equals("</dependencyManagement>")) inDepMgmt = false;
                continue;
            }
            result.add(line);
        }
        return String.join(System.lineSeparator(), result);
    }

    private static String extractSimpleTag(String content, String tag) {
        String open = "<" + tag + ">";
        String close = "</" + tag + ">";
        int s = content.indexOf(open);
        if (s < 0) return null;
        int e = content.indexOf(close, s);
        if (e < 0) return null;
        return content.substring(s + open.length(), e).trim();
    }

    /**
     * Returns "groupId:artifactId" for every redkite-managed exclusion comment in the POM.
     */
    public List<String> parseRedkiteExclusions(String content) {
        List<String> result = new ArrayList<>();
        for (String line : content.split("\n", -1)) {
            String s = line.strip();
            if (s.startsWith("<!-- " + EXCLUSION_TAG)) {
                String g = extractAttrValue(s, "groupId");
                String a = extractAttrValue(s, "artifactId");
                if (g != null && a != null) result.add(g + ":" + a);
            }
        }
        return result;
    }

    // ---- Scanning helpers ----

    private boolean isDependencyBlockStart(String line) {
        String s = line.strip();
        return s.equals("<dependency>") || s.startsWith("<dependency>");
    }

    private int findBlockEnd(List<String> lines, int start, String closeTag) {
        for (int i = start + 1; i < lines.size(); i++) {
            if (lines.get(i).strip().contains(closeTag)) return i;
        }
        return -1;
    }

    private boolean blockMatchesCoord(List<String> block, String groupId, String artifactId) {
        boolean gMatch = false, aMatch = false;
        for (String line : block) {
            String s = line.strip();
            if (s.equals("<groupId>" + groupId + "</groupId>")) gMatch = true;
            if (s.equals("<artifactId>" + artifactId + "</artifactId>")) aMatch = true;
        }
        return gMatch && aMatch;
    }

    private boolean hasRedkiteExclusion(List<String> block, String groupId, String artifactId) {
        for (String line : block) {
            String s = line.strip();
            if (s.startsWith("<!-- " + EXCLUSION_TAG)
                    && s.contains("groupId=\"" + groupId + "\"")
                    && s.contains("artifactId=\"" + artifactId + "\"")) {
                return true;
            }
        }
        return false;
    }

    private int findDepMgmtDepsClose(List<String> lines) {
        boolean inDepMgmt = false;
        for (int i = 0; i < lines.size(); i++) {
            String s = lines.get(i).strip();
            if (s.startsWith("<dependencyManagement")) inDepMgmt = true;
            if (inDepMgmt && s.equals("</dependencies>")) return i;
            if (s.equals("</dependencyManagement>")) inDepMgmt = false;
        }
        return -1;
    }

    private int findLastTag(List<String> lines, String tag) {
        for (int i = lines.size() - 1; i >= 0; i--) {
            if (lines.get(i).strip().equals(tag)) return i;
        }
        return -1;
    }

    private int findRedkiteDepMgmtComment(List<String> lines, String groupId, String artifactId) {
        for (int i = 0; i < lines.size(); i++) {
            String s = lines.get(i).strip();
            if (s.startsWith("<!-- " + DEP_MGMT_TAG)
                    && s.contains("groupId=\"" + groupId + "\"")
                    && s.contains("artifactId=\"" + artifactId + "\"")) {
                return i;
            }
        }
        return -1;
    }

    private String updateDepMgmtVersion(List<String> lines, int commentIdx, String version, String reason) {
        List<String> result = new ArrayList<>(lines);
        String old = result.get(commentIdx);
        // Replace version="..." in the comment
        String updated = old.replaceAll("version=\"[^\"]*\"", "version=\"" + version + "\"")
                            .replaceAll("reason=\"[^\"]*\"", "reason=\"" + escapeAttr(reason) + "\"");
        result.set(commentIdx, updated);
        // Also update the <version> tag in the following dependency block
        for (int i = commentIdx + 1; i < result.size() && i < commentIdx + 10; i++) {
            String s = result.get(i);
            if (s.strip().startsWith("<version>") && s.strip().endsWith("</version>")) {
                result.set(i, s.replaceAll("<version>[^<]*</version>", "<version>" + version + "</version>"));
                break;
            }
        }
        return String.join(System.lineSeparator(), result);
    }

    private String collapseEmptyExclusions(String content) {
        return content.replaceAll("\\s*<exclusions>\\s*</exclusions>", "");
    }

    private String detectIndent(String line) {
        int i = 0;
        while (i < line.length() && (line.charAt(i) == ' ' || line.charAt(i) == '\t')) i++;
        return line.substring(0, i);
    }

    private String detectIndentForClose(List<String> lines, int closeIdx) {
        return detectIndent(lines.get(closeIdx));
    }

    private String extractRedkiteTag(String commentLine) {
        int start = commentLine.indexOf("<!-- ") + 5;
        int end = commentLine.indexOf(' ', start);
        if (end == -1) end = commentLine.indexOf("-->");
        return end > start ? commentLine.substring(start, end) : null;
    }

    private static List<String> toLines(String content) {
        return new ArrayList<>(List.of(content.split("\n", -1)));
    }

    private String extractAttrValue(String comment, String attr) {
        String key = attr + "=\"";
        int start = comment.indexOf(key);
        if (start == -1) return null;
        start += key.length();
        int end = comment.indexOf('"', start);
        return end > start ? comment.substring(start, end) : null;
    }

    private static String escapeAttr(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;");
    }

    /** Strips Maven tree annotations (e.g. " (managed) <-- ...") from a version string. */
    static String sanitizeVersion(String version) {
        if (version == null) return "";
        int space = version.indexOf(' ');
        return space > 0 ? version.substring(0, space) : version;
    }
}

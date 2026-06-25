package com.redkite.maven;

import com.redkite.core.domain.ConflictCandidateAction;
import com.redkite.core.domain.ConflictCandidateAction.ActionType;
import com.redkite.core.domain.TransitiveConflictFinding;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses the output of {@code mvn enforcer:enforce} to extract structured
 * {@link TransitiveConflictFinding} records.
 *
 * <p>Handles both {@code dependencyConvergence} and {@code requireUpperBoundDeps} rule output.
 */
public class ConflictOutputParser {

    private static final Pattern CONVERGENCE_HEADER = Pattern.compile(
            "Dependency convergence error for ([^:]+):([^:]+):([^\\s]+)");
    private static final Pattern UPPER_BOUND_HEADER = Pattern.compile(
            "Require upper bound dependencies error for ([^:]+):([^:]+):([^\\s]+)");
    private static final Pattern PATH_ENTRY = Pattern.compile(
            "^[\\s|+\\\\-]*\\+?-([^:]+):([^:]+):([^:]+):([^:]+)(?::(.+))?$");
    private static final Pattern SIMPLE_COORD = Pattern.compile(
            "^[\\s|+\\\\-]*\\+?-([^:]+):([^:]+):([^\\s:]+)");

    public List<TransitiveConflictFinding> parse(String rawOutput) {
        List<TransitiveConflictFinding> findings = new ArrayList<>();
        if (rawOutput == null || rawOutput.isBlank()) return findings;

        String[] lines = rawOutput.split("\n");
        int i = 0;
        while (i < lines.length) {
            String stripped = stripInfoPrefix(lines[i]);
            Matcher cm = CONVERGENCE_HEADER.matcher(stripped);
            Matcher um = UPPER_BOUND_HEADER.matcher(stripped);
            if (cm.find()) {
                String gId = cm.group(1);
                String aId = cm.group(2);
                String version = normalizeVersion(cm.group(3).replaceAll("\\s.*", ""));
                List<String> paths = collectPaths(lines, i + 1);
                i += 1 + countPathBlock(lines, i + 1);
                findings.add(buildFinding(gId, aId, version, paths, "dependencyConvergence"));
            } else if (um.find()) {
                String gId = um.group(1);
                String aId = um.group(2);
                String version = normalizeVersion(um.group(3).replaceAll("\\s.*", ""));
                List<String> paths = collectPaths(lines, i + 1);
                i += 1 + countPathBlock(lines, i + 1);
                findings.add(buildFinding(gId, aId, version, paths, "requireUpperBoundDeps"));
            } else {
                i++;
            }
        }
        return findings;
    }

    private static String normalizeVersion(String raw) {
        // Enforcer headers sometimes include the Maven type: "jar:3.5.6" or "pom:2.0.0".
        // Strip it so the version compares correctly with versions extracted from path lines.
        int colon = raw.indexOf(':');
        if (colon > 0) {
            String prefix = raw.substring(0, colon).toLowerCase();
            if (prefix.equals("jar") || prefix.equals("pom") || prefix.equals("war")
                    || prefix.equals("ear") || prefix.equals("test-jar")
                    || prefix.equals("bundle") || prefix.equals("aar")) {
                raw = raw.substring(colon + 1);
            }
        }
        // Strip trailing sentence punctuation — enforcer headers end with a period before " Paths to..."
        // and the regex captures up to the space, leaving e.g. "3.5.6." instead of "3.5.6".
        return raw.replaceAll("\\.+$", "");
    }

    private TransitiveConflictFinding buildFinding(
            String groupId, String artifactId, String resolvedVersion,
            List<String> paths, String ruleName) {

        Set<String> conflictingVersions = new LinkedHashSet<>();
        List<ConflictCandidateAction> actions = new ArrayList<>();
        Set<String> exclusionParents = new LinkedHashSet<>();

        // ADD_DEPENDENCY_MANAGEMENT: pin to the resolved version
        actions.add(new ConflictCandidateAction(
                ActionType.ADD_DEPENDENCY_MANAGEMENT,
                groupId, artifactId, resolvedVersion, null, null));

        // ADD_EXCLUSION: one candidate per distinct direct-dependency parent, for ALL paths.
        // Each candidate carries the version it introduces so the UI can offer "use latest" auto-fix.
        // A jar cannot be excluded from itself (self-exclusion guard).
        for (String path : paths) {
            String[] pathLines = path.split("\n");

            // Determine the version of the conflicting artifact this path introduces
            String introducedVersion = null;
            for (String line : pathLines) {
                Optional<String> v = extractVersion(line, groupId, artifactId);
                if (v.isPresent()) { introducedVersion = v.get(); break; }
            }
            if (introducedVersion == null) continue;

            if (!introducedVersion.equals(resolvedVersion)) {
                conflictingVersions.add(introducedVersion);
            }

            if (pathLines.length >= 2) {
                final String pathVersion = introducedVersion;
                parseCoord(pathLines[1]).ifPresent(coord -> {
                    if (coord[0].equals(groupId) && coord[1].equals(artifactId)) return;
                    String key = coord[0] + ":" + coord[1];
                    if (exclusionParents.add(key)) {
                        actions.add(new ConflictCandidateAction(
                                ActionType.ADD_EXCLUSION,
                                groupId, artifactId, pathVersion,
                                coord[0], coord[1]));
                    }
                });
            }
        }

        return new TransitiveConflictFinding(
                groupId, artifactId, resolvedVersion,
                List.copyOf(conflictingVersions),
                paths, ruleName, null,
                List.copyOf(actions));
    }

    /**
     * Collects dependency path blocks starting at {@code startLine}.
     * Each path is one continuous tree block (lines starting with tree chars or +-).
     */
    private List<String> collectPaths(String[] lines, int startLine) {
        List<String> paths = new ArrayList<>();
        StringBuilder current = null;
        for (int i = startLine; i < lines.length; i++) {
            String stripped = stripInfoPrefix(lines[i]);
            if (stripped.trim().isEmpty() || stripped.trim().equals("]")) break;
            if (stripped.trim().equals("[")) continue;

            boolean isRoot = stripped.matches("^\\+-[^:]+:[^:]+:.*") || stripped.matches("^[^\\s|+\\\\-]+:[^:]+:.*");
            if (isRoot && current != null) {
                paths.add(current.toString());
                current = null;
            }
            if (current == null) current = new StringBuilder();
            if (current.length() > 0) current.append("\n");
            current.append(stripped);
        }
        if (current != null && !current.isEmpty()) paths.add(current.toString());
        return paths;
    }

    private int countPathBlock(String[] lines, int startLine) {
        int count = 0;
        for (int i = startLine; i < lines.length; i++) {
            String stripped = stripInfoPrefix(lines[i]);
            if (stripped.trim().isEmpty() || stripped.trim().equals("]")) {
                count++;
                break;
            }
            count++;
        }
        return count;
    }

    private Optional<String> extractVersion(String line, String groupId, String artifactId) {
        // Handles "+-groupId:artifactId:version" or "+-groupId:artifactId:packaging:version:scope"
        String stripped = line.replaceAll("^[\\s|+\\\\-]*\\+-", "").strip();
        String[] parts = stripped.split(":");
        if (parts.length >= 3 && parts[0].equals(groupId) && parts[1].equals(artifactId)) {
            // g:a:v or g:a:p:v or g:a:p:v:s
            String v = parts.length == 3 ? parts[2] : parts[2].equals("jar") || parts[2].equals("pom") ? parts[3] : parts[2];
            // Maven annotates managed versions with " (managed) <-- ..." — strip everything after the first space
            int space = v.indexOf(' ');
            return Optional.of(space > 0 ? v.substring(0, space) : v);
        }
        return Optional.empty();
    }

    private Optional<String[]> parseCoord(String line) {
        String stripped = line.replaceAll("^[\\s|+\\\\-]*\\+-", "").strip();
        String[] parts = stripped.split(":");
        if (parts.length >= 2) {
            return Optional.of(new String[]{parts[0], parts[1]});
        }
        return Optional.empty();
    }

    private static String stripInfoPrefix(String line) {
        // Strips "[INFO] " prefix from Maven output lines
        String s = line;
        if (s.startsWith("[INFO] ")) s = s.substring(7);
        else if (s.startsWith("[WARNING] ")) s = s.substring(10);
        else if (s.startsWith("[ERROR] ")) s = s.substring(8);
        return s;
    }
}

package com.redkite.maven;

import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Applies enforcer-suggested remediations to POM files.
 *
 * <p>All mutations go through DOM parse + serialise (never string splicing), so output is
 * always well-formed XML with consistent two-space indentation.
 *
 * <p>RedKite-managed insertions are marked with structured XML comments so they
 * can be identified and reversed:
 * <ul>
 *   <li>Exclusions: {@code <!-- redkite:exclusion groupId="..." artifactId="..." reason="..." -->}
 *   <li>Dependency management pins: {@code <!-- redkite:dependency-management pin groupId="..." artifactId="..." version="..." reason="..." — remove this comment to prevent RedKite managing this dependency -->}
 * </ul>
 *
 * <p>Dependency management pins RedKite inserts itself always use a hardcoded {@code <version>}
 * rather than a {@code ${...}} property reference — they're meant to be a single, self-contained,
 * independently removable override. The reverse also holds: when the PROJECT already manages an
 * artifact through a version property, RedKite updates the property's value rather than
 * hardcoding the entry, preserving the family semantics the property encodes.
 */
public class RemediationApplier {

    private static final String EXCLUSION_TAG = "redkite:exclusion";
    private static final String DEP_MGMT_TAG = "redkite:dependency-management pin";
    // Matches both the current marker and the pre-rename one ("redkite:dependency-management",
    // no " pin" suffix) so pins written by older RedKite versions are still recognized as
    // existing pins to update in place instead of being duplicated by a fresh insert.
    private static final String DEP_MGMT_TAG_DETECT_PREFIX = "redkite:dependency-management";
    private static final String DEP_MGMT_REMOVE_NOTE = "remove this comment to prevent RedKite managing this dependency";

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
        Document doc = parse(content);
        boolean changed = false;
        for (Element dep : elementsByTag(doc, "dependency")) {
            if (!coordMatches(dep, parentGroupId, parentArtifactId)) continue;
            if (hasRedkiteExclusion(dep, excludeGroupId, excludeArtifactId)) continue;

            // Maven allows at most one <exclusions> element per dependency — reuse it if present
            Element exclusions = directChild(dep, "exclusions");
            if (exclusions == null) {
                exclusions = doc.createElement("exclusions");
                dep.appendChild(exclusions);
            }
            Comment marker = doc.createComment(" " + EXCLUSION_TAG
                    + " groupId=\"" + excludeGroupId + "\""
                    + " artifactId=\"" + excludeArtifactId + "\""
                    + " reason=\"" + escapeAttr(reason) + "\" ");
            Element exclusion = doc.createElement("exclusion");
            appendTextChild(doc, exclusion, "groupId", excludeGroupId);
            appendTextChild(doc, exclusion, "artifactId", excludeArtifactId);
            exclusions.appendChild(marker);
            exclusions.appendChild(exclusion);
            changed = true;
        }
        return changed ? serialize(doc) : content;
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
        Document doc = parse(content);

        // 1) A redkite-managed entry already exists — update it in place.
        Comment existing = findRedkiteDepMgmtComment(doc, groupId, artifactId);
        if (existing != null) {
            String data = existing.getData()
                    .replaceAll("version=\"[^\"]*\"", "version=\"" + version + "\"")
                    .replaceAll("reason=\"[^\"]*\"", "reason=\"" + escapeAttr(reason) + "\"");
            existing.setData(data);
            Element dep = nextElementSibling(existing);
            if (dep != null && "dependency".equals(dep.getNodeName())) {
                setChildText(doc, dep, "version", version);
            }
            return serialize(doc);
        }

        // 2) The project already has its OWN (non-RedKite) dependencyManagement entry for this
        // artifact. Never insert a second <dependency> block for the same groupId:artifactId
        // (Maven rejects it with "must be unique") — and never destroy the entry's semantics:
        Element plain = findPlainDepMgmtEntry(doc, groupId, artifactId);
        if (plain != null) {
            Element versionEl = directChild(plain, "version");
            String versionText = versionEl != null ? versionEl.getTextContent().trim() : null;
            if (versionText != null && versionText.startsWith("${") && versionText.endsWith("}")) {
                // The entry manages this artifact through a version property — typically a
                // family property shared by sibling modules (e.g. ${logback.version} driving
                // both logback-core and logback-classic). Hardcoding this one entry would
                // silently detach it from its family, so update the property's VALUE instead,
                // moving every dependency that shares it together.
                String propertyName = versionText.substring(2, versionText.length() - 1);
                Element property = findProjectProperty(doc, propertyName);
                if (property == null) {
                    // Property not defined in this POM (e.g. inherited from a parent) — leave
                    // the project's management untouched; converting the entry into a
                    // standalone hardcoded pin is worse than not applying the fix.
                    return content;
                }
                if (version.equals(property.getTextContent().trim())) {
                    return content;
                }
                property.setTextContent(version);
                return serialize(doc);
            }
            // Literal version: take the entry over — mark it and update the version in place.
            setChildText(doc, plain, "version", version);
            plain.getParentNode().insertBefore(
                    buildPinComment(doc, groupId, artifactId, version, reason), plain);
            return serialize(doc);
        }

        // 3) Append to an existing <dependencyManagement><dependencies> block.
        for (Element depMgmt : elementsByTag(doc, "dependencyManagement")) {
            Element dependencies = directChild(depMgmt, "dependencies");
            if (dependencies != null) {
                dependencies.appendChild(buildPinComment(doc, groupId, artifactId, version, reason));
                dependencies.appendChild(buildPinDependency(doc, groupId, artifactId, version));
                return serialize(doc);
            }
        }

        // 4) No <dependencyManagement> at all — create one under the project root.
        Element root = doc.getDocumentElement();
        Element depMgmt = doc.createElement("dependencyManagement");
        Element dependencies = doc.createElement("dependencies");
        dependencies.appendChild(buildPinComment(doc, groupId, artifactId, version, reason));
        dependencies.appendChild(buildPinDependency(doc, groupId, artifactId, version));
        depMgmt.appendChild(dependencies);
        root.appendChild(depMgmt);
        return serialize(doc);
    }

    /**
     * Strips all redkite-managed exclusions and dependency-management entries from a POM.
     * Used to create a "clean" temp POM for re-analysis (Stage 4).
     */
    public String stripRedkiteRemediations(String content) {
        Document doc = parse(content);
        for (Comment comment : allComments(doc)) {
            String data = comment.getData().strip();
            if (data.startsWith(EXCLUSION_TAG)) {
                Element next = nextElementSibling(comment);
                if (next != null && "exclusion".equals(next.getNodeName())) {
                    Node exclusions = next.getParentNode();
                    exclusions.removeChild(next);
                    comment.getParentNode().removeChild(comment);
                    // If the <exclusions> wrapper is now empty, remove it too
                    if (exclusions instanceof Element e && "exclusions".equals(e.getNodeName())
                            && directChildren(e).isEmpty()) {
                        e.getParentNode().removeChild(e);
                    }
                } else {
                    comment.getParentNode().removeChild(comment);
                }
            } else if (data.startsWith(DEP_MGMT_TAG_DETECT_PREFIX)) {
                Element next = nextElementSibling(comment);
                if (next != null && "dependency".equals(next.getNodeName())) {
                    next.getParentNode().removeChild(next);
                }
                comment.getParentNode().removeChild(comment);
            }
        }
        return serialize(doc);
    }

    /** Removes all {@code <dependencyManagement>} blocks from content. */
    public String stripAllDepManagement(String content) {
        Document doc = parse(content);
        for (Element depMgmt : elementsByTag(doc, "dependencyManagement")) {
            depMgmt.getParentNode().removeChild(depMgmt);
        }
        return serialize(doc);
    }

    /**
     * Returns G:A:V strings for all entries declared in {@code <dependencyManagement>} sections.
     */
    public List<String> extractDepMgmtEntries(String content) {
        List<String> entries = new ArrayList<>();
        Document doc = parse(content);
        for (Element depMgmt : elementsByTag(doc, "dependencyManagement")) {
            for (Element dep : elementsByTag(depMgmt, "dependency")) {
                String g = childText(dep, "groupId");
                String a = childText(dep, "artifactId");
                String v = childText(dep, "version");
                if (g != null && a != null && v != null) {
                    entries.add(g + ":" + a + ":" + v);
                }
            }
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

    // ---- DOM builders ----

    private Comment buildPinComment(Document doc, String groupId, String artifactId,
                                    String version, String reason) {
        return doc.createComment(" " + DEP_MGMT_TAG
                + " groupId=\"" + groupId + "\""
                + " artifactId=\"" + artifactId + "\""
                + " version=\"" + version + "\""
                + " reason=\"" + escapeAttr(reason) + "\""
                + " — " + DEP_MGMT_REMOVE_NOTE + " ");
    }

    private Element buildPinDependency(Document doc, String groupId, String artifactId, String version) {
        Element dep = doc.createElement("dependency");
        appendTextChild(doc, dep, "groupId", groupId);
        appendTextChild(doc, dep, "artifactId", artifactId);
        appendTextChild(doc, dep, "version", version);
        return dep;
    }

    // ---- DOM scanning helpers ----

    /** All elements with the given tag name, in document order, materialised so removal is safe. */
    private static List<Element> elementsByTag(Document doc, String tag) {
        return materialise(doc.getElementsByTagName(tag));
    }

    private static List<Element> elementsByTag(Element scope, String tag) {
        return materialise(scope.getElementsByTagName(tag));
    }

    private static List<Element> materialise(NodeList nl) {
        List<Element> out = new ArrayList<>();
        for (int i = 0; i < nl.getLength(); i++) {
            if (nl.item(i) instanceof Element e) out.add(e);
        }
        return out;
    }

    private static List<Comment> allComments(Document doc) {
        List<Comment> out = new ArrayList<>();
        collectComments(doc.getDocumentElement(), out);
        return out;
    }

    private static void collectComments(Node node, List<Comment> out) {
        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child instanceof Comment c) out.add(c);
            else if (child.getNodeType() == Node.ELEMENT_NODE) collectComments(child, out);
        }
    }

    private Comment findRedkiteDepMgmtComment(Document doc, String groupId, String artifactId) {
        for (Comment comment : allComments(doc)) {
            String data = comment.getData().strip();
            if (data.startsWith(DEP_MGMT_TAG_DETECT_PREFIX)
                    && data.contains("groupId=\"" + groupId + "\"")
                    && data.contains("artifactId=\"" + artifactId + "\"")) {
                return comment;
            }
        }
        return null;
    }

    /** Finds a property element by name in the project root's {@code <properties>} block. */
    private static Element findProjectProperty(Document doc, String propertyName) {
        Element properties = directChild(doc.getDocumentElement(), "properties");
        return properties != null ? directChild(properties, propertyName) : null;
    }

    /**
     * Finds an existing, plain (non-RedKite-tagged) {@code <dependency>} entry for
     * {@code groupId:artifactId} inside any {@code <dependencyManagement>} block.
     */
    private Element findPlainDepMgmtEntry(Document doc, String groupId, String artifactId) {
        for (Element depMgmt : elementsByTag(doc, "dependencyManagement")) {
            for (Element dep : elementsByTag(depMgmt, "dependency")) {
                if (coordMatches(dep, groupId, artifactId)) return dep;
            }
        }
        return null;
    }

    private boolean hasRedkiteExclusion(Element dep, String groupId, String artifactId) {
        List<Comment> comments = new ArrayList<>();
        collectComments(dep, comments);
        for (Comment comment : comments) {
            String data = comment.getData().strip();
            if (data.startsWith(EXCLUSION_TAG)
                    && data.contains("groupId=\"" + groupId + "\"")
                    && data.contains("artifactId=\"" + artifactId + "\"")) {
                return true;
            }
        }
        return false;
    }

    private static boolean coordMatches(Element dep, String groupId, String artifactId) {
        return groupId.equals(childText(dep, "groupId")) && artifactId.equals(childText(dep, "artifactId"));
    }

    private static Element directChild(Element parent, String tag) {
        for (Element child : directChildren(parent)) {
            if (tag.equals(child.getNodeName())) return child;
        }
        return null;
    }

    private static List<Element> directChildren(Element parent) {
        List<Element> out = new ArrayList<>();
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i) instanceof Element e) out.add(e);
        }
        return out;
    }

    private static String childText(Element parent, String tag) {
        Element child = directChild(parent, tag);
        return child != null ? child.getTextContent().trim() : null;
    }

    private static void setChildText(Document doc, Element parent, String tag, String value) {
        Element child = directChild(parent, tag);
        if (child != null) {
            child.setTextContent(value);
        } else {
            appendTextChild(doc, parent, tag, value);
        }
    }

    private static void appendTextChild(Document doc, Element parent, String tag, String value) {
        Element child = doc.createElement(tag);
        child.setTextContent(value);
        parent.appendChild(child);
    }

    private static Element nextElementSibling(Node node) {
        Node sibling = node.getNextSibling();
        while (sibling != null && sibling.getNodeType() != Node.ELEMENT_NODE) {
            sibling = sibling.getNextSibling();
        }
        return (Element) sibling;
    }

    // ---- Parse / serialise ----

    private static Document parse(String content) {
        try {
            return DocumentBuilderFactory.newInstance().newDocumentBuilder()
                    .parse(new InputSource(new StringReader(content)));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse POM XML: " + e.getMessage(), e);
        }
    }

    private static String serialize(Document doc) {
        try {
            stripWhitespaceNodes(doc.getDocumentElement());
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            StringWriter sw = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(sw));
            return sw.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialise POM XML: " + e.getMessage(), e);
        }
    }

    /** Removes whitespace-only text nodes so the indenting serialiser re-indents cleanly. */
    private static void stripWhitespaceNodes(Node node) {
        NodeList children = node.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.TEXT_NODE && child.getTextContent().isBlank()) {
                node.removeChild(child);
            } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                stripWhitespaceNodes(child);
            }
        }
    }

    // ---- Misc ----

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

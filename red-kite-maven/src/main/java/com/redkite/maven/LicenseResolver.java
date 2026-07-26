package com.redkite.maven;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Resolves the license(s) declared by a Maven artifact's own POM — walking its parent chain when
 * the POM itself declares none, since Maven allows a {@code <licenses>} block to be inherited
 * rather than repeated on every child. Unlike {@link ManagedVersionResolver} this needs no
 * property resolution or BOM-import walking, just {@code <licenses>} and {@code <parent>}.
 *
 * <p>Returns an empty list when nothing in the reachable chain declares a license — whether that's
 * because the artifact genuinely has none, or its POM (or an ancestor's) couldn't be fetched at
 * all. Callers show that as "no license declared" either way; distinguishing "confirmed none" from
 * "couldn't check" isn't tracked here.
 */
public final class LicenseResolver {
    private static final Logger LOGGER = Logger.getLogger(LicenseResolver.class.getName());
    private static final int MAX_DEPTH = 10;

    private record ParsedPom(List<String> licenses, String parentGroupId, String parentArtifactId, String parentVersion) {
    }

    private final PomSource source;
    private final Map<String, Optional<ParsedPom>> cache = new HashMap<>();

    public LicenseResolver(PomSource source) {
        this.source = source;
    }

    /** Licenses declared by {@code groupId:artifactId:version}'s own POM, or — if it declares
     *  none — the nearest ancestor in its parent chain that does. */
    public List<String> resolve(String groupId, String artifactId, String version) {
        return resolve(groupId, artifactId, version, 0, new LinkedHashSet<>());
    }

    private List<String> resolve(String groupId, String artifactId, String version, int depth, Set<String> visited) {
        if (depth > MAX_DEPTH) return List.of();
        String key = groupId + ":" + artifactId + ":" + version;
        if (!visited.add(key)) return List.of(); // cycle guard
        ParsedPom parsed = cache.computeIfAbsent(key, k -> fetchAndParse(groupId, artifactId, version)).orElse(null);
        if (parsed == null) return List.of();
        if (!parsed.licenses().isEmpty()) return parsed.licenses();
        if (parsed.parentGroupId() != null && parsed.parentArtifactId() != null && parsed.parentVersion() != null) {
            return resolve(parsed.parentGroupId(), parsed.parentArtifactId(), parsed.parentVersion(), depth + 1, visited);
        }
        return List.of();
    }

    private Optional<ParsedPom> fetchAndParse(String groupId, String artifactId, String version) {
        Optional<String> xml = source.fetchPom(groupId, artifactId, version);
        if (xml.isEmpty()) {
            LOGGER.fine(() -> "Could not fetch POM for " + groupId + ":" + artifactId + ":" + version + " — license lookup stops here on this branch");
            return Optional.empty();
        }
        try {
            return Optional.of(parse(xml.get()));
        } catch (Exception e) {
            LOGGER.warning(() -> "Failed to parse fetched POM for " + groupId + ":" + artifactId + ":" + version + ": " + e.getMessage());
            return Optional.empty();
        }
    }

    private static ParsedPom parse(String xml) throws Exception {
        var dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        Document doc = dbf.newDocumentBuilder().parse(new org.xml.sax.InputSource(new StringReader(xml)));
        Element project = doc.getDocumentElement();

        String parentGroupId = null, parentArtifactId = null, parentVersion = null;
        Element parent = directChild(project, "parent");
        if (parent != null) {
            parentGroupId = childText(parent, "groupId");
            parentArtifactId = childText(parent, "artifactId");
            parentVersion = childText(parent, "version");
        }

        List<String> licenses = new ArrayList<>();
        Element licensesEl = directChild(project, "licenses");
        if (licensesEl != null) {
            NodeList licenseNodes = licensesEl.getElementsByTagName("license");
            for (int i = 0; i < licenseNodes.getLength(); i++) {
                Element licenseEl = (Element) licenseNodes.item(i);
                String name = childText(licenseEl, "name");
                if (name != null && !name.isBlank()) licenses.add(name.trim());
            }
        }
        return new ParsedPom(List.copyOf(licenses), parentGroupId, parentArtifactId, parentVersion);
    }

    private static Element directChild(Element parent, String tag) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n instanceof Element e && tag.equals(e.getNodeName())) return e;
        }
        return null;
    }

    private static String childText(Element parent, String tag) {
        Element child = directChild(parent, tag);
        if (child == null) return null;
        String text = child.getTextContent();
        return text == null ? null : text.trim();
    }
}

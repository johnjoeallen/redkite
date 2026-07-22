package com.redkite.maven;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Recursively resolves what a module's parent chain and imported BOMs manage for coordinates the
 * module doesn't already control itself — the piece of the provenance design that needs fetching
 * external POMs, kept separate from {@link MavenProjectScanner}'s own-POM-only parsing.
 *
 * <p>Precedence mirrors Maven's own: a POM's own {@code dependencyManagement} entries (including
 * BOMs it imports, in declaration order) win over anything from its parent; the parent's own
 * entries/imports win over the grandparent's, and so on. Property resolution follows the same
 * "nearest POM wins" rule — a property is resolved against whichever POM nearest the start
 * (walked first) defines it, so a child's override of a name a parent/BOM also defines is used
 * everywhere, including inside the parent/BOM's own managed-version expressions.
 *
 * <p>Known simplification: a property is only resolved from each POM's own {@code <properties>}
 * block, not that POM's inherited properties from its own parent — going further would mean
 * resolving each ancestor's full property set before this walk can even begin. Good enough for
 * the common case (a project overriding a shared, directly-declared property like
 * {@code logback.version}), not a fully faithful Maven property-resolution engine.
 */
public final class ManagedVersionResolver {
    private static final Logger LOGGER = Logger.getLogger(ManagedVersionResolver.class.getName());
    private static final int MAX_DEPTH = 10;

    /** @param controllerCoordinate {@code groupId:artifactId:version} of the parent or imported
     *      BOM that manages this version — {@code null} for an entry that came from the starting
     *      module's own dependencyManagement (the scanner already handles those directly; such
     *      entries are never actually looked up through this resolver's result).
     *  @param propertyName null when the managed version is a literal, not a property reference. */
    public record ManagedVersion(String version, String controllerCoordinate, String propertyName, boolean bomImport) {
    }

    private record RawManagedEntry(String groupId, String artifactId, String rawVersion, String propertyName, boolean bomImport) {
    }

    private record ExternalPom(String parentGroupId, String parentArtifactId, String parentVersion,
                                Map<String, String> properties, List<RawManagedEntry> managedDependencies) {
    }

    private final PomSource source;
    private final Map<String, Optional<ExternalPom>> cache = new HashMap<>();

    public ManagedVersionResolver(PomSource source) {
        this.source = source;
    }

    /** Resolves the merged parent/BOM-import managed-version table for {@code module}. Coordinates
     *  already controlled by the module's own literal/property/dependencyManagement declarations
     *  appear here too (with a null controllerCoordinate) but should never actually be queried —
     *  the scanner only consults this for components its own local pass left as
     *  {@code VersionSource.UNKNOWN}. */
    public Map<String, ManagedVersion> resolve(PomModel module) {
        Map<String, String> properties = new LinkedHashMap<>(module.properties());
        Map<String, ManagedVersion> managed = new LinkedHashMap<>();
        Set<String> visited = new LinkedHashSet<>();
        ExternalPom asExternal = new ExternalPom(module.parentGroupId(), module.parentArtifactId(), module.parentVersion(),
                Map.of(), toRawEntries(module.dependencyManagement()));
        contribute(asExternal, properties, managed, visited, 0, null, false);
        return managed;
    }

    private void contribute(ExternalPom pom, Map<String, String> properties, Map<String, ManagedVersion> managed,
                             Set<String> visited, int depth, String selfCoordinate, boolean viaBomImport) {
        if (pom == null || depth > MAX_DEPTH) return;
        for (Map.Entry<String, String> e : pom.properties().entrySet()) {
            properties.putIfAbsent(e.getKey(), e.getValue());
        }
        for (RawManagedEntry dep : pom.managedDependencies()) {
            String resolvedVersion = dep.propertyName() == null ? dep.rawVersion() : properties.get(dep.propertyName());
            if (resolvedVersion == null) continue; // undefined anywhere reachable — nothing to contribute
            if (dep.bomImport()) {
                recurse(dep.groupId(), dep.artifactId(), resolvedVersion, properties, managed, visited, depth + 1, true);
            } else {
                String key = dep.groupId() + ":" + dep.artifactId();
                managed.putIfAbsent(key, new ManagedVersion(resolvedVersion, selfCoordinate, dep.propertyName(), viaBomImport));
            }
        }
        if (pom.parentGroupId() != null && pom.parentArtifactId() != null && pom.parentVersion() != null) {
            recurse(pom.parentGroupId(), pom.parentArtifactId(), pom.parentVersion(), properties, managed, visited, depth + 1, false);
        }
    }

    private void recurse(String groupId, String artifactId, String version, Map<String, String> properties,
                          Map<String, ManagedVersion> managed, Set<String> visited, int depth, boolean viaBomImport) {
        String coordKey = groupId + ":" + artifactId + ":" + version;
        if (!visited.add(coordKey)) return; // cycle guard
        ExternalPom fetched = cache.computeIfAbsent(coordKey, k -> fetchAndParse(groupId, artifactId, version)).orElse(null);
        contribute(fetched, properties, managed, visited, depth, coordKey, viaBomImport);
    }

    private Optional<ExternalPom> fetchAndParse(String groupId, String artifactId, String version) {
        Optional<String> xml = source.fetchPom(groupId, artifactId, version);
        if (xml.isEmpty()) {
            LOGGER.fine(() -> "Could not fetch POM for " + groupId + ":" + artifactId + ":" + version + " — provenance stops here on this branch");
            return Optional.empty();
        }
        try {
            return Optional.of(parseExternalPom(xml.get()));
        } catch (Exception e) {
            LOGGER.warning(() -> "Failed to parse fetched POM for " + groupId + ":" + artifactId + ":" + version + ": " + e.getMessage());
            return Optional.empty();
        }
    }

    private static List<RawManagedEntry> toRawEntries(List<PomModel.PomDependency> deps) {
        return deps.stream()
                .map(d -> new RawManagedEntry(d.groupId(), d.artifactId(), d.version(), null, d.bomImport()))
                .toList();
    }

    private static ExternalPom parseExternalPom(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        Document document = factory.newDocumentBuilder().parse(new org.xml.sax.InputSource(new StringReader(xml)));
        Element project = document.getDocumentElement();

        String groupId = optionalText(project, "groupId");
        String version = optionalText(project, "version");
        String parentGroupId = null, parentArtifactId = null, parentVersion = null;
        Element parent = childElement(project, "parent");
        if (parent != null) {
            parentGroupId = optionalText(parent, "groupId");
            parentArtifactId = optionalText(parent, "artifactId");
            parentVersion = optionalText(parent, "version");
            if (groupId == null) groupId = parentGroupId;
            if (version == null) version = parentVersion;
        }

        Map<String, String> properties = new LinkedHashMap<>();
        if (groupId != null) properties.put("project.groupId", groupId);
        if (version != null) properties.put("project.version", version);
        if (parentGroupId != null) properties.put("project.parent.groupId", parentGroupId);
        if (parentVersion != null) properties.put("project.parent.version", parentVersion);
        Element propertiesEl = childElement(project, "properties");
        if (propertiesEl != null) {
            NodeList children = propertiesEl.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                Node child = children.item(i);
                if (child.getNodeType() == Node.ELEMENT_NODE) {
                    properties.put(child.getNodeName(), child.getTextContent().trim());
                }
            }
        }

        List<RawManagedEntry> managedDeps = new java.util.ArrayList<>();
        Element depMgmt = childElement(project, "dependencyManagement");
        if (depMgmt != null) {
            Element deps = childElement(depMgmt, "dependencies");
            if (deps != null) {
                NodeList items = deps.getElementsByTagName("dependency");
                for (int i = 0; i < items.getLength(); i++) {
                    Element dep = (Element) items.item(i);
                    String depGroupId = optionalText(dep, "groupId");
                    String depArtifactId = optionalText(dep, "artifactId");
                    String rawVersion = optionalText(dep, "version");
                    if (depGroupId == null || depArtifactId == null || rawVersion == null) continue;
                    boolean bomImport = "pom".equalsIgnoreCase(optionalText(dep, "type"))
                            && "import".equalsIgnoreCase(optionalText(dep, "scope"));
                    String propertyName = null;
                    if (rawVersion.startsWith("${") && rawVersion.endsWith("}")) {
                        propertyName = rawVersion.substring(2, rawVersion.length() - 1);
                    }
                    managedDeps.add(new RawManagedEntry(depGroupId, depArtifactId, rawVersion, propertyName, bomImport));
                }
            }
        }
        return new ExternalPom(parentGroupId, parentArtifactId, parentVersion, properties, managedDeps);
    }

    private static Element childElement(Element parent, String name) {
        NodeList nodes = parent.getElementsByTagName(name);
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node.getParentNode() == parent) return (Element) node;
        }
        return null;
    }

    private static String optionalText(Element parent, String tag) {
        NodeList nodes = parent.getElementsByTagName(tag);
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node.getParentNode() == parent) {
                String text = node.getTextContent();
                return text == null ? null : text.trim();
            }
        }
        return null;
    }
}

package com.redkite.server;

import com.redkite.core.domain.*;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/** Rewrites a POM's dependency, plugin and parent versions: literal versions become properties, upgrades and user pins are applied. */
final class PomPatcher {
    private static final Logger LOGGER = Logger.getLogger(PomPatcher.class.getName());

    private PomPatcher() {
    }

    /** Comment tag marking a Maven property (or dependencyManagement entry) as user-pinned —
     *  shared convention with {@link com.redkite.maven.RemediationApplier}'s {@code redkite:user-pin}. */
    private static final String USER_PIN_TAG = "redkite:user-pin";
    private static final String USER_PIN_NOTE = "user pinned — uncheck Pin in RedKite to let it manage this dependency again";

    static String patchPomXml(String content, Map<String, String> versionUpdates) throws Exception {
        return patchPomXml(content, versionUpdates, Set.of(), Set.of(), Set.of(), Set.of());
    }

    static String patchPomXml(String content, Map<String, String> versionUpdates,
                                      Set<String> pinnedCoords, Set<String> unpinnedCoords) throws Exception {
        return patchPomXml(content, versionUpdates, pinnedCoords, unpinnedCoords, Set.of(), Set.of());
    }

    static String patchPomXml(String content, Map<String, String> versionUpdates,
                                      Set<String> pinnedCoords, Set<String> unpinnedCoords,
                                      Set<String> activeProperties) throws Exception {
        return patchPomXml(content, versionUpdates, pinnedCoords, unpinnedCoords, activeProperties, Set.of());
    }

    static String patchPomXml(String content, Map<String, String> versionUpdates,
                                      Set<String> pinnedCoords, Set<String> unpinnedCoords,
                                      Set<String> activeProperties, Set<String> reservedPropertyNames) throws Exception {
        var dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(false);
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(content)));
        Element root = doc.getDocumentElement();

        // Collect <parent>, <dependency>, and <plugin> elements to patch — excluding RedKite's own
        // dependencyManagement pins, which always keep a hardcoded <version> by design (a pin is
        // meant to be a single, self-contained, independently removable override; normalising it
        // to a ${...} property here would entangle it with the project's own versioning scheme
        // and defeat "remove this comment to stop RedKite managing it").
        NodeList allElements = doc.getElementsByTagName("*");
        List<Element> patchTargets = new ArrayList<>();
        for (int i = 0; i < allElements.getLength(); i++) {
            Element e = (Element) allElements.item(i);
            if ("parent".equals(e.getNodeName()) || "dependency".equals(e.getNodeName()) || "plugin".equals(e.getNodeName())) {
                if (isRedkiteDepMgmtPin(e)) continue;
                patchTargets.add(e);
            }
        }

        // Pass 1: register property names already claimed by existing property references,
        // so literal-to-property normalisation in pass 2 doesn't collide with them.
        Map<String, String> propNameForCoord = new LinkedHashMap<>();
        for (Element dep : patchTargets) {
            String g = childText(dep, "groupId"), a = childText(dep, "artifactId");
            if (g == null || a == null) continue;
            if ("plugin".equals(dep.getNodeName()) && g.trim().isEmpty()) g = "org.apache.maven.plugins";
            g = g.trim(); a = a.trim();
            Node vn = directChildVersion(dep);
            if (vn == null) continue;
            String vt = vn.getTextContent().trim();
            if (vt.startsWith("${") && vt.endsWith("}"))
                propNameForCoord.put(g + ":" + a, vt.substring(2, vt.length() - 1));
        }

        // Pass 2: apply patches.
        // Every dependency or plugin with a literal <version> is normalised to a ${prop} reference.
        // Deps with existing property references just have their property value updated (if upgrading).
        // BOM-managed deps (no <version>) only get an explicit version added when upgrading.
        // propUpgradeTo tracks what each property is being set to, so we can detect the case where
        // two deps share a property ref but the user chose different upgrade targets for them.
        Map<String, String> propUpgradeTo = new LinkedHashMap<>();
        for (Element dep : patchTargets) {
            String g = childText(dep, "groupId"), a = childText(dep, "artifactId");
            if (g == null || a == null) continue;
            if ("plugin".equals(dep.getNodeName()) && g.trim().isEmpty()) g = "org.apache.maven.plugins";
            g = g.trim(); a = a.trim();
            String coord = g + ":" + a;
            String upgrade = versionUpdates.get(coord);
            Node versionNode = directChildVersion(dep);

            if (versionNode == null) {
                // BOM-managed: add explicit <version> only when upgrading (or when pinning, since
                // a pin needs a concrete version to attach its marker to).
                if (upgrade != null) {
                    Element versionEl = doc.createElement("version");
                    if (pinnedCoords.contains(coord) || unpinnedCoords.contains(coord)) {
                        // Route through the same property-backed convention as every other pin,
                        // rather than leaving a bare literal <version> with nothing to mark.
                        String propName = assignPropName(a, g, propNameForCoord, reservedPropertyNames);
                        propNameForCoord.put(coord, propName);
                        Element propertiesEl = findOrCreateProperties(doc, root);
                        setProperty(doc, propertiesEl, propName, upgrade);
                        versionEl.setTextContent("${" + propName + "}");
                        markPropertyPin(doc, propertiesEl, propName, upgrade, pinnedCoords.contains(coord));
                    } else {
                        versionEl.setTextContent(upgrade);
                    }
                    dep.appendChild(versionEl);
                }
                continue;
            }

            String versionText = versionNode.getTextContent().trim();
            if (versionText.isEmpty()) continue;

            if ("parent".equals(dep.getNodeName())) {
                // <parent> versions always stay literal, upgrade or not — even when the parent
                // is already declared through a ${...} reference. Maven resolves the parent's
                // coordinates before it processes <properties> (properties can themselves be
                // inherited from that same parent), so a ${...} reference here is never
                // interpolated. Falling through to the property branch below would write the
                // "upgrade" value into the referenced property instead: harmless when it's a
                // real version, but when the parent's current version couldn't be resolved (e.g.
                // an inherited property this POM doesn't itself declare) "upgrade" is that same
                // unresolved "${propName}" text, and the property ends up defined as a reference
                // to itself.
                if (upgrade != null) versionNode.setTextContent(upgrade);
            } else if (versionText.startsWith("${") && versionText.endsWith("}")) {
                // Existing property reference: update the property value when upgrading.
                // If two deps share the same property ref but target different versions,
                // give the second dep its own independent property rather than silently
                // overwriting the shared one.
                String propName = versionText.substring(2, versionText.length() - 1);
                String effectivePropName = propName;
                if (upgrade != null) {
                    String alreadySetTo = propUpgradeTo.get(propName);
                    if (alreadySetTo != null && !alreadySetTo.equals(upgrade)) {
                        // Conflict: create an independent property for this dep
                        String newPropName = assignPropName(a, g, propNameForCoord, reservedPropertyNames);
                        propNameForCoord.put(coord, newPropName);
                        setProperty(doc, findOrCreateProperties(doc, root), newPropName, upgrade);
                        versionNode.setTextContent("${" + newPropName + "}");
                        propUpgradeTo.put(newPropName, upgrade);
                        effectivePropName = newPropName;
                    } else {
                        setProperty(doc, findOrCreateProperties(doc, root), propName, upgrade);
                        propUpgradeTo.put(propName, upgrade);
                    }
                }
                if (pinnedCoords.contains(coord) || unpinnedCoords.contains(coord)) {
                    Element propertiesEl = findOrCreateProperties(doc, root);
                    NodeList existingProp = propertiesEl.getElementsByTagName(effectivePropName);
                    String effectiveVersion = upgrade != null ? upgrade
                            : existingProp.getLength() > 0 ? existingProp.item(0).getTextContent().trim() : versionText;
                    markPropertyPin(doc, propertiesEl, effectivePropName, effectiveVersion, pinnedCoords.contains(coord));
                }
            } else {
                // Literal version: normalise to a property reference.
                // Use the upgrade version if selected, otherwise keep the current version.
                String effectiveVersion = upgrade != null ? upgrade : versionText;
                String propName = propNameForCoord.get(coord);
                if (propName == null) {
                    propName = assignPropName(a, g, propNameForCoord, reservedPropertyNames);
                    propNameForCoord.put(coord, propName);
                }
                Element propertiesEl = findOrCreateProperties(doc, root);
                setProperty(doc, propertiesEl, propName, effectiveVersion);
                versionNode.setTextContent("${" + propName + "}");
                if (pinnedCoords.contains(coord) || unpinnedCoords.contains(coord)) {
                    markPropertyPin(doc, propertiesEl, propName, effectiveVersion, pinnedCoords.contains(coord));
                }
            }
        }

        // Pass 3: RedKite's own dependencyManagement pins are excluded from patchTargets above —
        // deliberately, so an unrelated bulk upgrade never re-normalises a pin's hardcoded version
        // into a ${...} property. But a scan surfaces every unmatched dependencyManagement entry
        // (including RedKite's own prior pins) as its own component, so a user can explicitly pick
        // a newer version for one — that selection must still land somewhere. Update the pin's
        // version (and the version= attribute on its marker comment, so the comment stays
        // truthful) in place, without touching who owns it or why.
        for (int i = 0; i < allElements.getLength(); i++) {
            Element e = (Element) allElements.item(i);
            if (!"dependency".equals(e.getNodeName()) || !isRedkiteDepMgmtPin(e)) continue;
            String pg = childText(e, "groupId"), pa = childText(e, "artifactId");
            if (pg == null || pa == null) continue;
            String upgrade = versionUpdates.get(pg.trim() + ":" + pa.trim());
            if (upgrade == null) continue;
            Node versionNode = directChildVersion(e);
            if (versionNode == null) continue;
            if (upgrade.equals(versionNode.getTextContent().trim())) continue;
            versionNode.setTextContent(upgrade);
            Node sibling = e.getPreviousSibling();
            while (sibling != null && sibling.getNodeType() == Node.TEXT_NODE && sibling.getTextContent().isBlank()) {
                sibling = sibling.getPreviousSibling();
            }
            if (sibling instanceof Comment c) {
                c.setData(c.getData().replaceFirst("version=\"[^\"]*\"", "version=\"" + upgrade + "\""));
            }
        }

        // Pass 4: drop <properties> entries no longer referenced by ${name} anywhere in this
        // file's own text — leftover cruft from an earlier upgrade that normalised a literal
        // version into a property whose owning <dependency> (or dependencyManagement pin) was
        // later removed some other way (as seen with a stale bcprov-jdk18on.version left behind
        // after its pin was replaced). Scoped to names ending in ".version": Maven's own
        // convention-consumed properties (maven.compiler.source, skipITs, etc.) are read directly
        // by plugins without ever appearing as a ${...} reference, so a blind "never referenced"
        // rule would delete those outright. activeProperties is the other half of the safety net —
        // properties the scan's own provenance resolution found actually controlling some
        // component's version, including ones a parent/imported BOM manages internally (Spring
        // Boot's BOM referencing its own ${logback-classic.version}, say) that never appear as a
        // literal ${...} anywhere in *this* project's own POM text at all. Also skipped entirely
        // for parent/aggregator POMs (packaging=pom), whose properties commonly exist purely for
        // child-module inheritance.
        if (!"pom".equals(childText(root, "packaging"))) {
            Element propertiesEl = null;
            for (int i = 0; i < root.getChildNodes().getLength(); i++) {
                Node n = root.getChildNodes().item(i);
                if (n instanceof Element e && "properties".equals(e.getNodeName())) { propertiesEl = e; break; }
            }
            if (propertiesEl != null) {
                StringBuilder allText = new StringBuilder();
                collectText(doc.getDocumentElement(), allText);
                String text = allText.toString();
                List<Element> orphaned = new ArrayList<>();
                for (int i = 0; i < propertiesEl.getChildNodes().getLength(); i++) {
                    Node n = propertiesEl.getChildNodes().item(i);
                    if (n instanceof Element propEl && propEl.getNodeName().endsWith(".version")
                            && !activeProperties.contains(propEl.getNodeName())
                            && !text.contains("${" + propEl.getNodeName() + "}")) {
                        orphaned.add(propEl);
                    }
                }
                for (Element propEl : orphaned) {
                    Node sibling = propEl.getPreviousSibling();
                    while (sibling != null && sibling.getNodeType() == Node.TEXT_NODE && sibling.getTextContent().isBlank()) {
                        sibling = sibling.getPreviousSibling();
                    }
                    if (sibling instanceof Comment c && c.getTextContent() != null
                            && c.getTextContent().strip().startsWith(USER_PIN_TAG)) {
                        propertiesEl.removeChild(sibling);
                    }
                    propertiesEl.removeChild(propEl);
                }
            }
        }

        stripWhitespaceNodes(doc);
        var tf = TransformerFactory.newInstance();
        var transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        StringWriter sw = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }

    /** Concatenates every text-node value under {@code node}, separated so adjacent text nodes
     *  can never accidentally merge into a false {@code ${name}} match. */
    private static void collectText(Node node, StringBuilder sb) {
        if (node.getNodeType() == Node.TEXT_NODE) {
            sb.append(node.getTextContent()).append('\n');
        }
        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            collectText(children.item(i), sb);
        }
    }

    static Node directChildVersion(Element dep) {
        for (int j = 0; j < dep.getChildNodes().getLength(); j++) {
            Node child = dep.getChildNodes().item(j);
            if ("version".equals(child.getNodeName())) return child;
        }
        return null;
    }

    /** Whether this &lt;dependency&gt; element is immediately preceded (ignoring whitespace) by a
     *  RedKite dependency-management-pin marker comment. Matched by substring rather than the
     *  full current tag text, so it still recognizes pins written by older RedKite versions that
     *  used the marker before it was renamed to include " pin". */
    private static boolean isRedkiteDepMgmtPin(Element dep) {
        Node sibling = dep.getPreviousSibling();
        while (sibling != null && sibling.getNodeType() == Node.TEXT_NODE && sibling.getTextContent().isBlank()) {
            sibling = sibling.getPreviousSibling();
        }
        return sibling != null && sibling.getNodeType() == Node.COMMENT_NODE
                && sibling.getTextContent() != null
                && (sibling.getTextContent().contains("redkite:dependency-management")
                    || sibling.getTextContent().contains(USER_PIN_TAG));
    }

    /** Adds, updates, or removes the {@code redkite:user-pin} marker comment immediately
     *  preceding a {@code <properties>} entry, mirroring RemediationApplier's convention. */
    private static void markPropertyPin(Document doc, Element propertiesEl, String propName, String version, boolean pinned) {
        NodeList existingProp = propertiesEl.getElementsByTagName(propName);
        if (existingProp.getLength() == 0) return;
        Element property = (Element) existingProp.item(0);
        Node prev = property.getPreviousSibling();
        while (prev != null && prev.getNodeType() == Node.TEXT_NODE && prev.getTextContent().isBlank()) {
            prev = prev.getPreviousSibling();
        }
        Comment existing = (prev != null && prev.getNodeType() == Node.COMMENT_NODE
                && prev.getTextContent() != null && prev.getTextContent().strip().startsWith(USER_PIN_TAG))
                ? (Comment) prev : null;
        if (!pinned) {
            if (existing != null) existing.getParentNode().removeChild(existing);
            return;
        }
        String data = " " + USER_PIN_TAG + " version=\"" + version + "\" — " + USER_PIN_NOTE + " ";
        if (existing != null) {
            existing.setData(data);
        } else {
            propertiesEl.insertBefore(doc.createComment(data), property);
        }
    }

    /** Picks an unused property name for a newly property-backed dependency version. Avoids two
     *  kinds of collision: another coordinate RedKite is patching in the same batch already claimed
     *  the short form (propNameForCoord), and a name the project's own parent chain / imported BOMs
     *  already rely on for something else entirely (reservedPropertyNames) — e.g. a Spring Boot
     *  parent's own {@code jackson-bom.version} controlling its internal Jackson BOM import. The
     *  groupId-qualified fallback resolves the overwhelming majority of real collisions (a
     *  third-party parent's own convention essentially never uses a fully-qualified name); if even
     *  that collides, the qualified name is still returned — there's no third fallback — since a
     *  caller needs *some* name, but this is logged so it's diagnosable. */
    private static String assignPropName(String a, String g, Map<String, String> propNameForCoord,
                                          Set<String> reservedPropertyNames) {
        String shortName = a + ".version";
        if (!propNameForCoord.containsValue(shortName) && !reservedPropertyNames.contains(shortName)) return shortName;
        String qualifiedName = g + "." + a + ".version";
        if (reservedPropertyNames.contains(shortName) && reservedPropertyNames.contains(qualifiedName)) {
            LOGGER.warning(() -> "Property name " + qualifiedName + " for " + g + ":" + a
                    + " also collides with a parent/BOM-declared property — using it anyway, nothing else available");
        }
        return qualifiedName;
    }

    private static Element findOrCreateProperties(Document doc, Element root) {
        for (int i = 0; i < root.getChildNodes().getLength(); i++) {
            Node n = root.getChildNodes().item(i);
            if (n instanceof Element e && "properties".equals(e.getNodeName())) return e;
        }
        Element propertiesEl = doc.createElement("properties");
        // Anchor on <project>'s own children only: a <dependencies> nested in a <profile> is not
        // a child of root, and inserting before it would throw.
        Node insertBefore = null;
        for (String anchor : List.of("dependencyManagement", "dependencies", "build")) {
            insertBefore = directChild(root, anchor);
            if (insertBefore != null) break;
        }
        if (insertBefore != null) {
            root.insertBefore(doc.createTextNode("\n  "), insertBefore);
            root.insertBefore(propertiesEl, insertBefore);
        } else {
            root.appendChild(doc.createTextNode("\n  "));
            root.appendChild(propertiesEl);
        }
        return propertiesEl;
    }

    private static void stripWhitespaceNodes(Node node) {
        for (int i = node.getChildNodes().getLength() - 1; i >= 0; i--) {
            Node child = node.getChildNodes().item(i);
            if (child.getNodeType() == Node.TEXT_NODE && child.getTextContent().isBlank()) {
                node.removeChild(child);
            } else if (child.getNodeType() == Node.ELEMENT_NODE) {
                stripWhitespaceNodes(child);
            }
        }
    }

    private static void setProperty(Document doc, Element propertiesEl, String name, String value) {
        NodeList existing = propertiesEl.getElementsByTagName(name);
        if (existing.getLength() > 0) {
            existing.item(0).setTextContent(value);
        } else {
            propertiesEl.appendChild(doc.createTextNode("\n    "));
            Element prop = doc.createElement(name);
            prop.setTextContent(value);
            propertiesEl.appendChild(prop);
        }
    }

    private static Element directChild(Element parent, String tagName) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && tagName.equals(e.getNodeName())) return e;
        }
        return null;
    }

    static String childText(Element parent, String tagName) {
        NodeList nl = parent.getElementsByTagName(tagName);
        return nl.getLength() > 0 ? nl.item(0).getTextContent() : null;
    }
}

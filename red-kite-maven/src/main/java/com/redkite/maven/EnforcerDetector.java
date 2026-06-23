package com.redkite.maven;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.logging.Logger;

/**
 * Detects whether a Maven project configures maven-enforcer-plugin with
 * dependency convergence rules (dependencyConvergence / requireUpperBoundDeps).
 */
public class EnforcerDetector {

    private static final Logger LOGGER = Logger.getLogger(EnforcerDetector.class.getName());

    private static final String ENFORCER_ARTIFACT_ID = "maven-enforcer-plugin";
    private static final String ENFORCER_GROUP_ID = "org.apache.maven.plugins";

    public enum DetectionResult {
        NOT_CONFIGURED,
        CONFIGURED_NO_CONVERGENCE_RULES,
        CONFIGURED_WITH_CONVERGENCE_RULES
    }

    public DetectionResult detect(Path projectRoot) {
        Path pom = projectRoot.resolve("pom.xml");
        if (!Files.exists(pom)) {
            return DetectionResult.NOT_CONFIGURED;
        }
        try {
            Document doc = parse(pom);
            Element root = doc.getDocumentElement();

            // Check <build><plugins> and <build><pluginManagement><plugins>
            boolean found = hasEnforcerPlugin(child(root, "build"));
            if (!found) {
                return DetectionResult.NOT_CONFIGURED;
            }
            boolean hasRules = hasConvergenceRules(child(root, "build"));
            return hasRules
                    ? DetectionResult.CONFIGURED_WITH_CONVERGENCE_RULES
                    : DetectionResult.CONFIGURED_NO_CONVERGENCE_RULES;
        } catch (Exception e) {
            LOGGER.warning(() -> "Failed to parse POM for enforcer detection: " + e.getMessage());
            return DetectionResult.NOT_CONFIGURED;
        }
    }

    private boolean hasEnforcerPlugin(Element buildEl) {
        if (buildEl == null) return false;
        return searchPlugins(child(buildEl, "plugins"))
                || searchPlugins(childPath(buildEl, "pluginManagement", "plugins"));
    }

    private boolean searchPlugins(Element pluginsEl) {
        if (pluginsEl == null) return false;
        NodeList plugins = pluginsEl.getChildNodes();
        for (int i = 0; i < plugins.getLength(); i++) {
            if (!(plugins.item(i) instanceof Element plugin)) continue;
            if (!"plugin".equals(plugin.getLocalName()) && !"plugin".equals(plugin.getNodeName())) continue;
            String groupId = text(plugin, "groupId");
            String artifactId = text(plugin, "artifactId");
            if (ENFORCER_ARTIFACT_ID.equals(artifactId)
                    && (groupId == null || groupId.isBlank() || ENFORCER_GROUP_ID.equals(groupId))) {
                return true;
            }
        }
        return false;
    }

    private boolean hasConvergenceRules(Element buildEl) {
        if (buildEl == null) return false;
        return scanPluginsForRules(child(buildEl, "plugins"))
                || scanPluginsForRules(childPath(buildEl, "pluginManagement", "plugins"));
    }

    private boolean scanPluginsForRules(Element pluginsEl) {
        if (pluginsEl == null) return false;
        NodeList plugins = pluginsEl.getChildNodes();
        for (int i = 0; i < plugins.getLength(); i++) {
            if (!(plugins.item(i) instanceof Element plugin)) continue;
            String artifactId = text(plugin, "artifactId");
            if (!ENFORCER_ARTIFACT_ID.equals(artifactId)) continue;
            // Check all <configuration><rules> in <executions> and top-level
            if (rulesContainConvergence(plugin)) return true;
        }
        return false;
    }

    private boolean rulesContainConvergence(Element pluginEl) {
        // Check top-level <configuration><rules>
        if (rulesEl(child(pluginEl, "configuration"))) return true;
        // Check each execution's <configuration><rules>
        Element executions = child(pluginEl, "executions");
        if (executions == null) return false;
        NodeList exList = executions.getChildNodes();
        for (int i = 0; i < exList.getLength(); i++) {
            if (!(exList.item(i) instanceof Element exec)) continue;
            if (rulesEl(child(exec, "configuration"))) return true;
        }
        return false;
    }

    private boolean rulesEl(Element configEl) {
        if (configEl == null) return false;
        Element rules = child(configEl, "rules");
        if (rules == null) {
            // rules may be absent; check config children directly
            rules = configEl;
        }
        NodeList children = rules.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (!(children.item(i) instanceof Element rule)) continue;
            String name = rule.getLocalName() != null ? rule.getLocalName() : rule.getNodeName();
            if ("dependencyConvergence".equalsIgnoreCase(name)
                    || "requireUpperBoundDeps".equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }

    // ---- XML helpers ----

    private static Document parse(Path path) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        try (InputStream in = Files.newInputStream(path)) {
            return factory.newDocumentBuilder().parse(in);
        }
    }

    static Element child(Element parent, String name) {
        if (parent == null) return null;
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            if (nodes.item(i) instanceof Element el) {
                String n = el.getLocalName() != null ? el.getLocalName() : el.getNodeName();
                if (name.equals(n)) return el;
            }
        }
        return null;
    }

    private static Element childPath(Element parent, String... names) {
        Element cur = parent;
        for (String name : names) {
            cur = child(cur, name);
            if (cur == null) return null;
        }
        return cur;
    }

    private static String text(Element parent, String name) {
        Element el = child(parent, name);
        return el == null ? null : el.getTextContent().strip();
    }
}

package com.redkite.maven;

import com.redkite.core.domain.PlannedFileChange;

import org.w3c.dom.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

public class PomEditor {
    public void applyChange(Path repoRoot, PlannedFileChange change) {
        try {
            Path file = repoRoot.resolve(change.relativeFilePath()).normalize();
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(false);
            Document document;
            try (var in = Files.newInputStream(file)) {
                document = factory.newDocumentBuilder().parse(in);
            }
            Element root = document.getDocumentElement();
            switch (change.changeType()) {
                case MAVEN_PROPERTY_UPDATE -> updateProperty(document, root, change.propertyName(), change.newVersion());
                case MAVEN_DIRECT_DEPENDENCY_VERSION_UPDATE -> updateDependencyVersion(document, root, change.groupId(), change.artifactId(), change.newVersion());
                case MAVEN_PARENT_VERSION_UPDATE -> updateChildText(root, "parent", "version", change.newVersion());
                case MAVEN_BOM_VERSION_UPDATE -> updateDependencyManagementVersion(document, root, change.groupId(), change.artifactId(), change.newVersion());
            }
            write(document, file);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to apply POM change", e);
        }
    }

    private void updateProperty(Document document, Element root, String propertyName, String version) {
        NodeList propertiesNodes = root.getElementsByTagName("properties");
        if (propertiesNodes.getLength() == 0) {
            throw new IllegalArgumentException("properties section not found");
        }
        Element properties = (Element) propertiesNodes.item(0);
        updateNamedChildText(properties, propertyName, version);
    }

    private void updateDependencyVersion(Document document, Element root, String groupId, String artifactId, String version) {
        Element dependencies = firstDirectChild(root, "dependencies").orElseThrow(() -> new IllegalArgumentException("dependencies section not found"));
        NodeList items = dependencies.getElementsByTagName("dependency");
        for (int i = 0; i < items.getLength(); i++) {
            Element dependency = (Element) items.item(i);
            if (groupId.equals(text(dependency, "groupId")) && artifactId.equals(text(dependency, "artifactId"))) {
                updateNamedChildText(dependency, "version", version);
                return;
            }
        }
        throw new IllegalArgumentException("dependency not found");
    }

    private void updateDependencyManagementVersion(Document document, Element root, String groupId, String artifactId, String version) {
        Element dependencyManagement = firstDirectChild(root, "dependencyManagement").orElseThrow(() -> new IllegalArgumentException("dependencyManagement section not found"));
        Element dependencies = firstDirectChild(dependencyManagement, "dependencies").orElseThrow(() -> new IllegalArgumentException("dependencyManagement dependencies section not found"));
        NodeList items = dependencies.getElementsByTagName("dependency");
        for (int i = 0; i < items.getLength(); i++) {
            Element dependency = (Element) items.item(i);
            if (groupId.equals(text(dependency, "groupId")) && artifactId.equals(text(dependency, "artifactId"))) {
                updateNamedChildText(dependency, "version", version);
                return;
            }
        }
        throw new IllegalArgumentException("managed dependency not found");
    }

    private void updateChildText(Element root, String childName, String nestedName, String version) {
        firstDirectChild(root, childName).ifPresentOrElse(element -> updateNamedChildText(element, nestedName, version), () -> {
            throw new IllegalArgumentException(childName + " section not found");
        });
    }

    private void updateNamedChildText(Element parent, String name, String value) {
        NodeList nodes = parent.getElementsByTagName(name);
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node.getParentNode() == parent) {
                node.setTextContent(value);
                return;
            }
        }
        Element child = parent.getOwnerDocument().createElement(name);
        child.setTextContent(value);
        parent.appendChild(child);
    }

    private Optional<Element> firstDirectChild(Element parent, String name) {
        NodeList nodes = parent.getElementsByTagName(name);
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node.getParentNode() == parent) {
                return Optional.of((Element) node);
            }
        }
        return Optional.empty();
    }

    private String text(Element parent, String tag) {
        NodeList nodes = parent.getElementsByTagName(tag);
        if (nodes.getLength() == 0) {
            return null;
        }
        return nodes.item(0).getTextContent().trim();
    }

    private void write(Document document, Path file) throws Exception {
        var transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        StringWriter out = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(out));
        Files.writeString(file, out.toString(), StandardCharsets.UTF_8);
    }
}

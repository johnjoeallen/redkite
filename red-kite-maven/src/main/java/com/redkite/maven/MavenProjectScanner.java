package com.redkite.maven;

import com.redkite.core.domain.*;

import org.w3c.dom.*;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

public class MavenProjectScanner {
    private static final Logger LOGGER = Logger.getLogger(MavenProjectScanner.class.getName());
    private final boolean allowMajorUpgrades;

    public MavenProjectScanner() {
        this(false);
    }

    public MavenProjectScanner(boolean allowMajorUpgrades) {
        this.allowMajorUpgrades = allowMajorUpgrades;
    }

    public ScanInput scan(Path projectRoot) {
        try {
            Path root = projectRoot.toAbsolutePath().normalize();
            LOGGER.info(() -> "Starting Maven scan for " + root);
            GitMetadata gitMetadata = readGitMetadata(root);
            LOGGER.info(() -> "Git metadata: branch=" + gitMetadata.branch() + ", head=" + gitMetadata.head() + ", clean=" + gitMetadata.clean());

            List<Path> pomFiles;
            try (var stream = Files.walk(root)) {
                pomFiles = stream.filter(p -> p.getFileName().toString().equals("pom.xml")).sorted().toList();
            }
            LOGGER.info(() -> "Found " + pomFiles.size() + " pom.xml file(s)");

            Map<String, PomModel> models = new LinkedHashMap<>();
            Map<String, String> hashes = new LinkedHashMap<>();
            Map<String, ScanComponent> componentsByKey = new LinkedHashMap<>();
            List<DependencyEdge> edges = new ArrayList<>();

            AtomicLong nextId = new AtomicLong(1L);
            for (Path pom : pomFiles) {
                LOGGER.info(() -> "Parsing POM " + root.relativize(pom));
                PomModel model = parsePom(pom);
                models.put(key(model.groupId(), model.artifactId()), model);
                String relativePom = sourceFile(root, pom);
                hashes.put(relativePom, sha256(pom));
                for (PomModel.PomDependency dep : model.dependencies()) {
                    if (isSelfDependency(model, dep)) {
                        LOGGER.info(() -> "Skipping self dependency declared in " + relativePom + ": " + dep.groupId() + ":" + dep.artifactId());
                        continue;
                    }
                    LOGGER.info(() -> "Top-level dependency declared in " + relativePom + ": " + dep.groupId() + ":" + dep.artifactId() + " version=" + dep.version() + " scope=" + dep.scope() + " source=" + dep.versionSource());
                    boolean snapshot = dep.version() != null && dep.version().contains("SNAPSHOT");
                    String sourceFile = relativePom;
                    String owning = versionControlPoint(dep, model);
                    ScanComponent component = new ScanComponent(
                            nextId.getAndIncrement(),
                            new ComponentCoordinate(dep.groupId(), dep.artifactId()),
                            dep.version() == null ? "unknown" : dep.version(),
                            dep.scope(),
                            true,
                            dep.versionSource(),
                            sourceFile,
                            "/project/dependencies/dependency[" + dep.groupId() + ":" + dep.artifactId() + "]",
                            model.properties(),
                            snapshot,
                            owning,
                            sourceFile);
                    componentsByKey.put(directKey(sourceFile, dep.groupId(), dep.artifactId()), component);
                }

                collectDependencyTree(root, pom, model, relativePom, componentsByKey, edges, nextId);
            }

            if (componentsByKey.isEmpty()) {
                LOGGER.warning(() -> "No dependencies discovered in " + root + "; creating placeholder component");
                componentsByKey.put("pom.xml|unknown:unknown|unknown|false", new ScanComponent(
                        nextId.getAndIncrement(),
                        new ComponentCoordinate("unknown", "unknown"),
                        "unknown",
                        DependencyScope.UNKNOWN,
                        false,
                        VersionSource.UNKNOWN,
                        "pom.xml",
                        "",
                        Map.of(),
                        false,
                        "unknown",
                        "pom.xml"));
            }

            List<ScanComponent> components = new ArrayList<>(componentsByKey.values());
            LOGGER.info(() -> "Scan completed with " + components.size() + " component(s), " + edges.size() + " dependency edge(s), and " + hashes.size() + " editable file hash(es)");
            return new ScanInput(root.getFileName().toString(), root.toString(), root.toString(), gitMetadata.branch(), gitMetadata.head(), gitMetadata.clean(), allowMajorUpgrades, Instant.now(), components, edges, hashes);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to scan Maven project", e);
        }
    }

    private void collectDependencyTree(Path root, Path pom, PomModel model, String sourceFile, Map<String, ScanComponent> componentsByKey, List<DependencyEdge> edges, AtomicLong nextId) {
        try {
            LOGGER.info(() -> "Running mvn dependency:tree for " + root.relativize(pom));
            List<String> command = List.of(
                    "mvn",
                    "-f",
                    pom.toString(),
                    "-DskipTests",
                    "dependency:tree");
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exit = process.waitFor();
            if (exit != 0) {
                LOGGER.warning(() -> "mvn dependency:tree failed for " + root.relativize(pom) + " with exit " + exit + "\n" + output);
                return;
            }
            List<ParsedTreeNode> nodes = parseDependencyTreeOutput(output);
            LOGGER.info(() -> "Parsed " + nodes.size() + " dependency tree node(s) from " + root.relativize(pom));
            String moduleNodeId = "module:" + sourceFile;
            List<String> ancestry = new ArrayList<>();
            ancestry.add(moduleNodeId);
            for (ParsedTreeNode node : nodes) {
                if (isSelfDependency(model.groupId(), model.artifactId(), node.groupId(), node.artifactId())) {
                    LOGGER.info(() -> "Skipping root self node from dependency tree for " + model.groupId() + ":" + model.artifactId());
                    continue;
                }
                while (ancestry.size() > node.depth()) {
                    ancestry.remove(ancestry.size() - 1);
                }
                String parentId = ancestry.get(ancestry.size() - 1);
                boolean direct = node.depth() == 1;
                ScanComponent component = findOrCreateTreeComponent(componentsByKey, sourceFile, node, direct, nextId);
                ancestry.add(component.id() + "");
                edges.add(new DependencyEdge(parentId, String.valueOf(component.id()), parseScope(node.scope()), direct));
                LOGGER.fine(() -> "Dependency tree edge: " + parentId + " -> " + component.id() + " (" + node.groupId() + ":" + node.artifactId() + ":" + node.version() + ")");
            }
        } catch (Exception e) {
            LOGGER.warning(() -> "Unable to run mvn dependency:tree for " + root.relativize(pom) + ": " + e.getMessage());
        }
    }

    private ScanComponent findOrCreateTreeComponent(Map<String, ScanComponent> componentsByKey, String sourceFile, ParsedTreeNode node, boolean direct, AtomicLong nextId) {
        if (direct) {
            for (ScanComponent component : componentsByKey.values()) {
                if (component.direct() && sourceFile.equals(component.sourceFilePath()) && component.coordinate().groupId().equals(node.groupId()) && component.coordinate().artifactId().equals(node.artifactId())) {
                    // Prefer the version from dependency:tree (Maven's effective/resolved version)
                    // over what we read from the raw POM, which may be an unresolved property or
                    // a declared version that loses to conflict/BOM resolution at runtime.
                    if (!isUnknownVersion(node.version()) && !node.version().equals(component.version())) {
                        ScanComponent resolved = new ScanComponent(
                                component.id(),
                                component.coordinate(),
                                node.version(),
                                component.scope(),
                                true,
                                component.versionSource(),
                                component.sourceFilePath(),
                                component.declarationPath(),
                                component.properties(),
                                node.version().contains("SNAPSHOT"),
                                component.owningVersionControlPoint(),
                                component.modulePath());
                        replaceComponent(componentsByKey, component, resolved);
                        LOGGER.info(() -> "Resolved direct dependency version from dependency tree for " + node.groupId() + ":" + node.artifactId() + " POM=" + component.version() + " => tree=" + node.version());
                        return resolved;
                    }
                    return component;
                }
            }
        }
        String key = direct ? directKey(sourceFile, node.groupId(), node.artifactId()) : componentKey(sourceFile, node.groupId(), node.artifactId(), node.version(), false);
        ScanComponent existing = componentsByKey.get(key);
        if (existing != null) {
            return existing;
        }
        ScanComponent created = new ScanComponent(
                nextId.getAndIncrement(),
                new ComponentCoordinate(node.groupId(), node.artifactId()),
                node.version(),
                parseScope(node.scope()),
                direct,
                VersionSource.UNKNOWN,
                sourceFile,
                "/project/dependency-tree/dependency[" + node.groupId() + ":" + node.artifactId() + "]",
                Map.of(),
                node.version() != null && node.version().contains("SNAPSHOT"),
                sourceFile + "#dependencyTree",
                sourceFile);
        componentsByKey.put(key, created);
        LOGGER.info(() -> "Discovered " + (direct ? "top-level" : "transitive") + " dependency from tree: " + node.groupId() + ":" + node.artifactId() + ":" + node.version() + " scope=" + node.scope());
        return created;
    }

    private void replaceComponent(Map<String, ScanComponent> componentsByKey, ScanComponent previous, ScanComponent replacement) {
        String previousKey = null;
        for (Map.Entry<String, ScanComponent> entry : componentsByKey.entrySet()) {
            if (entry.getValue().id() == previous.id()) {
                previousKey = entry.getKey();
                break;
            }
        }
        if (previousKey != null) {
            componentsByKey.remove(previousKey);
        }
        componentsByKey.put(replacement.direct()
                ? directKey(replacement.sourceFilePath(), replacement.coordinate().groupId(), replacement.coordinate().artifactId())
                : componentKey(replacement.sourceFilePath(), replacement.coordinate().groupId(), replacement.coordinate().artifactId(), replacement.version(), false), replacement);
    }

    private boolean isUnknownVersion(String version) {
        return version == null || version.isBlank() || "unknown".equalsIgnoreCase(version.trim());
    }

    private List<ParsedTreeNode> parseDependencyTreeOutput(String output) {
        List<ParsedTreeNode> nodes = new ArrayList<>();
        for (String rawLine : output.split("\\R")) {
            String line = rawLine.stripTrailing();
            if (line.isBlank()) {
                continue;
            }
            line = stripMavenLogPrefix(line);
            ParsedTreeNode node = parseDependencyTreeLine(line);
            if (node != null) {
                nodes.add(node);
            }
        }
        return nodes;
    }

    private String stripMavenLogPrefix(String line) {
        if (line.startsWith("[INFO] ")) {
            return line.substring(7);
        }
        if (line.startsWith("[WARNING] ")) {
            return line.substring(10);
        }
        if (line.startsWith("[ERROR] ")) {
            return line.substring(8);
        }
        return line;
    }

    private ParsedTreeNode parseDependencyTreeLine(String line) {
        if (!line.contains(":")) {
            return null;
        }
        int depth = depthOf(line);
        if (depth == 0) {
            return null;
        }
            int markerIndex = branchStart(line);
            if (markerIndex < 0 || markerIndex + 2 > line.length()) {
                return null;
            }
            String coords = line.substring(markerIndex + 2).trim();
            while (coords.startsWith("|")) {
                coords = coords.substring(1).trim();
            }
            // Skip omitted conflict entries — these are losing versions from Maven's
            // nearest-wins conflict resolution, not what's actually on the classpath.
            if (coords.contains("(omitted")) {
                return null;
            }
            String[] parts = coords.split(":");
            if (parts.length < 5) {
                return null;
            }
        String groupId = parts[0];
        String artifactId = parts[1];
        String version = parts[parts.length - 2];
        String scope = parts[parts.length - 1];
        return new ParsedTreeNode(depth, groupId, artifactId, version, scope);
    }

    private int depthOf(String line) {
        int index = branchStart(line);
        if (index < 0) {
            return 0;
        }
        String prefix = line.substring(0, index);
        int depth = 0;
        for (int i = 0; i + 3 <= prefix.length(); i += 3) {
            String segment = prefix.substring(i, i + 3);
            if ("|  ".equals(segment) || "   ".equals(segment)) {
                depth++;
            }
        }
        return depth + 1;
    }

    private int branchStart(String line) {
        int marker = line.indexOf("+-");
        int backslash = line.indexOf("\\-");
        if (marker < 0) {
            marker = -1;
        }
        if (backslash < 0) {
            backslash = -1;
        }
        if (marker < 0) {
            return backslash;
        }
        if (backslash < 0) {
            return marker;
        }
        return Math.min(marker, backslash);
    }

    private String sourceFile(Path root, Path pom) {
        return root.relativize(pom).toString().replace('\\', '/');
    }

    private String directKey(String sourceFile, String groupId, String artifactId) {
        return sourceFile + "|" + groupId + ":" + artifactId + "|direct";
    }

    private String componentKey(String sourceFile, String groupId, String artifactId, String version, boolean direct) {
        return sourceFile + "|" + groupId + ":" + artifactId + "|" + (version == null ? "unknown" : version) + "|" + direct;
    }

    private boolean isSelfDependency(PomModel model, PomModel.PomDependency dep) {
        return isSelfDependency(model.groupId(), model.artifactId(), dep.groupId(), dep.artifactId());
    }

    private boolean isSelfDependency(String leftGroupId, String leftArtifactId, String rightGroupId, String rightArtifactId) {
        return Objects.equals(leftGroupId, rightGroupId) && Objects.equals(leftArtifactId, rightArtifactId);
    }

    private record ParsedTreeNode(int depth, String groupId, String artifactId, String version, String scope) {
    }

    private GitMetadata readGitMetadata(Path root) {
        try {
            if (!Files.exists(root.resolve(".git"))) {
                LOGGER.info(() -> "No .git directory found at " + root + "; continuing as non-Git Maven directory");
                return new GitMetadata("(not a git repository)", "(not a git repository)", false);
            }
            String branch = git(root, "branch", "--show-current");
            String head = git(root, "rev-parse", "HEAD");
            boolean clean = git(root, "status", "--porcelain").isBlank();
            return new GitMetadata(branch, head, clean);
        } catch (Exception e) {
            return new GitMetadata("(not a git repository)", "(not a git repository)", false);
        }
    }

    private PomModel parsePom(Path pom) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        Document document;
        try (InputStream in = Files.newInputStream(pom)) {
            document = factory.newDocumentBuilder().parse(in);
        }
        Element project = document.getDocumentElement();
        String groupId = firstText(project, "groupId");
        String artifactId = firstText(project, "artifactId");
        String version = firstText(project, "version");
        String packaging = optionalText(project, "packaging");
        String parentGroupId = null;
        String parentArtifactId = null;
        String parentVersion = null;
        NodeList parentNodes = project.getElementsByTagName("parent");
        if (parentNodes.getLength() > 0) {
            Element parent = (Element) parentNodes.item(0);
            parentGroupId = optionalText(parent, "groupId");
            parentArtifactId = optionalText(parent, "artifactId");
            parentVersion = optionalText(parent, "version");
            if (groupId == null) {
                groupId = parentGroupId;
            }
            if (version == null) {
                version = parentVersion;
            }
        }
        Map<String, String> properties = new LinkedHashMap<>();
        if (groupId != null) {
            properties.put("project.groupId", groupId);
            properties.put("project.parent.groupId", parentGroupId == null ? groupId : parentGroupId);
        }
        if (artifactId != null) {
            properties.put("project.artifactId", artifactId);
        }
        if (version != null) {
            properties.put("project.version", version);
            properties.put("project.parent.version", parentVersion == null ? version : parentVersion);
        }
        if (packaging != null) {
            properties.put("project.packaging", packaging);
        }
        NodeList propertiesNodes = project.getElementsByTagName("properties");
        if (propertiesNodes.getLength() > 0) {
            Node propsNode = propertiesNodes.item(0);
            NodeList children = propsNode.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                Node child = children.item(i);
                if (child.getNodeType() == Node.ELEMENT_NODE) {
                    properties.put(child.getNodeName(), child.getTextContent().trim());
                }
            }
        }

        List<PomModel.PomDependency> deps = parseDependencies(project, properties);
        List<PomModel.PomDependency> managed = parseManagedDependencies(project, properties);
        return new PomModel(pom, groupId, artifactId, version, packaging, properties, deps, managed, parentGroupId, parentArtifactId, parentVersion);
    }

    private List<PomModel.PomDependency> parseDependencies(Element project, Map<String, String> properties) {
        Element deps = childElement(project, "dependencies");
        if (deps == null) {
            return List.of();
        }
        List<PomModel.PomDependency> result = new ArrayList<>();
        NodeList items = deps.getElementsByTagName("dependency");
        for (int i = 0; i < items.getLength(); i++) {
            Element dep = (Element) items.item(i);
            String groupId = optionalText(dep, "groupId");
            String artifactId = optionalText(dep, "artifactId");
            String version = optionalText(dep, "version");
            String propertyName = null;
            VersionSource source = VersionSource.UNKNOWN;
            if (version != null) {
                if (version.startsWith("${") && version.endsWith("}")) {
                    propertyName = version.substring(2, version.length() - 1);
                    version = resolveExpression(version, properties);
                    source = VersionSource.PROPERTY;
                } else {
                    source = VersionSource.LITERAL;
                }
            }
            result.add(new PomModel.PomDependency(
                    groupId,
                    artifactId,
                    version,
                    parseScope(optionalText(dep, "scope")),
                    Boolean.parseBoolean(optionalText(dep, "optional")),
                    source,
                    propertyName));
        }
        return result;
    }

    private List<PomModel.PomDependency> parseManagedDependencies(Element project, Map<String, String> properties) {
        Element dm = childElement(project, "dependencyManagement");
        if (dm == null) {
            return List.of();
        }
        Element deps = childElement(dm, "dependencies");
        if (deps == null) {
            return List.of();
        }
        List<PomModel.PomDependency> result = new ArrayList<>();
        NodeList items = deps.getElementsByTagName("dependency");
        for (int i = 0; i < items.getLength(); i++) {
            Element dep = (Element) items.item(i);
            String version = optionalText(dep, "version");
            String propertyName = null;
            VersionSource source = VersionSource.BOM_MANAGED;
            if (version != null && version.startsWith("${") && version.endsWith("}")) {
                propertyName = version.substring(2, version.length() - 1);
                version = resolveExpression(version, properties);
                source = VersionSource.PROPERTY;
            }
            result.add(new PomModel.PomDependency(
                    optionalText(dep, "groupId"),
                    optionalText(dep, "artifactId"),
                    version,
                    parseScope(optionalText(dep, "scope")),
                    false,
                    source,
                    propertyName));
        }
        return result;
    }

    private String resolveExpression(String value, Map<String, String> properties) {
        if (value == null || !value.startsWith("${") || !value.endsWith("}")) {
            return value;
        }
        String key = value.substring(2, value.length() - 1);
        String resolved = properties.get(key);
        if (resolved != null) {
            return resolved;
        }
        if ("project.version".equals(key)) {
            return properties.get("project.version");
        }
        if ("project.groupId".equals(key)) {
            return properties.get("project.groupId");
        }
        if ("project.artifactId".equals(key)) {
            return properties.get("project.artifactId");
        }
        if ("project.packaging".equals(key)) {
            return properties.get("project.packaging");
        }
        if ("project.parent.version".equals(key)) {
            return properties.get("project.parent.version");
        }
        if ("project.parent.groupId".equals(key)) {
            return properties.get("project.parent.groupId");
        }
        return null;
    }

    private DependencyScope parseScope(String scope) {
        if (scope == null || scope.isBlank()) {
            return DependencyScope.COMPILE;
        }
        return switch (scope.trim()) {
            case "compile" -> DependencyScope.COMPILE;
            case "runtime" -> DependencyScope.RUNTIME;
            case "provided" -> DependencyScope.PROVIDED;
            case "test" -> DependencyScope.TEST;
            default -> DependencyScope.UNKNOWN;
        };
    }

    private Element childElement(Element parent, String name) {
        NodeList nodes = parent.getElementsByTagName(name);
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node.getParentNode() == parent) {
                return (Element) node;
            }
        }
        return null;
    }

    private String firstText(Element parent, String tag) {
        String value = optionalText(parent, tag);
        if (value != null) {
            return value;
        }
        return null;
    }

    private String optionalText(Element parent, String tag) {
        NodeList nodes = parent.getElementsByTagName(tag);
        if (nodes.getLength() == 0) {
            return null;
        }
        Node node = nodes.item(0);
        if (node.getParentNode() != parent && !"dependency".equals(parent.getTagName()) && !"parent".equals(parent.getTagName())) {
            return null;
        }
        String text = node.getTextContent();
        return text == null ? null : text.trim();
    }

    private String key(String groupId, String artifactId) {
        return (groupId == null ? "" : groupId) + ":" + (artifactId == null ? "" : artifactId);
    }

    private String versionControlPoint(PomModel.PomDependency dep, PomModel model) {
        if (dep.versionSource() == VersionSource.PROPERTY && dep.propertyName() != null) {
            return model.path().getFileName() + "#" + dep.propertyName();
        }
        if (dep.versionSource() == VersionSource.BOM_MANAGED) {
            return model.path().getFileName() + "#dependencyManagement";
        }
        if (model.parentVersion() != null && model.version() != null && model.version().equals(dep.version())) {
            return model.path().getFileName() + "#parent";
        }
        return model.path().getFileName() + "#dependency";
    }

    private String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = Files.readAllBytes(path);
        byte[] hash = digest.digest(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private String git(Path repo, String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add("git");
        command.add("-C");
        command.add(repo.toString());
        command.addAll(Arrays.asList(args));
        LOGGER.fine(() -> "Running git command: " + String.join(" ", command));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        byte[] out = process.getInputStream().readAllBytes();
        int exit = process.waitFor();
        String text = new String(out, StandardCharsets.UTF_8).trim();
        if (exit != 0) {
            LOGGER.warning(() -> "Git command failed: " + String.join(" ", command) + " => " + text);
            throw new IllegalStateException("git command failed: " + String.join(" ", command) + " => " + text);
        }
        return text;
    }

    private record GitMetadata(String branch, String head, boolean clean) {
    }
}

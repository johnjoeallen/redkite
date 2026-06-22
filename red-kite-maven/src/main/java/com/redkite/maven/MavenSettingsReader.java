package com.redkite.maven;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Reads repository URLs and server credentials from ~/.m2/settings.xml so
 * that RedKite can fetch version metadata from the same repos Maven uses —
 * including corporate Artifactory mirrors with authentication.
 *
 * Resolution order:
 *   1. Mirrors whose <mirrorOf> includes "central" or "*"
 *   2. Repositories declared in active profiles
 *   3. https://repo1.maven.org/maven2 (fallback)
 *
 * Server credentials are matched by ID: if a <mirror id="X"> exists and a
 * <server id="X"> provides username/password, those credentials are included
 * in the returned RepoConfig for that URL.
 */
public class MavenSettingsReader {
    private static final Logger LOGGER = Logger.getLogger(MavenSettingsReader.class.getName());
    private static final String CENTRAL = "https://repo1.maven.org/maven2";

    public record RepoConfig(String url, String username, String password) {}
    private record MirrorEntry(String id, String url) {}

    private MavenSettingsReader() {}

    /**
     * Returns repository configs (URL + optional credentials) derived from
     * ~/.m2/settings.xml, falling back to anonymous Maven Central if the file
     * does not exist or cannot be parsed.
     */
    public static List<RepoConfig> discoverRepositoryConfigs(Path projectRoot) {
        Path settingsFile = resolveSettingsFile(projectRoot);
        if (settingsFile == null) {
            LOGGER.info("No settings.xml found; using Maven Central");
            return List.of(new RepoConfig(CENTRAL, null, null));
        }
        try {
            List<RepoConfig> configs = parseConfigs(settingsFile);
            if (configs.isEmpty()) {
                LOGGER.info(() -> settingsFile.toAbsolutePath() + " contained no usable entries; using Maven Central");
                return List.of(new RepoConfig(CENTRAL, null, null));
            }
            LOGGER.info(() -> "Discovered " + configs.size() + " repository config(s) from " + settingsFile.toAbsolutePath());
            return configs;
        } catch (Exception e) {
            LOGGER.warning(() -> "Failed to parse " + settingsFile.toAbsolutePath() + ": " + e.getMessage() + "; using Maven Central");
            return List.of(new RepoConfig(CENTRAL, null, null));
        }
    }

    /** Resolve settings without a known project root — home settings only. */
    public static List<RepoConfig> discoverRepositoryConfigs() {
        return discoverRepositoryConfigs(null);
    }

    /**
     * Settings precedence (first found wins, no merging):
     *   1. projectRoot/.m2/settings.xml
     *   2. -s path from projectRoot/.mvn/maven.config
     *   3. ~/.m2/settings.xml
     *
     * @param projectRoot the scanned project root; null skips project-local checks
     */
    public static Path resolveSettingsFile(Path projectRoot) {
        if (projectRoot != null) {
            Path projectLocal = projectRoot.resolve(".m2/settings.xml");
            if (Files.exists(projectLocal)) {
                LOGGER.info(() -> "Using project settings.xml: " + projectLocal.toAbsolutePath());
                return projectLocal;
            }
            Path mavenConfig = projectRoot.resolve(".mvn/maven.config");
            if (Files.exists(mavenConfig)) {
                Path fromConfig = settingsFromMavenConfig(mavenConfig, projectRoot);
                if (fromConfig != null) {
                    LOGGER.info(() -> "Using settings.xml from .mvn/maven.config: " + fromConfig.toAbsolutePath());
                    return fromConfig;
                }
            }
        }
        Path home = Path.of(System.getProperty("user.home"), ".m2", "settings.xml");
        if (Files.exists(home)) {
            LOGGER.info(() -> "Using home settings.xml: " + home.toAbsolutePath());
            return home;
        }
        return null;
    }

    /** Resolve settings without a known project root — home settings only. */
    public static Path resolveSettingsFile() {
        return resolveSettingsFile(null);
    }

    /**
     * Returns true if the settings file is project-local (under projectRoot).
     * When true, maven commands need an explicit -s flag because Maven does not
     * load project-local settings automatically.
     */
    public static boolean isProjectLocalSettings(Path settingsFile, Path projectRoot) {
        if (settingsFile == null || projectRoot == null) return false;
        return settingsFile.startsWith(projectRoot);
    }

    /** Parse .mvn/maven.config for -s / --settings flags. Returns resolved absolute path or null. */
    private static Path settingsFromMavenConfig(Path mavenConfig, Path projectRoot) {
        try {
            String content = Files.readString(mavenConfig);
            String[] tokens = content.split("\\s+");
            for (int i = 0; i < tokens.length - 1; i++) {
                String t = tokens[i].trim();
                if ("-s".equals(t) || "--settings".equals(t)) {
                    Path p = Path.of(tokens[i + 1].trim());
                    if (!p.isAbsolute()) p = projectRoot.resolve(p);
                    if (Files.exists(p)) return p.toAbsolutePath();
                }
            }
        } catch (Exception e) {
            LOGGER.warning(() -> "Could not read " + mavenConfig + ": " + e.getMessage());
        }
        return null;
    }

    /**
     * Returns a comma-separated list of repository base URLs derived from
     * settings.xml, or the Maven Central URL if no settings file is found.
     */
    public static String discoverRepositoryUrls() {
        Path settingsFile = resolveSettingsFile(null);
        if (settingsFile == null) {
            LOGGER.info("No settings.xml found; using Maven Central");
            return CENTRAL;
        }
        try {
            List<String> urls = parse(settingsFile);
            if (urls.isEmpty()) {
                LOGGER.info(() -> settingsFile.toAbsolutePath() + " contained no usable repository entries; using Maven Central");
                return CENTRAL;
            }
            String result = String.join(",", urls);
            LOGGER.info(() -> "Discovered Maven repository URLs from " + settingsFile.toAbsolutePath() + ": " + result);
            return result;
        } catch (Exception e) {
            LOGGER.warning(() -> "Failed to parse " + settingsFile.toAbsolutePath() + ": " + e.getMessage() + "; using Maven Central");
            return CENTRAL;
        }
    }

    static List<String> parse(Path settingsFile) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        Document doc;
        try (InputStream in = Files.newInputStream(settingsFile)) {
            doc = factory.newDocumentBuilder().parse(in);
        }
        Element root = doc.getDocumentElement();
        LinkedHashSet<String> urls = new LinkedHashSet<>();

        List<String> mirrorUrls = parseMirrors(root);
        urls.addAll(mirrorUrls);

        List<String> activeProfileIds = parseActiveProfiles(root);
        List<String> profileRepos = parseProfileRepositories(root, activeProfileIds);
        for (String url : profileRepos) {
            if (!urls.contains(url)) urls.add(url);
        }

        if (!isCentralMirrored(root)) {
            urls.add(CENTRAL);
        }

        return List.copyOf(urls);
    }

    static List<RepoConfig> parseConfigs(Path settingsFile) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        Document doc;
        try (InputStream in = Files.newInputStream(settingsFile)) {
            doc = factory.newDocumentBuilder().parse(in);
        }
        Element root = doc.getDocumentElement();
        List<RepoConfig> configs = new ArrayList<>();
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        Map<String, String[]> servers = parseServers(root);

        for (MirrorEntry mirror : parseMirrorEntries(root)) {
            if (!seen.add(mirror.url())) continue;
            String[] creds = servers.get(mirror.id());
            String username = creds != null ? creds[0] : null;
            String password = creds != null ? creds[1] : null;
            configs.add(new RepoConfig(mirror.url(), username, password));
            LOGGER.info(() -> "Found mirror '" + mirror.id() + "': " + mirror.url()
                    + (username != null && !username.isBlank() ? " (with credentials)" : ""));
        }

        // When mirrorOf=* (or external:*) is present every repository is routed through
        // the mirror. Adding profile repos directly would bypass the mirror and send
        // requests to the original upstream (the typical source of "wrong Artifactory" bugs).
        if (!isAllMirrored(root)) {
            List<String> activeProfileIds = parseActiveProfiles(root);
            for (String url : parseProfileRepositories(root, activeProfileIds)) {
                if (seen.add(url)) {
                    configs.add(new RepoConfig(url, null, null));
                }
            }
        }

        if (!isCentralMirrored(root)) {
            if (seen.add(CENTRAL)) {
                configs.add(new RepoConfig(CENTRAL, null, null));
            }
        }

        LOGGER.info(() -> "Effective Maven repositories: "
                + configs.stream().map(RepoConfig::url).collect(java.util.stream.Collectors.joining(", ")));
        return List.copyOf(configs);
    }

    private static List<MirrorEntry> parseMirrorEntries(Element root) {
        List<MirrorEntry> entries = new ArrayList<>();
        Element mirrorsEl = firstChild(root, "mirrors");
        if (mirrorsEl == null) return entries;
        NodeList mirrors = mirrorsEl.getElementsByTagName("mirror");
        for (int i = 0; i < mirrors.getLength(); i++) {
            if (!(mirrors.item(i) instanceof Element mirror)) continue;
            String mirrorOf = text(mirror, "mirrorOf");
            String url = text(mirror, "url");
            String id = text(mirror, "id");
            if (url == null || url.isBlank()) continue;
            if (mirrorOf != null && coversCentral(mirrorOf)) {
                String cleanUrl = url.trim().replaceAll("/$", "");
                entries.add(new MirrorEntry(id != null ? id.trim() : "", cleanUrl));
            }
        }
        return entries;
    }

    private static Map<String, String[]> parseServers(Element root) {
        Map<String, String[]> servers = new LinkedHashMap<>();
        Element serversEl = firstChild(root, "servers");
        if (serversEl == null) return servers;
        NodeList serverNodes = serversEl.getElementsByTagName("server");
        for (int i = 0; i < serverNodes.getLength(); i++) {
            if (!(serverNodes.item(i) instanceof Element server)) continue;
            String id = text(server, "id");
            String username = text(server, "username");
            String password = text(server, "password");
            if (id != null && !id.isBlank()) {
                servers.put(id.trim(), new String[]{username, password});
            }
        }
        return servers;
    }

    private static List<String> parseMirrors(Element root) {
        List<String> urls = new ArrayList<>();
        Element mirrorsEl = firstChild(root, "mirrors");
        if (mirrorsEl == null) return urls;
        NodeList mirrors = mirrorsEl.getElementsByTagName("mirror");
        for (int i = 0; i < mirrors.getLength(); i++) {
            if (!(mirrors.item(i) instanceof Element mirror)) continue;
            String mirrorOf = text(mirror, "mirrorOf");
            String url = text(mirror, "url");
            if (url == null || url.isBlank()) continue;
            if (mirrorOf != null && coversCentral(mirrorOf)) {
                urls.add(url.trim().replaceAll("/$", ""));
                LOGGER.info(() -> "Found mirror for '" + mirrorOf + "': " + url.trim());
            }
        }
        return urls;
    }

    private static boolean coversCentral(String mirrorOf) {
        for (String part : mirrorOf.split(",")) {
            String t = part.trim();
            if ("*".equals(t) || "central".equals(t) || "external:*".equals(t)) {
                return true;
            }
        }
        return false;
    }

    /** Returns true if any mirror's mirrorOf is * or external:*, meaning it covers every repo. */
    private static boolean isAllMirrored(Element root) {
        Element mirrorsEl = firstChild(root, "mirrors");
        if (mirrorsEl == null) return false;
        NodeList mirrors = mirrorsEl.getElementsByTagName("mirror");
        for (int i = 0; i < mirrors.getLength(); i++) {
            if (!(mirrors.item(i) instanceof Element mirror)) continue;
            String mirrorOf = text(mirror, "mirrorOf");
            if (mirrorOf == null) continue;
            for (String part : mirrorOf.split(",")) {
                String t = part.trim();
                if ("*".equals(t) || "external:*".equals(t)) return true;
            }
        }
        return false;
    }

    private static boolean isCentralMirrored(Element root) {
        Element mirrorsEl = firstChild(root, "mirrors");
        if (mirrorsEl == null) return false;
        NodeList mirrors = mirrorsEl.getElementsByTagName("mirror");
        for (int i = 0; i < mirrors.getLength(); i++) {
            if (!(mirrors.item(i) instanceof Element mirror)) continue;
            String mirrorOf = text(mirror, "mirrorOf");
            if (mirrorOf != null && coversCentral(mirrorOf)) return true;
        }
        return false;
    }

    private static List<String> parseActiveProfiles(Element root) {
        List<String> ids = new ArrayList<>();
        Element ap = firstChild(root, "activeProfiles");
        if (ap == null) return ids;
        NodeList nodes = ap.getElementsByTagName("activeProfile");
        for (int i = 0; i < nodes.getLength(); i++) {
            String id = nodes.item(i).getTextContent();
            if (id != null && !id.isBlank()) ids.add(id.trim());
        }
        return ids;
    }

    private static List<String> parseProfileRepositories(Element root, List<String> activeProfileIds) {
        List<String> urls = new ArrayList<>();
        Element profilesEl = firstChild(root, "profiles");
        if (profilesEl == null) return urls;
        NodeList profiles = profilesEl.getElementsByTagName("profile");
        for (int i = 0; i < profiles.getLength(); i++) {
            if (!(profiles.item(i) instanceof Element profile)) continue;
            String id = text(profile, "id");
            boolean explicitlyActive = id != null && activeProfileIds.contains(id);
            boolean activationDefault = isDefaultActive(profile);
            if (!explicitlyActive && !activationDefault) continue;
            Element reposEl = firstChild(profile, "repositories");
            if (reposEl == null) continue;
            NodeList repos = reposEl.getElementsByTagName("repository");
            for (int j = 0; j < repos.getLength(); j++) {
                if (!(repos.item(j) instanceof Element repo)) continue;
                String url = text(repo, "url");
                if (url != null && !url.isBlank()) {
                    String trimmed = url.trim().replaceAll("/$", "");
                    urls.add(trimmed);
                    LOGGER.info(() -> "Found repository in active profile '" + id + "': " + trimmed);
                }
            }
        }
        return urls;
    }

    private static boolean isDefaultActive(Element profile) {
        Element activation = firstChild(profile, "activation");
        if (activation == null) return false;
        String activeByDefault = text(activation, "activeByDefault");
        return "true".equalsIgnoreCase(activeByDefault);
    }

    private static Element firstChild(Element parent, String name) {
        NodeList nodes = parent.getElementsByTagName(name);
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            if (node.getParentNode() == parent) return (Element) node;
        }
        return null;
    }

    private static String text(Element parent, String tag) {
        NodeList nodes = parent.getElementsByTagName(tag);
        if (nodes.getLength() == 0) return null;
        String value = nodes.item(0).getTextContent();
        return value == null ? null : value.trim();
    }
}

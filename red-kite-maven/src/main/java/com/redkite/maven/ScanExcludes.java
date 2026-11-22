package com.redkite.maven;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Folders RedKite must not scan, configured as the plugin's {@code excludes} parameter. Each entry is a
 * directory relative to the project root (a leading {@code ./} or {@code /} and a trailing {@code /} are
 * optional). A POM in or below an excluded directory is skipped by the scan, the enforcer analysis and
 * the pin search, so test fixtures and sample projects do not appear in the report.
 */
public final class ScanExcludes {
    private static final ScanExcludes NONE = new ScanExcludes(List.of());

    private final List<String> prefixes;

    private ScanExcludes(List<String> prefixes) {
        this.prefixes = prefixes;
    }

    public static ScanExcludes none() {
        return NONE;
    }

    /**
     * The exclusions configured for the RedKite Maven plugin in {@code root/pom.xml}: every
     * {@code <excludes><exclude>} under a {@code red-kite-maven-plugin} {@code <plugin>} (build, pluginManagement
     * or a profile). This lets the server honour the same POM setting the plugin uses. A missing or
     * unparseable POM excludes nothing.
     */
    public static ScanExcludes fromPom(Path root) {
        Path pom = root.resolve("pom.xml");
        if (!java.nio.file.Files.isRegularFile(pom)) return NONE;
        try {
            javax.xml.parsers.DocumentBuilderFactory f = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            org.w3c.dom.Document doc = f.newDocumentBuilder().parse(pom.toFile());
            List<String> dirs = new ArrayList<>();
            org.w3c.dom.NodeList plugins = doc.getElementsByTagName("plugin");
            for (int i = 0; i < plugins.getLength(); i++) {
                org.w3c.dom.Element plugin = (org.w3c.dom.Element) plugins.item(i);
                if (!"red-kite-maven-plugin".equals(childText(plugin, "artifactId"))) continue;
                org.w3c.dom.NodeList excludes = plugin.getElementsByTagName("exclude");
                for (int j = 0; j < excludes.getLength(); j++) dirs.add(excludes.item(j).getTextContent());
            }
            return of(dirs);
        } catch (Exception e) {
            return NONE;
        }
    }

    private static String childText(org.w3c.dom.Element parent, String name) {
        for (org.w3c.dom.Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof org.w3c.dom.Element e && e.getTagName().equals(name)) return e.getTextContent().trim();
        }
        return null;
    }

    /** Normalises the configured directories; null, blank and {@code .} entries are ignored. */
    public static ScanExcludes of(java.util.Collection<String> dirs) {
        if (dirs == null) return NONE;
        List<String> out = new ArrayList<>();
        for (String raw : dirs) {
            if (raw == null) continue;
            String line = raw.strip().replace('\\', '/');
            while (line.startsWith("/")) line = line.substring(1);
            if (line.startsWith("./")) line = line.substring(2);
            while (line.endsWith("/")) line = line.substring(0, line.length() - 1);
            if (!line.isEmpty() && !line.equals(".")) out.add(line);
        }
        return out.isEmpty() ? NONE : new ScanExcludes(List.copyOf(out));
    }

    /** True when {@code path} (absolute or relative to {@code root}) is at or below an excluded directory. */
    public boolean excludes(Path root, Path path) {
        if (prefixes.isEmpty()) return false;
        Path abs = path.isAbsolute() ? path : root.resolve(path);
        String rel = root.toAbsolutePath().normalize().relativize(abs.toAbsolutePath().normalize())
                .toString().replace('\\', '/');
        for (String p : prefixes) {
            if (rel.equals(p) || rel.startsWith(p + "/")) return true;
        }
        return false;
    }

    public boolean isEmpty() {
        return prefixes.isEmpty();
    }

    public List<String> entries() {
        return prefixes;
    }
}

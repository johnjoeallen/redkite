package com.redkite.server;

import com.redkite.maven.MavenExecutable;
import com.redkite.metadata.HttpVersionMetadataProvider;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Everything a {@link RedKiteServerMain} needs to run a real analysis offline: a temp user home
 * whose {@code settings.xml} mirrors every repository to a file-based Maven repository (POMs and
 * their licenses), a local HTTP server standing in for Maven Central's {@code maven-metadata.xml},
 * the Central HEAD check and OSV, a fake {@code mvn} script replaying canned
 * {@code dependency:tree}, enforcer and build output, and a demo Maven project to analyse.
 */
final class ServerFixture implements AutoCloseable {

    // ---------------------------------------------------------------- the demo project

    static final String DEMO_POM = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project>
              <modelVersion>4.0.0</modelVersion>
              <parent>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-parent</artifactId>
                <version>3.0.0</version>
              </parent>
              <groupId>com.example</groupId>
              <artifactId>demo</artifactId>
              <version>1.0.0</version>
              <properties>
                <jackson.version>2.13.0</jackson.version>
                <stale-thing.version>9.9</stale-thing.version>
              </properties>
              <dependencyManagement>
                <dependencies>
                  <dependency><groupId>org.own</groupId><artifactId>managed</artifactId><version>1.0</version></dependency>
                </dependencies>
              </dependencyManagement>
              <dependencies>
                <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency>
                <dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.12.0</version></dependency>
                <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>1.7.36</version></dependency>
                <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.33</version></dependency>
                <dependency><groupId>org.bad</groupId><artifactId>downgrade</artifactId><version>2.1</version></dependency>
                <dependency><groupId>org.other</groupId><artifactId>uses-old-core</artifactId><version>1.0</version></dependency>
                <dependency><groupId>org.example</groupId><artifactId>snap</artifactId><version>1.0-SNAPSHOT</version></dependency>
                <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
              </dependencies>
              <build>
                <plugins>
                  <plugin><artifactId>maven-compiler-plugin</artifactId><version>3.10.1</version></plugin>
                </plugins>
              </build>
            </project>
            """;

    static final String DEMO_TREE = """
            [INFO] --- dependency:3.6.0:tree (default-cli) @ demo ---
            [INFO] com.example:demo:jar:1.0.0
            [INFO] +- com.fasterxml.jackson.core:jackson-databind:jar:2.13.0:compile
            [INFO] |  +- com.fasterxml.jackson.core:jackson-annotations:jar:2.13.0:compile
            [INFO] |  \\- com.fasterxml.jackson.core:jackson-core:jar:2.13.0:compile
            [INFO] +- org.apache.commons:commons-lang3:jar:3.12.0:compile
            [INFO] +- org.slf4j:slf4j-api:jar:1.7.36:compile
            [INFO] +- org.yaml:snakeyaml:jar:1.33:compile
            [INFO] +- org.bad:downgrade:jar:2.1:compile
            [INFO] +- org.other:uses-old-core:jar:1.0:compile
            [INFO] |  \\- org.other:transitive-vuln:jar:1.0:runtime
            [INFO] +- org.example:snap:jar:1.0-SNAPSHOT:compile
            [INFO] \\- junit:junit:jar:4.13.2:test
            [INFO]    \\- org.hamcrest:hamcrest-core:jar:1.3:test
            [INFO] BUILD SUCCESS
            """;

    static final String CONVERGENCE_FAILURE = """
            [INFO] --- enforcer:3.4.1:enforce (default-cli) @ demo ---
            [WARNING] Rule 0: org.apache.maven.plugins.enforcer.DependencyConvergence failed with message:
            Failed while enforcing releasability the error(s) are [
            Dependency convergence error for com.fasterxml.jackson.core:jackson-core:2.13.0 paths to dependency are:
            +-com.example:demo:1.0.0
              +-com.fasterxml.jackson.core:jackson-databind:2.13.0
                +-com.fasterxml.jackson.core:jackson-core:2.13.0
            +-com.example:demo:1.0.0
              +-org.other:uses-old-core:1.0
                +-com.fasterxml.jackson.core:jackson-core:2.12.0
            ]
            [INFO] BUILD FAILURE
            """;

    /** groupId:artifactId -> every published version, oldest first. */
    static final Map<String, List<String>> VERSIONS = new LinkedHashMap<>();
    /** groupId:artifactId:version -> license names (none = no licenses element). */
    static final Map<String, List<String>> LICENSES = new LinkedHashMap<>();

    static {
        VERSIONS.put("com.fasterxml.jackson.core:jackson-databind", List.of("2.12.7", "2.13.0", "2.13.3", "2.13.4", "2.14.0", "2.15.2"));
        VERSIONS.put("com.fasterxml.jackson.core:jackson-core", List.of("2.12.0", "2.13.0", "2.13.4", "2.15.2"));
        VERSIONS.put("com.fasterxml.jackson.core:jackson-annotations", List.of("2.13.0", "2.13.4", "2.15.2"));
        VERSIONS.put("org.apache.commons:commons-lang3", List.of("3.11", "3.12.0", "3.13.0", "3.14.0"));
        VERSIONS.put("org.slf4j:slf4j-api", List.of("1.7.30", "1.7.36", "2.0.9"));
        VERSIONS.put("org.yaml:snakeyaml", List.of("1.30", "1.33"));
        VERSIONS.put("org.bad:downgrade", List.of("1.9", "2.0", "2.1"));
        VERSIONS.put("org.other:uses-old-core", List.of("1.0"));
        VERSIONS.put("org.other:transitive-vuln", List.of("1.0", "1.1", "2.0"));
        VERSIONS.put("junit:junit", List.of("4.12", "4.13.2"));
        VERSIONS.put("org.hamcrest:hamcrest-core", List.of("1.3"));
        VERSIONS.put("org.springframework.boot:spring-boot-starter-parent", List.of("3.0.0", "3.1.5"));
        VERSIONS.put("org.apache.maven.plugins:maven-compiler-plugin", List.of("3.10.1", "3.11.0"));
        VERSIONS.put("org.own:managed", List.of("1.0", "1.1"));

        for (Map.Entry<String, List<String>> e : VERSIONS.entrySet()) {
            for (String v : e.getValue()) LICENSES.put(e.getKey() + ":" + v, List.of("Apache License, Version 2.0"));
        }
        LICENSES.put("org.yaml:snakeyaml:1.33", List.of("MIT License", "Apache License, Version 2.0"));
        LICENSES.put("junit:junit:4.13.2", List.of("Eclipse Public License 1.0"));
        LICENSES.put("org.bad:downgrade:2.1", List.of("GNU General Public License v3.0"));
        LICENSES.put("org.other:uses-old-core:1.0", List.of());
        LICENSES.put("org.example:snap:1.0-SNAPSHOT", List.of("Some Custom License"));
    }

    /** OSV advisories by package: {id, severity, introduced, fixed or null}. */
    static final Map<String, List<String[]>> ADVISORIES = Map.of(
            "com.fasterxml.jackson.core:jackson-databind", List.of(
                    new String[]{"GHSA-jd01", "HIGH", "2.13.0", "2.13.4"},
                    new String[]{"GHSA-jd02", "CRITICAL", "2.12.0", "2.13.3"}),
            "org.yaml:snakeyaml", List.<String[]>of(new String[]{"GHSA-sy01", "MODERATE", "0", null}),
            "org.bad:downgrade", List.<String[]>of(new String[]{"GHSA-bd01", "LOW", "2.1", null}),
            "org.other:transitive-vuln", List.<String[]>of(new String[]{"GHSA-tv01", "HIGH", "1.0", "1.1"}));

    // ---------------------------------------------------------------- state

    final Path root;
    final Path home;
    final Path fileRepo;
    final Path fakeMvnDir;
    final Path project;
    final Path prefsFile;
    final HttpServer http;
    final String httpBase;
    final List<String> osvQueries = Collections.synchronizedList(new ArrayList<>());
    /** groupId:artifactId whose maven-metadata.xml the fake repository answers 404 for. */
    final java.util.Set<String> hiddenMetadata = java.util.concurrent.ConcurrentHashMap.newKeySet();
    final RedKiteServerMain app;
    final String base;
    final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    private final Map<String, String> savedProperties = new LinkedHashMap<>();

    ServerFixture(Path root) throws Exception {
        this.root = root;
        this.home = Files.createDirectories(root.resolve("home"));
        this.fileRepo = Files.createDirectories(root.resolve("file-repo"));
        this.fakeMvnDir = Files.createDirectories(root.resolve("fake-mvn"));
        this.project = Files.createDirectories(root.resolve("demo"));
        this.prefsFile = root.resolve("prefs/preferences.properties");

        writeFileRepository();
        Files.createDirectories(home.resolve(".m2"));
        Files.writeString(home.resolve(".m2/settings.xml"), """
                <settings><mirrors><mirror><id>files</id><mirrorOf>*</mirrorOf><url>%s</url></mirror></mirrors></settings>
                """.formatted(fileRepo.toUri()));

        http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        http.createContext("/repo/", exchange -> {
            String path = exchange.getRequestURI().getPath().substring("/repo/".length());
            String body = metadataFor(path, hiddenMetadata);
            respond(exchange, body == null ? 404 : 200, body == null ? "" : body);
        });
        http.createContext("/central/", exchange -> respond(exchange, 404, ""));
        http.createContext("/v1/query", exchange -> {
            String request = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Matcher m = Pattern.compile("\"name\":\"([^\"]+)\"").matcher(request);
            String name = m.find() ? m.group(1) : "";
            osvQueries.add(name);
            respond(exchange, 200, osvResponse(name));
        });
        http.start();
        httpBase = "http://127.0.0.1:" + http.getAddress().getPort();

        writeFakeMaven();
        writeDemoProject();

        setProperty("user.home", home.toString());
        setProperty("redkite.maven.repositories", httpBase + "/repo");
        setProperty("redkite.osv.url", httpBase);
        setProperty(HttpVersionMetadataProvider.CENTRAL_URL_PROPERTY, httpBase + "/central");
        setProperty("redkite.prefs.file", prefsFile.toString());
        setProperty(MavenExecutable.PROPERTY, fakeMvnDir.resolve("mvn").toString());

        String jdbc = "jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1";
        app = new RedKiteServerMain(jdbc, "sa", "", 0);
        app.start();
        base = "http://127.0.0.1:" + app.port();
    }

    private void setProperty(String key, String value) {
        savedProperties.putIfAbsent(key, System.getProperty(key));
        System.setProperty(key, value);
    }

    @Override
    public void close() {
        app.stop();
        http.stop(0);
        for (Map.Entry<String, String> e : savedProperties.entrySet()) {
            if (e.getValue() == null) System.clearProperty(e.getKey());
            else System.setProperty(e.getKey(), e.getValue());
        }
    }

    // ---------------------------------------------------------------- fake repositories

    private void writeFileRepository() throws IOException {
        for (Map.Entry<String, List<String>> e : LICENSES.entrySet()) {
            String[] gav = e.getKey().split(":");
            StringBuilder licenses = new StringBuilder();
            if (!e.getValue().isEmpty()) {
                licenses.append("<licenses>");
                for (String name : e.getValue()) licenses.append("<license><name>").append(name).append("</name></license>");
                licenses.append("</licenses>");
            }
            Path pom = fileRepo.resolve(gav[0].replace('.', '/')).resolve(gav[1]).resolve(gav[2])
                    .resolve(gav[1] + "-" + gav[2] + ".pom");
            Files.createDirectories(pom.getParent());
            Files.writeString(pom, "<project><groupId>" + gav[0] + "</groupId><artifactId>" + gav[1]
                    + "</artifactId><version>" + gav[2] + "</version>" + licenses + "</project>");
        }
    }

    private static String metadataFor(String path, java.util.Set<String> hidden) {
        if (!path.endsWith("/maven-metadata.xml")) return null;
        String[] parts = path.substring(0, path.length() - "/maven-metadata.xml".length()).split("/");
        String artifact = parts[parts.length - 1];
        String group = String.join(".", java.util.Arrays.copyOf(parts, parts.length - 1));
        List<String> versions = VERSIONS.get(group + ":" + artifact);
        if (versions == null || hidden.contains(group + ":" + artifact)) return null;
        StringBuilder xml = new StringBuilder("<metadata><groupId>" + group + "</groupId><artifactId>" + artifact
                + "</artifactId><versioning><versions>");
        for (String v : versions) xml.append("<version>").append(v).append("</version>");
        xml.append("</versions></versioning></metadata>");
        return xml.toString();
    }

    private static String osvResponse(String packageName) {
        List<String[]> advisories = ADVISORIES.getOrDefault(packageName, List.of());
        StringBuilder json = new StringBuilder("{\"vulns\":[");
        for (int i = 0; i < advisories.size(); i++) {
            String[] a = advisories.get(i);
            if (i > 0) json.append(',');
            json.append("{\"id\":\"").append(a[0]).append("\",\"aliases\":[\"CVE-2099-").append(1000 + i)
                    .append("\"],\"database_specific\":{\"severity\":\"").append(a[1]).append("\"},\"affected\":[{\"package\":{\"name\":\"")
                    .append(packageName).append("\",\"ecosystem\":\"Maven\"},\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[{\"introduced\":\"")
                    .append(a[2]).append("\"}");
            if (a[3] != null) json.append(",{\"fixed\":\"").append(a[3]).append("\"}");
            json.append("]}]}]}");
        }
        return json.append("]}").toString();
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        boolean head = "HEAD".equals(exchange.getRequestMethod());
        exchange.sendResponseHeaders(status, bytes.length == 0 || head ? -1 : bytes.length);
        if (bytes.length > 0 && !head) exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    // ---------------------------------------------------------------- fake mvn

    private void writeFakeMaven() throws IOException {
        Path script = fakeMvnDir.resolve("mvn");
        Files.writeString(script, """
                #!/bin/sh
                D='%s'
                echo "$@" >> "$D/calls.log"
                G=""
                POM=""
                PREV=""
                for a in "$@"; do
                  case "$a" in
                    dependency:tree|enforcer:enforce|verify|install|test|spring-boot:run) G="$a";;
                  esac
                  if [ "$PREV" = "-f" ]; then POM="$a"; fi
                  PREV="$a"
                done
                G=$(echo "$G" | tr ':' '_')
                if [ -f "$D/$G.rules" ] && [ -f "$POM" ]; then
                  while IFS='|' read -r pat code out; do
                    if [ -n "$pat" ] && grep -q -- "$pat" "$POM"; then cat "$D/$out"; exit "$code"; fi
                  done < "$D/$G.rules"
                fi
                if [ -f "$D/$G.out" ]; then cat "$D/$G.out"; fi
                if [ -f "$D/$G.sleep" ]; then sleep "$(cat "$D/$G.sleep")"; fi
                if [ -f "$D/$G.exit" ]; then exit "$(cat "$D/$G.exit")"; fi
                exit 0
                """.formatted(fakeMvnDir.toAbsolutePath()));
        Files.setPosixFilePermissions(script, PosixFilePermissions.fromString("rwxr-xr-x"));
        mvnOutput("dependency:tree", DEMO_TREE, 0);
        mvnOutput("enforcer:enforce", CONVERGENCE_FAILURE, 1);
        // Phase 2 runs the enforcer again with RedKite's computed pins: that resolves the conflict.
        mvnRule("enforcer:enforce", "redkite-phase2", 0, "[INFO] Rule 0: DependencyConvergence passed\n[INFO] BUILD SUCCESS\n");
        mvnOutput("install", "[INFO] BUILD SUCCESS\n", 0);
    }

    /** Default output and exit code of {@code goal}. */
    void mvnOutput(String goal, String output, int exit) throws IOException {
        String g = goal.replace(':', '_');
        Files.writeString(fakeMvnDir.resolve(g + ".out"), output);
        Files.writeString(fakeMvnDir.resolve(g + ".exit"), String.valueOf(exit));
    }

    /** When the POM passed with -f contains {@code pattern}, {@code goal} prints {@code output} and
     *  exits {@code exit} instead of its default. Rules are checked in the order added. */
    void mvnRule(String goal, String pattern, int exit, String output) throws IOException {
        String g = goal.replace(':', '_');
        String outName = g + "-rule-" + UUID.randomUUID() + ".out";
        Files.writeString(fakeMvnDir.resolve(outName), output);
        Files.writeString(fakeMvnDir.resolve(g + ".rules"), pattern + "|" + exit + "|" + outName + "\n",
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
    }

    void mvnSleep(String goal, double seconds) throws IOException {
        Files.writeString(fakeMvnDir.resolve(goal.replace(':', '_') + ".sleep"), String.valueOf(seconds));
    }

    void clearMvnRules(String goal) throws IOException {
        Files.deleteIfExists(fakeMvnDir.resolve(goal.replace(':', '_') + ".rules"));
    }

    List<String> mvnCalls() throws IOException {
        Path log = fakeMvnDir.resolve("calls.log");
        return Files.exists(log) ? Files.readAllLines(log) : List.of();
    }

    // ---------------------------------------------------------------- the project on disk

    void writeDemoProject() throws IOException {
        Files.writeString(project.resolve("pom.xml"), DEMO_POM);
    }

    String projectPom() throws IOException {
        return Files.readString(project.resolve("pom.xml"));
    }

    // ---------------------------------------------------------------- HTTP helpers

    record Response(int status, String body, java.net.http.HttpHeaders headers) {}

    Response get(String path) throws Exception {
        HttpResponse<String> r = client.send(HttpRequest.newBuilder(URI.create(base + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return new Response(r.statusCode(), r.body(), r.headers());
    }

    HttpResponse<byte[]> getBytes(String path) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(base + path)).GET().build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    Response send(String method, String path, String body) throws Exception {
        HttpRequest.BodyPublisher publisher = body == null ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body);
        HttpResponse<String> r = client.send(HttpRequest.newBuilder(URI.create(base + path)).method(method, publisher).build(),
                HttpResponse.BodyHandlers.ofString());
        return new Response(r.statusCode(), r.body(), r.headers());
    }

    Response post(String path, String body) throws Exception {
        return send("POST", path, body);
    }

    static String json(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }

    /** The (unescaped) value of string field {@code name} in a flat JSON object, or null. */
    static String field(String json, String name) {
        String key = "\"" + name + "\":\"";
        int start = json.indexOf(key);
        if (start < 0) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = start + key.length(); i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') return sb.toString();
            if (c == '\\') {
                char n = json.charAt(++i);
                switch (n) {
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> { sb.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16)); i += 4; }
                    default -> sb.append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return null;
    }

    /** Starts an analysis of {@code path} and waits for it to finish; returns the final status JSON. */
    String analyse(Path path) throws Exception {
        Response started = post("/api/scan", "{\"path\":" + json(path.toString()) + "}");
        if (started.status() != 200) throw new AssertionError(started.status() + " " + started.body());
        String jobId = field(started.body(), "jobId");
        long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        while (System.nanoTime() < deadline) {
            Response status = get("/api/scan-status?jobId=" + jobId);
            if (!status.body().contains("\"status\":\"running\"")) return status.body();
            Thread.sleep(50);
        }
        throw new AssertionError("analysis did not finish");
    }

    /** Runs an analysis of the demo project and returns its scan id. */
    String analyseDemo() throws Exception {
        String status = analyse(project);
        String scanId = field(status, "scanId");
        if (scanId == null) throw new AssertionError(status);
        return scanId;
    }

    /** Polls an apply job to completion; returns the final status JSON. */
    String awaitApply(String jobId) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        while (System.nanoTime() < deadline) {
            Response status = get("/api/scans/remediation/apply-status?jobId=" + jobId);
            if (!status.body().contains("\"status\":\"running\"")) return status.body();
            Thread.sleep(50);
        }
        throw new AssertionError("apply did not finish");
    }
}

package com.redkite.maven;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Real {@link PomSource}: the local Maven repository cache first (a plain file read, no network
 * and no {@code mvn} process — and very likely already populated, since anything RedKite scanned
 * with {@code dependency:tree} was necessarily downloaded there), then each configured repository
 * in order, the same way {@link com.redkite.metadata.HttpVersionMetadataProvider} already
 * resolves {@code maven-metadata.xml} — a {@code file:} base is read directly, anything else is
 * fetched over HTTP with an anonymous-then-credentialed retry on 401.
 */
public class PomFetcher implements PomSource {
    private static final Logger LOGGER = Logger.getLogger(PomFetcher.class.getName());
    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    private final Path localRepository;
    private final List<MavenSettingsReader.RepoConfig> repoConfigs;

    public PomFetcher(Path projectRoot) {
        this(defaultLocalRepository(), MavenSettingsReader.discoverRepositoryConfigs(projectRoot));
    }

    /** Visible for testing — lets a test point {@code localRepository} at a temp directory instead
     *  of the real {@code ~/.m2/repository}. */
    PomFetcher(Path localRepository, List<MavenSettingsReader.RepoConfig> repoConfigs) {
        this.localRepository = localRepository;
        this.repoConfigs = repoConfigs;
    }

    private static Path defaultLocalRepository() {
        return Path.of(System.getProperty("user.home", "."), ".m2", "repository");
    }

    @Override
    public Optional<String> fetchPom(String groupId, String artifactId, String version) {
        if (groupId == null || artifactId == null || version == null) return Optional.empty();
        String relativePath = relativePomPath(groupId, artifactId, version);

        Path local = localRepository.resolve(relativePath);
        if (Files.isRegularFile(local)) {
            try {
                LOGGER.fine(() -> "Local Maven repo cache hit for " + groupId + ":" + artifactId + ":" + version);
                return Optional.of(Files.readString(local, StandardCharsets.UTF_8));
            } catch (IOException e) {
                LOGGER.warning(() -> "Failed to read cached POM at " + local + ": " + e.getMessage());
            }
        }

        for (MavenSettingsReader.RepoConfig repo : repoConfigs) {
            Optional<String> result = fetchFromRepo(repo, relativePath, groupId, artifactId, version);
            if (result.isPresent()) return result;
        }
        return Optional.empty();
    }

    private Optional<String> fetchFromRepo(MavenSettingsReader.RepoConfig repo, String relativePath,
                                            String groupId, String artifactId, String version) {
        String base = repo.url().endsWith("/") ? repo.url().substring(0, repo.url().length() - 1) : repo.url();
        if (base.startsWith("file:")) {
            try {
                Path path = Path.of(URI.create(base)).resolve(relativePath);
                if (Files.isRegularFile(path)) {
                    return Optional.of(Files.readString(path, StandardCharsets.UTF_8));
                }
            } catch (Exception e) {
                LOGGER.fine(() -> "Failed to read POM from file repo " + base + ": " + e.getMessage());
            }
            return Optional.empty();
        }

        String url = base + "/" + relativePath;
        try {
            HttpResponse<String> response = send(url, null);
            if (response.statusCode() == 401 && repo.username() != null && !repo.username().isBlank()) {
                response = send(url, repo);
            }
            if (response.statusCode() == 200) {
                return Optional.of(response.body());
            }
            int status = response.statusCode();
            LOGGER.fine(() -> "POM fetch " + url + " => HTTP " + status);
        } catch (Exception e) {
            LOGGER.fine(() -> "POM fetch failed for " + groupId + ":" + artifactId + ":" + version + " at " + url + ": " + e.getMessage());
        }
        return Optional.empty();
    }

    private HttpResponse<String> send(String url, MavenSettingsReader.RepoConfig credentials) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .GET().header("Accept", "application/xml,text/xml,*/*")
                .timeout(Duration.ofSeconds(20));
        if (credentials != null) {
            String encoded = java.util.Base64.getEncoder().encodeToString(
                    (credentials.username() + ":" + (credentials.password() != null ? credentials.password() : ""))
                            .getBytes(StandardCharsets.UTF_8));
            builder.header("Authorization", "Basic " + encoded);
        }
        return CLIENT.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static String relativePomPath(String groupId, String artifactId, String version) {
        return groupId.replace('.', '/') + "/" + artifactId + "/" + version + "/" + artifactId + "-" + version + ".pom";
    }
}

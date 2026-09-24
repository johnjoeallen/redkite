package com.redkite.maven;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PomFetcherHttpTest {
    private static final String POM_PATH = "/repo/org/example/lib/1.0/lib-1.0.pom";

    @TempDir
    Path tempDir;

    private HttpServer server;
    private String base;
    private final List<String> authHeaders = new ArrayList<>();

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/repo/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            authHeaders.add(auth == null ? "-" : auth);
            int status;
            byte[] body = new byte[0];
            if (!path.equals(POM_PATH)) {
                status = 404;
            } else if (auth == null) {
                status = 401;
            } else if (auth.equals("Basic " + Base64.getEncoder().encodeToString("u:p".getBytes(StandardCharsets.UTF_8)))) {
                status = 200;
                body = "<project>remote</project>".getBytes(StandardCharsets.UTF_8);
            } else {
                status = 403;
            }
            exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
            if (body.length > 0) exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/open/", exchange -> {
            byte[] body = "<project>open</project>".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/broken/", exchange -> {
            exchange.sendResponseHeaders(500, -1);
            exchange.close();
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private PomFetcher fetcher(MavenSettingsReader.RepoConfig... repos) {
        return new PomFetcher(tempDir.resolve("empty-local"), List.of(repos));
    }

    @Test
    void retriesWithCredentialsAfter401() {
        PomFetchResult result = fetcher(new MavenSettingsReader.RepoConfig(base + "/repo/", "u", "p"))
                .fetchPom("org.example", "lib", "1.0");
        assertEquals(new PomFetchResult.Found("<project>remote</project>"), result);
        assertEquals(2, authHeaders.size());
        assertEquals("-", authHeaders.get(0), "first attempt is anonymous");
    }

    @Test
    void unauthorizedWithoutCredentialsIsAFetchError() {
        PomFetchResult result = fetcher(new MavenSettingsReader.RepoConfig(base + "/repo", null, null))
                .fetchPom("org.example", "lib", "1.0");
        assertEquals(new PomFetchResult.FetchError(base + "/repo", "HTTP 401"), result);
        assertEquals(1, authHeaders.size());
    }

    @Test
    void blankUsernameDoesNotRetry() {
        PomFetchResult result = fetcher(new MavenSettingsReader.RepoConfig(base + "/repo", " ", null))
                .fetchPom("org.example", "lib", "1.0");
        assertInstanceOf(PomFetchResult.FetchError.class, result);
        assertEquals(1, authHeaders.size());
    }

    @Test
    void wrongCredentialsAreAFetchError() {
        PomFetchResult result = fetcher(new MavenSettingsReader.RepoConfig(base + "/repo", "u", null))
                .fetchPom("org.example", "lib", "1.0");
        assertEquals(new PomFetchResult.FetchError(base + "/repo", "HTTP 403"), result);
    }

    @Test
    void notFoundOutranksAnotherRepositorysError() {
        PomFetchResult result = fetcher(
                new MavenSettingsReader.RepoConfig(base + "/broken", null, null),
                new MavenSettingsReader.RepoConfig(base + "/repo", null, null))
                .fetchPom("org.example", "other", "1.0");
        assertInstanceOf(PomFetchResult.NotFound.class, result);
    }

    @Test
    void laterRepositoryCanStillFindIt() {
        PomFetchResult result = fetcher(
                new MavenSettingsReader.RepoConfig(base + "/broken", null, null),
                new MavenSettingsReader.RepoConfig(base + "/open", null, null))
                .fetchPom("org.example", "lib", "1.0");
        assertEquals(new PomFetchResult.Found("<project>open</project>"), result);
    }

    @Test
    void serverErrorOnlyIsReturnedAsTheError() {
        PomFetchResult result = fetcher(new MavenSettingsReader.RepoConfig(base + "/broken", null, null))
                .fetchPom("org.example", "lib", "1.0");
        assertEquals(new PomFetchResult.FetchError(base + "/broken", "HTTP 500"), result);
    }

    @Test
    void unreachableRepositoryIsAFetchError() {
        server.stop(0);
        PomFetchResult result = fetcher(new MavenSettingsReader.RepoConfig(base + "/repo", null, null))
                .fetchPom("org.example", "lib", "1.0");
        assertInstanceOf(PomFetchResult.FetchError.class, result);
        assertEquals(base + "/repo", ((PomFetchResult.FetchError) result).repositoryUrl());
    }

    @Test
    void nullCoordinatesAreNotFound() {
        PomFetcher fetcher = fetcher(new MavenSettingsReader.RepoConfig(base + "/open", null, null));
        assertInstanceOf(PomFetchResult.NotFound.class, fetcher.fetchPom(null, "a", "1"));
        assertInstanceOf(PomFetchResult.NotFound.class, fetcher.fetchPom("g", null, "1"));
        assertInstanceOf(PomFetchResult.NotFound.class, fetcher.fetchPom("g", "a", null));
    }

    @Test
    void malformedFileRepositoryIsAFetchError() {
        PomFetchResult result = fetcher(new MavenSettingsReader.RepoConfig("file:bad path with spaces", null, null))
                .fetchPom("org.example", "lib", "1.0");
        assertInstanceOf(PomFetchResult.FetchError.class, result);
    }

    @Test
    void projectRootConstructorUsesSettings() {
        PomFetcher fetcher = new PomFetcher(tempDir);
        assertNotNull(fetcher);
    }
}

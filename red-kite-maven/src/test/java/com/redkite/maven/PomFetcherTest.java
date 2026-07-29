package com.redkite.maven;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PomFetcherTest {

    @TempDir
    Path tempDir;

    @Test
    void readsFromLocalRepositoryCacheWithoutConsultingAnyRepoConfig() throws Exception {
        Path localRepo = tempDir.resolve("local-repo");
        Path pomPath = localRepo.resolve("org/example/lib/1.2.3/lib-1.2.3.pom");
        Files.createDirectories(pomPath.getParent());
        Files.writeString(pomPath, "<project><groupId>org.example</groupId></project>");

        // No repo configs at all — a cache hit must never need to reach out anywhere.
        PomFetcher fetcher = new PomFetcher(localRepo, List.of());

        PomFetchResult result = fetcher.fetchPom("org.example", "lib", "1.2.3");
        assertInstanceOf(PomFetchResult.Found.class, result);
        assertTrue(((PomFetchResult.Found) result).xml().contains("<groupId>org.example</groupId>"));
    }

    @Test
    void fallsBackToAFileRepoConfigWhenNotInLocalCache() throws Exception {
        Path emptyLocalRepo = tempDir.resolve("empty-local-repo");
        Files.createDirectories(emptyLocalRepo);

        Path remoteRepo = tempDir.resolve("remote-repo");
        Path pomPath = remoteRepo.resolve("org/example/lib/1.2.3/lib-1.2.3.pom");
        Files.createDirectories(pomPath.getParent());
        Files.writeString(pomPath, "<project><groupId>org.example</groupId></project>");

        PomFetcher fetcher = new PomFetcher(emptyLocalRepo,
                List.of(new MavenSettingsReader.RepoConfig(remoteRepo.toUri().toString(), null, null)));

        PomFetchResult result = fetcher.fetchPom("org.example", "lib", "1.2.3");
        assertInstanceOf(PomFetchResult.Found.class, result);
        assertTrue(((PomFetchResult.Found) result).xml().contains("<groupId>org.example</groupId>"));
    }

    @Test
    void returnsNotFoundWhenNotFoundAnywhere() {
        PomFetcher fetcher = new PomFetcher(tempDir.resolve("nowhere"), List.of());
        assertInstanceOf(PomFetchResult.NotFound.class, fetcher.fetchPom("org.example", "lib", "1.2.3"));
    }

    @Test
    void missingFileRepoIsReportedAsNotFoundNotAnError() throws Exception {
        Path emptyLocalRepo = tempDir.resolve("empty-local-repo");
        Files.createDirectories(emptyLocalRepo);
        Path remoteRepo = tempDir.resolve("remote-repo");
        Files.createDirectories(remoteRepo);

        PomFetcher fetcher = new PomFetcher(emptyLocalRepo,
                List.of(new MavenSettingsReader.RepoConfig(remoteRepo.toUri().toString(), null, null)));

        assertInstanceOf(PomFetchResult.NotFound.class, fetcher.fetchPom("org.example", "lib", "1.2.3"));
    }

    @Test
    void unreachableRepoIsReportedAsATransportErrorNotNotFound() throws Exception {
        Path emptyLocalRepo = tempDir.resolve("empty-local-repo");
        Files.createDirectories(emptyLocalRepo);

        // A malformed repo URL that isn't a "file:" base falls into the HTTP send path and throws
        // during the request itself — a stand-in for a real network transport failure without
        // depending on an actual unreachable host in a test.
        PomFetcher fetcher = new PomFetcher(emptyLocalRepo,
                List.of(new MavenSettingsReader.RepoConfig("not-a-valid-uri-scheme:###", null, null)));

        PomFetchResult result = fetcher.fetchPom("org.example", "lib", "1.2.3");
        assertInstanceOf(PomFetchResult.FetchError.class, result);
    }

    @Test
    void notFoundFromOneRepoWinsOverTransportErrorFromAnother() throws Exception {
        Path emptyLocalRepo = tempDir.resolve("empty-local-repo");
        Files.createDirectories(emptyLocalRepo);

        Path validButEmptyRepo = tempDir.resolve("valid-empty-repo");
        Files.createDirectories(validButEmptyRepo);

        // repo[0] errors (malformed base -> exception branch), repo[1] cleanly reports absent
        // (valid directory, file just doesn't exist there) — a confirmed absence from ANY repo
        // must win over an inconclusive error from another, regardless of query order.
        PomFetcher fetcher = new PomFetcher(emptyLocalRepo, List.of(
                new MavenSettingsReader.RepoConfig("not-a-valid-uri-scheme:###", null, null),
                new MavenSettingsReader.RepoConfig(validButEmptyRepo.toUri().toString(), null, null)));

        PomFetchResult result = fetcher.fetchPom("org.example", "lib", "1.2.3");
        assertInstanceOf(PomFetchResult.NotFound.class, result,
                "A confirmed absence from one repo must outrank a transport error from another");
    }
}

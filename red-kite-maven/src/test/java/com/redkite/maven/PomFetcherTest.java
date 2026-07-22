package com.redkite.maven;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

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

        Optional<String> result = fetcher.fetchPom("org.example", "lib", "1.2.3");
        assertTrue(result.isPresent());
        assertTrue(result.get().contains("<groupId>org.example</groupId>"));
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

        Optional<String> result = fetcher.fetchPom("org.example", "lib", "1.2.3");
        assertTrue(result.isPresent());
        assertTrue(result.get().contains("<groupId>org.example</groupId>"));
    }

    @Test
    void returnsEmptyWhenNotFoundAnywhere() {
        PomFetcher fetcher = new PomFetcher(tempDir.resolve("nowhere"), List.of());
        assertTrue(fetcher.fetchPom("org.example", "lib", "1.2.3").isEmpty());
    }
}

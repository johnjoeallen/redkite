package com.redkite.maven;

import java.util.LinkedHashMap;
import java.util.Map;

/** In-memory {@link PomSource} shared by resolver tests — no filesystem or network, so the
 *  resolution/walk logic itself is what's under test, not {@link PomFetcher}'s real fetching. */
class FakePomSource implements PomSource {
    private final Map<String, String> poms = new LinkedHashMap<>();
    private final Map<String, PomFetchResult.FetchError> errors = new LinkedHashMap<>();

    FakePomSource with(String groupId, String artifactId, String version, String xml) {
        poms.put(key(groupId, artifactId, version), xml);
        return this;
    }

    /** Registers a coordinate that fails with a transport/other error rather than resolving to
     *  either found or confirmed-absent content. */
    FakePomSource withError(String groupId, String artifactId, String version, String repositoryUrl, String message) {
        errors.put(key(groupId, artifactId, version), new PomFetchResult.FetchError(repositoryUrl, message));
        return this;
    }

    @Override
    public PomFetchResult fetchPom(String groupId, String artifactId, String version) {
        String k = key(groupId, artifactId, version);
        String xml = poms.get(k);
        if (xml != null) return new PomFetchResult.Found(xml);
        PomFetchResult.FetchError error = errors.get(k);
        if (error != null) return error;
        return new PomFetchResult.NotFound();
    }

    private static String key(String groupId, String artifactId, String version) {
        return groupId + ":" + artifactId + ":" + version;
    }
}

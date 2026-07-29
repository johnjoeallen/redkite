package com.redkite.maven;

/**
 * Supplies the raw POM XML for a given Maven coordinate — the seam between
 * {@link ManagedVersionResolver} (the recursive parent/BOM-import walking logic) and however that
 * content is actually obtained ({@link PomFetcher} in production; an in-memory fake in tests).
 * Kept minimal and network-free at the interface level so the resolution algorithm itself can be
 * tested without any real filesystem or HTTP access.
 */
public interface PomSource {
    /** Returns the outcome of trying to fetch {@code groupId:artifactId:version} — see
     *  {@link PomFetchResult}. Never throws: a gap in provenance data (private/unreachable repos,
     *  network issues) is expected and must not abort the rest of the resolution, but callers that
     *  need to know WHY a coordinate resolved to nothing (confirmed absent vs. an inconclusive
     *  error) can inspect the returned variant instead of losing that distinction. */
    PomFetchResult fetchPom(String groupId, String artifactId, String version);
}

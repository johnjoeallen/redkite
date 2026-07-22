package com.redkite.maven;

import java.util.Optional;

/**
 * Supplies the raw POM XML for a given Maven coordinate — the seam between
 * {@link ManagedVersionResolver} (the recursive parent/BOM-import walking logic) and however that
 * content is actually obtained ({@link PomFetcher} in production; an in-memory fake in tests).
 * Kept minimal and network-free at the interface level so the resolution algorithm itself can be
 * tested without any real filesystem or HTTP access.
 */
public interface PomSource {
    /** Returns the raw POM XML for {@code groupId:artifactId:version}, or empty if it couldn't be
     *  found anywhere this source knows to look. Never throws for a not-found artifact — a gap in
     *  provenance data is expected (private/unreachable repos, network issues) and must not abort
     *  the rest of the resolution. */
    Optional<String> fetchPom(String groupId, String artifactId, String version);
}

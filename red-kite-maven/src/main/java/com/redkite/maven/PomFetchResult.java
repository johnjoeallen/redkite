package com.redkite.maven;

/** The outcome of trying to fetch one POM. Distinguishes a confirmed absence (a repository
 *  affirmatively reported the coordinate doesn't exist, e.g. HTTP 404) from a transport/other
 *  error (a repository couldn't be reached, or answered with something other than 200/404) — the
 *  two must never be conflated: a flaky optional/snapshot repo erroring must not be read as "this
 *  artifact doesn't exist," and a genuinely absent artifact must not be excused as "just a network
 *  blip." See {@link PomFetcher} for how per-repo results aggregate into one of these. */
public sealed interface PomFetchResult {
    record Found(String xml) implements PomFetchResult {}

    record NotFound() implements PomFetchResult {}

    record FetchError(String repositoryUrl, String message) implements PomFetchResult {}
}

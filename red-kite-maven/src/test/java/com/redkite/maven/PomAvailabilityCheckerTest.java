package com.redkite.maven;

import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class PomAvailabilityCheckerTest {

    private static class CountingPomSource implements PomSource {
        final AtomicInteger calls = new AtomicInteger();
        private final PomFetchResult result;

        CountingPomSource(PomFetchResult result) {
            this.result = result;
        }

        @Override
        public PomFetchResult fetchPom(String groupId, String artifactId, String version) {
            calls.incrementAndGet();
            return result;
        }
    }

    @Test
    void foundIsReportedAsAvailable() {
        CountingPomSource source = new CountingPomSource(new PomFetchResult.Found("<project/>"));
        PomAvailabilityChecker checker = new PomAvailabilityChecker();

        PomAvailabilityChecker.CheckResult result = checker.check(source, "org.example", "lib", "1.0.0");

        assertEquals(PomAvailabilityChecker.Availability.AVAILABLE, result.status());
    }

    @Test
    void confirmedAbsentIsNotAvailable() {
        CountingPomSource source = new CountingPomSource(new PomFetchResult.NotFound());
        PomAvailabilityChecker checker = new PomAvailabilityChecker();

        PomAvailabilityChecker.CheckResult result = checker.check(source, "org.example", "lib", "999.0.0");

        assertEquals(PomAvailabilityChecker.Availability.CONFIRMED_ABSENT, result.status());
        assertTrue(result.detail().contains("org.example:lib:999.0.0"), result.detail());
    }

    @Test
    void transportErrorIsDistinguishedFromConfirmedAbsent() {
        CountingPomSource source = new CountingPomSource(new PomFetchResult.FetchError("https://repo.example", "timed out"));
        PomAvailabilityChecker checker = new PomAvailabilityChecker();

        PomAvailabilityChecker.CheckResult result = checker.check(source, "org.example", "lib", "1.0.0");

        assertEquals(PomAvailabilityChecker.Availability.UNKNOWN_ERROR, result.status());
        assertTrue(result.detail().contains("https://repo.example"), result.detail());
        assertTrue(result.detail().contains("timed out"), result.detail());
    }

    // --- Scenario 9: negative (and error) resolution results are cached ---

    @Test
    void negativeResultIsCachedRatherThanRequeriedEveryTime() {
        CountingPomSource source = new CountingPomSource(new PomFetchResult.NotFound());
        PomAvailabilityChecker checker = new PomAvailabilityChecker();

        checker.check(source, "org.example", "lib", "1.0.0");
        checker.check(source, "org.example", "lib", "1.0.0");
        checker.check(source, "org.example", "lib", "1.0.0");

        assertEquals(1, source.calls.get(), "Repeated checks for the same absent coordinate must hit the cache, not the source");
    }

    @Test
    void errorResultIsCachedRatherThanRequeriedEveryTime() {
        CountingPomSource source = new CountingPomSource(new PomFetchResult.FetchError("https://repo.example", "connection refused"));
        PomAvailabilityChecker checker = new PomAvailabilityChecker();

        checker.check(source, "org.example", "lib", "1.0.0");
        checker.check(source, "org.example", "lib", "1.0.0");

        assertEquals(1, source.calls.get());
    }

    @Test
    void positiveResultIsAlsoCached() {
        CountingPomSource source = new CountingPomSource(new PomFetchResult.Found("<project/>"));
        PomAvailabilityChecker checker = new PomAvailabilityChecker();

        checker.check(source, "org.example", "lib", "1.0.0");
        checker.check(source, "org.example", "lib", "1.0.0");

        assertEquals(1, source.calls.get());
    }

    @Test
    void differentCoordinatesAreCachedIndependently() {
        CountingPomSource source = new CountingPomSource(new PomFetchResult.NotFound());
        PomAvailabilityChecker checker = new PomAvailabilityChecker();

        checker.check(source, "org.example", "lib-a", "1.0.0");
        checker.check(source, "org.example", "lib-b", "1.0.0");

        assertEquals(2, source.calls.get(), "Distinct coordinates must not share a cache entry");
    }
}

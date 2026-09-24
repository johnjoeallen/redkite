package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.metadata.HttpVersionMetadataProvider;
import com.redkite.metadata.HttpVulnerabilityProvider;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/** The cache TTLs editable on the /config page, with their defaults and preset choices. */
final class CacheTtlSettings {
    private CacheTtlSettings() {
    }

    record ConfigTtlEntry(String key, String label, Duration defaultValue) {}

    /** Config key + compiled-in default for the license cache — a resolved license for a fixed
     *  {@code groupId:artifactId:version} is effectively immutable, so this defaults far longer
     *  than the version/vulnerability TTLs above, which track things that genuinely change over
     *  time. */
    static final String CONFIG_KEY_LICENSE_FRESH_TTL = "cache.ttl.license.fresh";
    static final Duration DEFAULT_LICENSE_FRESH_TTL = Duration.ofDays(30);

    /** The cache TTLs editable from the /config page — single source of truth shared by the
     *  first-run seeding logic and the config page's rendering, so the two never drift apart. */
    static final List<ConfigTtlEntry> CONFIG_TTL_ENTRIES = List.of(
            new ConfigTtlEntry(HttpVulnerabilityProvider.CONFIG_KEY_FRESH_TTL,
                    "Vulnerability lookup cache (OSV.dev)", HttpVulnerabilityProvider.DEFAULT_FRESH_TTL),
            new ConfigTtlEntry(HttpVersionMetadataProvider.CONFIG_KEY_FRESH_TTL,
                    "Version metadata cache (Maven Central)", HttpVersionMetadataProvider.DEFAULT_FRESH_TTL),
            new ConfigTtlEntry(HttpVersionMetadataProvider.CONFIG_KEY_LOCAL_TTL,
                    "Version metadata cache (internal/local repositories)", HttpVersionMetadataProvider.DEFAULT_LOCAL_TTL),
            new ConfigTtlEntry(HttpVersionMetadataProvider.CONFIG_KEY_NEGATIVE_TTL,
                    "Version metadata cache (artifact not found)", HttpVersionMetadataProvider.DEFAULT_NEGATIVE_TTL),
            new ConfigTtlEntry(HttpVersionMetadataProvider.CONFIG_KEY_ERROR_TTL,
                    "Version metadata cache (provider error)", HttpVersionMetadataProvider.DEFAULT_ERROR_TTL),
            new ConfigTtlEntry(CONFIG_KEY_LICENSE_FRESH_TTL,
                    "License lookup cache (POM licenses)", DEFAULT_LICENSE_FRESH_TTL));

    /** Preset choices offered by each TTL dropdown on the /config page, in minutes. */
    static final List<Map.Entry<Long, String>> CONFIG_TTL_OPTIONS = List.of(
            Map.entry(15L, "15 minutes"),
            Map.entry(30L, "30 minutes"),
            Map.entry(60L, "1 hour"),
            Map.entry(120L, "2 hours"),
            Map.entry(240L, "4 hours"),
            Map.entry(360L, "6 hours"),
            Map.entry(720L, "12 hours"),
            Map.entry(1440L, "1 day"));
}

package com.redkite.metadata;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Duration;
import java.util.function.Supplier;
import java.util.logging.Logger;

/**
 * Reads cache TTL overrides from the {@code rk_config} table, falling back to the compiled-in
 * default when no override is configured (or the DB is unavailable). Read fresh on every call
 * rather than cached, so a change made on the config page takes effect on the next cache lookup
 * without a restart — TTL lookups are already infrequent relative to the network calls they gate.
 *
 * <p>This class only ever reads. Seeding {@code rk_config} with the current defaults on first
 * startup, and updating rows from the config page, is RedKiteServerMain's responsibility.
 */
final class CacheTtlConfig {
    private static final Logger LOGGER = Logger.getLogger(CacheTtlConfig.class.getName());

    private CacheTtlConfig() {
    }

    static Duration read(Supplier<Connection> dbConnectionFactory, String configKey, Duration fallback) {
        if (dbConnectionFactory == null) return fallback;
        try (Connection c = dbConnectionFactory.get();
             PreparedStatement ps = c.prepareStatement("select config_value from rk_config where config_key = ?")) {
            ps.setString(1, configKey);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return fallback;
                long minutes = Long.parseLong(rs.getString("config_value").trim());
                return Duration.ofMinutes(minutes);
            }
        } catch (Exception e) {
            LOGGER.warning(() -> "Failed to read TTL config for " + configKey + ": " + e.getMessage());
            return fallback;
        }
    }
}

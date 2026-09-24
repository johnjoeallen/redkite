package com.redkite.server;

import com.redkite.core.domain.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.logging.Logger;

import static com.redkite.server.Json.*;
import static com.redkite.server.CacheTtlSettings.*;

/** Declared licenses of a dependency version, resolved from its POM and cached in the database. */
final class LicenseLookup {
    private static final Logger LOGGER = Logger.getLogger(LicenseLookup.class.getName());
    private final Store store;

    LicenseLookup(Store store) {
        this.store = store;
    }

    synchronized void clearLicenseCache() {
        try (Connection c = store.connection();
             PreparedStatement ps = c.prepareStatement("delete from rk_license_cache")) {
            int rows = ps.executeUpdate();
            LOGGER.info(() -> "Cleared rk_license_cache: " + rows + " rows deleted");
        } catch (SQLException e) {
            LOGGER.warning(() -> "Failed to clear rk_license_cache: " + e.getMessage());
        }
    }

    /** Resolves the license(s) declared by {@code coordinate}'s own POM (walking its parent
     *  chain), backed by a DB cache — a resolved license for a fixed groupId:artifactId:version
     *  essentially never changes, so this is worth persisting across restarts even though
     *  {@link LicenseResolver}'s own in-memory cache already avoids re-fetching within one
     *  project's scan session. */
    List<String> resolveLicenses(ComponentCoordinate coordinate, String version) {
        String key = coordinate.groupId() + ":" + coordinate.artifactId() + ":" + version;
        List<String> cached = dbLoadLicenses(key);
        if (cached != null) return cached;
        List<String> resolved = store.licenseResolver.resolve(coordinate.groupId(), coordinate.artifactId(), version);
        dbSaveLicenses(key, resolved);
        return resolved;
    }

    private List<String> dbLoadLicenses(String key) {
        try (Connection c = store.connection();
             PreparedStatement ps = c.prepareStatement(
                     "select licenses_json, expires_at_epoch_ms from rk_license_cache where cache_key = ?")) {
            ps.setString(1, key);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                if (System.currentTimeMillis() > rs.getLong("expires_at_epoch_ms")) return null;
                return parseLicensesJson(rs.getString("licenses_json"));
            }
        } catch (Exception e) {
            LOGGER.warning(() -> "License cache load failed for " + key + ": " + e.getMessage());
            return null;
        }
    }

    private void dbSaveLicenses(String key, List<String> licenses) {
        long expires = System.currentTimeMillis() + readLicenseTtl().toMillis();
        String json = "[" + licenses.stream().map(Json::jsonStr).collect(java.util.stream.Collectors.joining(",")) + "]";
        try (Connection c = store.connection();
             PreparedStatement ps = c.prepareStatement(
                     "merge into rk_license_cache (cache_key, licenses_json, expires_at_epoch_ms, updated_at) key (cache_key) values (?, ?, ?, current_timestamp)")) {
            ps.setString(1, key);
            ps.setString(2, json);
            ps.setLong(3, expires);
            ps.executeUpdate();
        } catch (Exception e) {
            LOGGER.warning(() -> "License cache save failed for " + key + ": " + e.getMessage());
        }
    }

    private Duration readLicenseTtl() {
        try (Connection c = store.connection();
             PreparedStatement ps = c.prepareStatement("select config_value from rk_config where config_key = ?")) {
            ps.setString(1, CONFIG_KEY_LICENSE_FRESH_TTL);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return DEFAULT_LICENSE_FRESH_TTL;
                return Duration.ofMinutes(Long.parseLong(rs.getString("config_value").trim()));
            }
        } catch (Exception e) {
            return DEFAULT_LICENSE_FRESH_TTL;
        }
    }

    private static List<String> parseLicensesJson(String json) {
        com.google.gson.JsonArray array = com.google.gson.JsonParser.parseString(json).getAsJsonArray();
        List<String> licenses = new ArrayList<>();
        for (com.google.gson.JsonElement e : array) {
            licenses.add(e.getAsString());
        }
        return List.copyOf(licenses);
    }
}

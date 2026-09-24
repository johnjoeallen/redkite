package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.core.service.LicensePermissivenessDefaults;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.logging.Logger;

import static com.redkite.server.CacheTtlSettings.*;

/** Creates and migrates the database schema, and seeds configuration defaults on first start. */
final class StoreSchema {
    private static final Logger LOGGER = Logger.getLogger(StoreSchema.class.getName());
    private final Store store;

    StoreSchema(Store store) {
        this.store = store;
    }

    void initializeSchema() {
        try (Connection connection = store.connection();
             Statement st = connection.createStatement()) {

            // v2 is the only versioned gate: it was a destructive rekey from integer to UUID
            // primary keys. Guard it so it never re-runs on a DB that has already been migrated.
            st.executeUpdate("create table if not exists rk_schema_version (version int primary key)");
            int storedVersion;
            try (ResultSet vrs = st.executeQuery("select version from rk_schema_version")) {
                storedVersion = vrs.next() ? vrs.getInt("version") : 0;
            }
            if (storedVersion < 2) {
                LOGGER.info("One-time migration: dropping pre-UUID tables");
                st.executeUpdate("drop table if exists generated_poms");
                st.executeUpdate("drop table if exists source_poms");
                st.executeUpdate("drop table if exists metadata_cache_entries");
                st.executeUpdate("drop table if exists scans");
                st.executeUpdate("drop table if exists projects");
                st.executeUpdate("merge into rk_schema_version (version) values (2)");
            }

            // --- create all tables with their current full schema ---
            // Idempotent: CREATE TABLE IF NOT EXISTS is a no-op when the table already exists.

            st.executeUpdate("""
                    create table if not exists projects (
                      id uuid primary key,
                      name varchar(255) not null,
                      root_path varchar(1024) not null unique,
                      created_at timestamp not null default current_timestamp,
                      updated_at timestamp not null default current_timestamp,
                      enforcer_use_verify boolean not null default false,
                      validation_maven_args varchar(1024) not null default '',
                      validation_env varchar(2048) not null default ''
                    )
                    """);

            st.executeUpdate("""
                    create table if not exists scans (
                      id uuid primary key,
                      project_id uuid not null,
                      project_name varchar(255) not null,
                      repo_path varchar(1024) not null,
                      branch_name varchar(255) not null,
                      head_commit varchar(128) not null,
                      working_tree_clean boolean not null,
                      raw_input_json text not null,
                      report_json text not null,
                      complete boolean not null,
                      completeness_message text not null,
                      created_at timestamp not null default current_timestamp,
                      foreign key (project_id) references projects(id) on delete cascade
                    )
                    """);

            st.executeUpdate("""
                    create table if not exists metadata_cache_entries (
                      id uuid default random_uuid() primary key,
                      scan_id uuid not null,
                      component_id bigint not null,
                      metadata_type varchar(32) not null,
                      provider varchar(255) not null,
                      component_group_id varchar(255) not null,
                      component_artifact_id varchar(255) not null,
                      component_version varchar(255) not null,
                      latest_version varchar(255) not null,
                      latest_same_major_version varchar(255) not null,
                      complete boolean not null,
                      status varchar(32) not null,
                      cache_state varchar(32) not null,
                      last_successful_check_at timestamp with time zone,
                      cache_expiry_at timestamp with time zone,
                      attempted_refresh_at timestamp with time zone,
                      suggested_retry_at timestamp with time zone,
                      message text not null,
                      created_at timestamp with time zone not null default current_timestamp,
                      updated_at timestamp with time zone not null default current_timestamp,
                      unique (scan_id, component_id, metadata_type),
                      foreign key (scan_id) references scans(id) on delete cascade
                    )
                    """);

            st.executeUpdate("""
                    create table if not exists source_poms (
                      id uuid default random_uuid() primary key,
                      scan_id uuid not null,
                      file_path varchar(1024) not null,
                      pom_xml text not null,
                      unique (scan_id, file_path),
                      foreign key (scan_id) references scans(id) on delete cascade
                    )
                    """);

            st.executeUpdate("""
                    create table if not exists generated_poms (
                      id uuid default random_uuid() primary key,
                      scan_id uuid not null,
                      file_path varchar(1024) not null,
                      pom_xml text not null,
                      generated_at timestamp not null default current_timestamp,
                      unique (scan_id, file_path),
                      foreign key (scan_id) references scans(id) on delete cascade
                    )
                    """);

            st.executeUpdate("""
                    create table if not exists provider_rate_limit_state (
                      provider varchar(255) primary key,
                      rate_limited_at timestamp with time zone,
                      retry_after_at timestamp with time zone,
                      consecutive_rate_limits integer not null,
                      cooldown_until timestamp with time zone,
                      last_success_at timestamp with time zone,
                      updated_at timestamp with time zone not null default current_timestamp
                    )
                    """);

            st.executeUpdate("""
                    create table if not exists enforcer_results (
                      scan_id uuid primary key,
                      status varchar(64) not null,
                      raw_output text not null default '',
                      findings_blob text not null default '',
                      stale_exclusions_json text not null default '[]',
                      phase2_findings_blob text not null default '',
                      exclusions_stripped int not null default 0,
                      dep_mgmt_removed_json text not null default '[]',
                      phase2_pins_json text not null default '[]',
                      created_at timestamp not null default current_timestamp,
                      foreign key (scan_id) references scans(id) on delete cascade
                    )
                    """);

            st.executeUpdate("""
                    create table if not exists rk_version_cache (
                      cache_key varchar(512) primary key,
                      all_versions text not null,
                      latest_version varchar(255),
                      source varchar(512),
                      expires_at_epoch_ms bigint not null,
                      status varchar(32) not null,
                      complete boolean not null,
                      updated_at timestamp with time zone not null default current_timestamp
                    )
                    """);

            st.executeUpdate("""
                    create table if not exists rk_vuln_cache (
                      cache_key varchar(512) primary key,
                      response_json text not null,
                      expires_at_epoch_ms bigint not null,
                      updated_at timestamp with time zone not null default current_timestamp
                    )
                    """);

            st.executeUpdate("""
                    create table if not exists rk_license_cache (
                      cache_key varchar(512) primary key,
                      licenses_json text not null,
                      expires_at_epoch_ms bigint not null,
                      updated_at timestamp with time zone not null default current_timestamp
                    )
                    """);

            st.executeUpdate("""
                    create table if not exists rk_license_rank (
                      license_name varchar(255) primary key,
                      rank int not null,
                      updated_at timestamp with time zone not null default current_timestamp
                    )
                    """);

            st.executeUpdate("""
                    create table if not exists rk_config (
                      config_key varchar(100) primary key,
                      config_value varchar(255) not null,
                      updated_at timestamp with time zone not null default current_timestamp
                    )
                    """);

            // --- reconcile columns that were added to existing tables after initial release ---
            // ADD COLUMN IF NOT EXISTS is a no-op when the column already exists, so these
            // run on every startup without harm. New installs never reach these (the CREATE
            // TABLE above already includes all columns).
            st.executeUpdate("alter table enforcer_results add column if not exists stale_exclusions_json text not null default '[]'");
            st.executeUpdate("alter table enforcer_results add column if not exists phase2_findings_blob text not null default ''");
            st.executeUpdate("alter table enforcer_results add column if not exists exclusions_stripped int not null default 0");
            st.executeUpdate("alter table enforcer_results add column if not exists dep_mgmt_removed_json text not null default '[]'");
            st.executeUpdate("alter table enforcer_results add column if not exists phase2_pins_json text not null default '[]'");
            st.executeUpdate("alter table projects add column if not exists enforcer_use_verify boolean not null default false");
            st.executeUpdate("alter table projects add column if not exists validation_maven_args varchar(1024) not null default ''");
            st.executeUpdate("alter table projects add column if not exists validation_env varchar(2048) not null default ''");

        } catch (SQLException e) {
            throw new IllegalStateException("Failed to initialize schema", e);
        }
    }

    /** Inserts each configurable TTL's compiled-in default into rk_config, but only if that
     *  key has no row yet — never overwrites a value the user has already changed from the
     *  config page. Runs on every startup; idempotent after the first. */
    void seedConfigDefaults() {
        try (Connection connection = store.connection();
             PreparedStatement ps = connection.prepareStatement(
                     "insert into rk_config (config_key, config_value) " +
                     "select ?, ? where not exists (select 1 from rk_config where config_key = ?)")) {
            for (ConfigTtlEntry entry : CONFIG_TTL_ENTRIES) {
                ps.setString(1, entry.key());
                ps.setString(2, Long.toString(entry.defaultValue().toMinutes()));
                ps.setString(3, entry.key());
                ps.addBatch();
            }
            ps.executeBatch();
        } catch (SQLException e) {
            LOGGER.warning(() -> "Failed to seed config defaults: " + e.getMessage());
        }
    }

    /** Inserts each default license's seed rank into rk_license_rank, but only if that license
     *  has no row yet — never overwrites a rank the user already changed from the config page. */
    void seedLicenseRankDefaults() {
        try (Connection connection = store.connection();
             PreparedStatement ps = connection.prepareStatement(
                     "insert into rk_license_rank (license_name, rank) " +
                     "select ?, ? where not exists (select 1 from rk_license_rank where license_name = ?)")) {
            List<String> order = LicensePermissivenessDefaults.DEFAULT_ORDER;
            for (int i = 0; i < order.size(); i++) {
                ps.setString(1, order.get(i));
                ps.setInt(2, i);
                ps.setString(3, order.get(i));
                ps.addBatch();
            }
            ps.executeBatch();
        } catch (SQLException e) {
            LOGGER.warning(() -> "Failed to seed license rank defaults: " + e.getMessage());
        }
    }
}

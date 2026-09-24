package com.redkite.metadata;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import java.util.function.Supplier;

/** A private in-memory H2 database holding the cache tables the metadata providers use, created
 *  the same way red-kite-server's schema creates them. */
final class TestDb implements Supplier<Connection>, AutoCloseable {
    private final String url = "jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE";
    private final Connection keepAlive;
    private boolean broken;

    TestDb() throws SQLException {
        keepAlive = DriverManager.getConnection(url, "sa", "");
        exec("""
                create table rk_version_cache (
                  cache_key varchar(512) primary key,
                  all_versions text not null,
                  latest_version varchar(255),
                  source varchar(512),
                  expires_at_epoch_ms bigint not null,
                  status varchar(32) not null,
                  complete boolean not null,
                  updated_at timestamp with time zone not null default current_timestamp
                )""");
        exec("""
                create table rk_vuln_cache (
                  cache_key varchar(512) primary key,
                  response_json text not null,
                  expires_at_epoch_ms bigint not null,
                  updated_at timestamp with time zone not null default current_timestamp
                )""");
        exec("""
                create table rk_config (
                  config_key varchar(100) primary key,
                  config_value varchar(255) not null,
                  updated_at timestamp with time zone not null default current_timestamp
                )""");
    }

    /** After this, every connection request fails, as when the database is unavailable. */
    void breakConnections() {
        broken = true;
    }

    @Override
    public Connection get() {
        if (broken) throw new IllegalStateException("database unavailable");
        try {
            return DriverManager.getConnection(url, "sa", "");
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    void exec(String sql) throws SQLException {
        try (Statement st = keepAlive.createStatement()) {
            st.execute(sql);
        }
    }

    String query(String sql) throws SQLException {
        try (Statement st = keepAlive.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getString(1) : null;
        }
    }

    int count(String table) throws SQLException {
        return Integer.parseInt(query("select count(*) from " + table));
    }

    @Override
    public void close() throws SQLException {
        keepAlive.close();
    }
}

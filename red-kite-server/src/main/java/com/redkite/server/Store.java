package com.redkite.server;

import com.redkite.core.domain.*;
import com.redkite.core.service.SerializationSupport;
import com.redkite.maven.LicenseResolver;
import com.redkite.maven.MavenSettingsReader;
import com.redkite.maven.PomFetcher;
import com.redkite.metadata.HttpVersionMetadataProvider;
import com.redkite.metadata.HttpVulnerabilityProvider;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.logging.Logger;

final class Store {
    private static final Logger LOGGER = Logger.getLogger(Store.class.getName());
    private final String jdbcUrl;
    private final String dbUser;
    private final String dbPassword;
    volatile HttpVersionMetadataProvider versionProvider;
    final HttpVulnerabilityProvider vulnerabilityProvider;
    volatile LicenseResolver licenseResolver;
    volatile List<String> effectiveMavenRepos;
    volatile String mavenSettingsPath;
    final LicenseLookup licenses = new LicenseLookup(this);
    private final StoreSchema schema = new StoreSchema(this);
    private final ReportBuilder reports;

    private Store(String jdbcUrl, String dbUser, String dbPassword) {
        this.jdbcUrl = jdbcUrl;
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
        String mavenRepos = System.getProperty("redkite.maven.repositories");
        if (mavenRepos != null) {
            this.versionProvider = new HttpVersionMetadataProvider(mavenRepos, null, null, this::dbConnection);
            this.mavenSettingsPath = null;
        } else {
            // At startup the project root is not yet known; use home settings only.
            // reconfigureForProject() is called before each scan with the real root.
            java.nio.file.Path settingsPath = MavenSettingsReader.resolveSettingsFile(null);
            this.mavenSettingsPath = settingsPath != null ? settingsPath.toAbsolutePath().toString() : null;
            this.versionProvider = buildVersionProvider(null);
        }
        this.effectiveMavenRepos = this.versionProvider.getRepositoryBaseUrls();
        LOGGER.info(() -> "Maven settings: " + (mavenSettingsPath != null ? mavenSettingsPath : "(none)"));
        LOGGER.info(() -> "Effective Maven repositories: " + effectiveMavenRepos);
        this.vulnerabilityProvider = new HttpVulnerabilityProvider(System.getProperty("redkite.osv.url", "https://api.osv.dev"), this::dbConnection);
        this.licenseResolver = new LicenseResolver(new PomFetcher(null));
        this.reports = new ReportBuilder(this, new CveFixFinder(vulnerabilityProvider));
        schema.initializeSchema();
        schema.seedConfigDefaults();
        schema.seedLicenseRankDefaults();
    }

    /** Re-resolve settings from the project root before a scan. No-op when overridden by system property. */
    synchronized void reconfigureForProject(java.nio.file.Path projectRoot) {
        if (System.getProperty("redkite.maven.repositories") != null) return;
        java.nio.file.Path resolved = MavenSettingsReader.resolveSettingsFile(projectRoot);
        String newPath = resolved != null ? resolved.toAbsolutePath().toString() : null;
        if (java.util.Objects.equals(newPath, mavenSettingsPath)) {
            // Same settings file but credentials might have changed (env vars set after startup).
            // Clear error/missing cache so they get re-fetched with fresh env resolution.
            versionProvider.clearErrorCache();
            return;
        }
        LOGGER.info(() -> "Reconfiguring Maven settings for project " + projectRoot + ": " + newPath);
        this.mavenSettingsPath = newPath;
        this.versionProvider = buildVersionProvider(projectRoot); // instance method — has access to this::connection
        this.licenseResolver = new LicenseResolver(new PomFetcher(projectRoot));
        this.effectiveMavenRepos = this.versionProvider.getRepositoryBaseUrls();
        LOGGER.info(() -> "Effective Maven repositories: " + effectiveMavenRepos);
    }

    private HttpVersionMetadataProvider buildVersionProvider(java.nio.file.Path projectRoot) {
        List<MavenSettingsReader.RepoConfig> repoConfigs = MavenSettingsReader.discoverRepositoryConfigs(projectRoot);
        String urls = repoConfigs.stream()
                .map(MavenSettingsReader.RepoConfig::url)
                .collect(java.util.stream.Collectors.joining(","));
        String repoUser = null, repoPass = null;
        for (MavenSettingsReader.RepoConfig cfg : repoConfigs) {
            if (cfg.username() != null && !cfg.username().isBlank()) {
                repoUser = cfg.username();
                repoPass = cfg.password();
                break;
            }
        }
        return new HttpVersionMetadataProvider(urls, repoUser, repoPass, this::dbConnection);
    }

    private java.sql.Connection dbConnection() {
        try { return connection(); } catch (java.sql.SQLException e) { throw new RuntimeException(e); }
    }

    synchronized void clearVersionCache() {
        try (Connection c = connection();
             PreparedStatement ps = c.prepareStatement("delete from rk_version_cache")) {
            int rows = ps.executeUpdate();
            LOGGER.info(() -> "Cleared rk_version_cache: " + rows + " rows deleted");
        } catch (SQLException e) {
            LOGGER.warning(() -> "Failed to clear rk_version_cache: " + e.getMessage());
        }
    }

    static Store connect(String jdbcUrl, String dbUser, String dbPassword) {
        return new Store(jdbcUrl, dbUser, dbPassword);
    }

    synchronized List<ProjectEntry> listProjects() {
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement("""
                     select id, name, root_path, created_at, updated_at
                     from projects
                     order by updated_at desc
                     """);
             ResultSet rs = statement.executeQuery()) {
            List<ProjectEntry> projects = new ArrayList<>();
            while (rs.next()) {
                projects.add(new ProjectEntry(
                        rs.getString("id"),
                        rs.getString("name"),
                        rs.getString("root_path"),
                        rs.getTimestamp("created_at").toInstant(),
                        rs.getTimestamp("updated_at").toInstant()));
            }
            return projects;
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to list projects", e);
        }
    }

    synchronized ProjectEntry getProject(String id) {
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement("""
                     select id, name, root_path, created_at, updated_at
                     from projects
                     where id = ?
                     """)) {
            statement.setString(1, id);
            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    throw new IllegalArgumentException("project not found");
                }
                return new ProjectEntry(
                        rs.getString("id"),
                        rs.getString("name"),
                        rs.getString("root_path"),
                        rs.getTimestamp("created_at").toInstant(),
                        rs.getTimestamp("updated_at").toInstant());
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to fetch project", e);
        }
    }

    synchronized void deleteProject(String id) {
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement("delete from projects where id = ?")) {
            statement.setString(1, id);
            statement.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to delete project", e);
        }
    }

    synchronized boolean getProjectEnforcerUseVerify(String projectId) {
        try (Connection c = connection();
             PreparedStatement ps = c.prepareStatement(
                     "select enforcer_use_verify from projects where id = ?")) {
            ps.setString(1, projectId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() && rs.getBoolean("enforcer_use_verify");
            }
        } catch (SQLException e) {
            LOGGER.warning(() -> "Failed to read enforcer_use_verify for project " + projectId + ": " + e.getMessage());
            return false;
        }
    }

    synchronized void setProjectEnforcerUseVerify(String projectId) {
        try (Connection c = connection();
             PreparedStatement ps = c.prepareStatement(
                     "update projects set enforcer_use_verify = true where id = ?")) {
            ps.setString(1, projectId);
            ps.executeUpdate();
            LOGGER.info(() -> "Recorded enforcer_use_verify=true for project " + projectId);
        } catch (SQLException e) {
            LOGGER.warning(() -> "Failed to set enforcer_use_verify for project " + projectId + ": " + e.getMessage());
        }
    }

    synchronized List<ScanEntry> listScansForProject(String projectId) {
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement("""
                     select id, project_id, raw_input_json, report_json, created_at
                     from scans
                     where project_id = ?
                     order by created_at asc
                     """)) {
            statement.setString(1, projectId);
            List<ScanEntry> scans = new ArrayList<>();
            try (ResultSet rs = statement.executeQuery()) {
                while (rs.next()) scans.add(scanFromRow(rs));
            }
            return scans;
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to list scans for project", e);
        }
    }

    synchronized ScanEntry getScan(String scanId) {
        try (Connection connection = connection();
             PreparedStatement statement = connection.prepareStatement("""
                     select id, project_id, raw_input_json, report_json, created_at
                     from scans
                     where id = ?
                     """)) {
            statement.setString(1, scanId);
            try (ResultSet rs = statement.executeQuery()) {
                if (!rs.next()) {
                    throw new IllegalArgumentException("scan not found");
                }
                return scanFromRow(rs);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to fetch scan", e);
        }
    }

    synchronized ScanReport ingest(ScanInput input) {
        return ingest(input, msg -> {});
    }

    synchronized ScanReport ingest(ScanInput input, Consumer<String> progress) {
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            try {
                String projectId = upsertProject(connection, input.projectName(), input.projectRootPath());
                ScanReport draft = reports.buildReport(input, projectId, null, progress);
                String scanId = insertScan(connection, projectId, input, draft);
                List<MetadataResult> metadataResults = draft.metadataResults().stream().map(result -> withScanId(result, scanId)).toList();
                ScanReport finalReport = new ScanReport(scanId, projectId, draft.complete(), draft.completenessMessage(), draft.createdAt(), draft.components(), draft.dependencyEdges(), draft.vulnerabilityFindings(), draft.recommendations(), draft.snapshotDependencyRisks(), metadataResults, draft.treeParseWarnings());
                updateScanReport(connection, scanId, finalReport);
                persistMetadataCache(connection, finalReport);
                persistSourcePoms(connection, scanId, input);
                connection.commit();
                return finalReport;
            } catch (RuntimeException | SQLException e) {
                connection.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to ingest scan", e);
        }
    }

    private MetadataResult withScanId(MetadataResult result, String scanId) {
        return new MetadataResult(scanId, result.componentId(), result.metadataType(), result.provider(), result.currentVersion(), result.latestVersion(), result.latestSameMajorVersion(), result.upgradePathVersions(), result.allStableVersions(), result.complete(), result.status(), result.cacheState(), result.lastSuccessfulCheckAt(), result.cacheExpiryAt(), result.attemptedRefreshAt(), result.suggestedRetryAt(), result.message());
    }

    private void persistMetadataCache(Connection connection, ScanReport report) throws SQLException {
        java.util.Set<String> seen = new java.util.HashSet<>();
        try (PreparedStatement insert = connection.prepareStatement("""
                insert into metadata_cache_entries(
                  scan_id, component_id, metadata_type, provider, component_group_id, component_artifact_id, component_version, latest_version, latest_same_major_version,
                  complete, status, cache_state, last_successful_check_at, cache_expiry_at, attempted_refresh_at,
                  suggested_retry_at, message
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            for (MetadataResult result : report.metadataResults()) {
                String key = result.scanId() + ":" + result.componentId() + ":" + result.metadataType().name();
                if (!seen.add(key)) {
                    continue;
                }
                ScanComponent component = componentById(report.components(), result.componentId());
                insert.setString(1, result.scanId());
                insert.setLong(2, result.componentId());
                insert.setString(3, result.metadataType().name());
                insert.setString(4, result.provider());
                insert.setString(5, component == null ? "unknown" : component.coordinate().groupId());
                insert.setString(6, component == null ? "unknown" : component.coordinate().artifactId());
                insert.setString(7, component == null ? "unknown" : component.version());
                insert.setString(8, result.latestVersion() == null ? "unknown" : result.latestVersion());
                insert.setString(9, result.latestSameMajorVersion() == null ? "unknown" : result.latestSameMajorVersion());
                insert.setBoolean(10, result.complete());
                insert.setString(11, result.status().name());
                insert.setString(12, result.cacheState().name());
                insert.setTimestamp(13, result.lastSuccessfulCheckAt() == null ? null : java.sql.Timestamp.from(result.lastSuccessfulCheckAt()));
                insert.setTimestamp(14, result.cacheExpiryAt() == null ? null : java.sql.Timestamp.from(result.cacheExpiryAt()));
                insert.setTimestamp(15, result.attemptedRefreshAt() == null ? null : java.sql.Timestamp.from(result.attemptedRefreshAt()));
                insert.setTimestamp(16, result.suggestedRetryAt() == null ? null : java.sql.Timestamp.from(result.suggestedRetryAt()));
                insert.setString(17, result.message());
                insert.addBatch();
            }
            insert.executeBatch();
        }
    }

    private ScanComponent componentById(List<ScanComponent> components, long componentId) {
        for (ScanComponent component : components) {
            if (component.id() == componentId) {
                return component;
            }
        }
        return null;
    }

    /** All rk_config rows as key -> value (minutes, as stored). Missing keys are simply
     *  absent from the map — callers fall back to the compiled-in default. */
    synchronized Map<String, String> loadConfigValues() throws SQLException {
        Map<String, String> values = new LinkedHashMap<>();
        try (Connection connection = connection();
             PreparedStatement ps = connection.prepareStatement("select config_key, config_value from rk_config");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                values.put(rs.getString("config_key"), rs.getString("config_value"));
            }
        }
        return values;
    }

    synchronized void updateConfigValue(String key, String value) throws SQLException {
        try (Connection connection = connection();
             PreparedStatement ps = connection.prepareStatement(
                     "merge into rk_config (config_key, config_value, updated_at) key (config_key) values (?, ?, current_timestamp)")) {
            ps.setString(1, key);
            ps.setString(2, value);
            ps.executeUpdate();
        }
    }

    /** All configured license ranks, license name -> rank (lower = more permissive). Missing
     *  from this map means unranked, not "least permissive" — callers must treat the two
     *  differently rather than defaulting an absent rank to some large number. */
    synchronized Map<String, Integer> loadLicenseRanks() {
        Map<String, Integer> ranks = new LinkedHashMap<>();
        try (Connection connection = connection();
             PreparedStatement ps = connection.prepareStatement("select license_name, rank from rk_license_rank order by rank");
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                ranks.put(rs.getString("license_name"), rs.getInt("rank"));
            }
        } catch (SQLException e) {
            LOGGER.warning(() -> "Failed to load license ranks: " + e.getMessage());
        }
        return ranks;
    }

    /** Adds or updates a single license's rank — an upsert, so this also handles ranking a
     *  license name that isn't in the seeded default set at all yet. */
    synchronized void updateLicenseRank(String licenseName, int rank) throws SQLException {
        try (Connection connection = connection();
             PreparedStatement ps = connection.prepareStatement(
                     "merge into rk_license_rank (license_name, rank, updated_at) key (license_name) values (?, ?, current_timestamp)")) {
            ps.setString(1, licenseName);
            ps.setInt(2, rank);
            ps.executeUpdate();
        }
    }

    Connection connection() throws SQLException {
        return DriverManager.getConnection(jdbcUrl, dbUser, dbPassword);
    }

    private String upsertProject(Connection connection, String name, String rootPath) throws SQLException {
        try (PreparedStatement select = connection.prepareStatement("select id from projects where root_path = ?")) {
            select.setString(1, rootPath);
            try (ResultSet rs = select.executeQuery()) {
                if (rs.next()) {
                    String id = rs.getString(1);
                    try (PreparedStatement update = connection.prepareStatement("update projects set name = ?, updated_at = current_timestamp where id = ?")) {
                        update.setString(1, name);
                        update.setString(2, id);
                        update.executeUpdate();
                    }
                    return id;
                }
            }
        }
        String id = java.util.UUID.randomUUID().toString();
        try (PreparedStatement insert = connection.prepareStatement("insert into projects(id, name, root_path) values (?, ?, ?)")) {
            insert.setString(1, id);
            insert.setString(2, name);
            insert.setString(3, rootPath);
            insert.executeUpdate();
        }
        return id;
    }

    private String insertScan(Connection connection, String projectId, ScanInput input, ScanReport report) throws SQLException {
        String scanId = java.util.UUID.randomUUID().toString();
        try (PreparedStatement insert = connection.prepareStatement("""
                insert into scans(id, project_id, project_name, repo_path, branch_name, head_commit, working_tree_clean, raw_input_json, report_json, complete, completeness_message)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            insert.setString(1, scanId);
            insert.setString(2, projectId);
            insert.setString(3, input.projectName());
            insert.setString(4, input.projectRootPath());
            insert.setString(5, input.currentBranch());
            insert.setString(6, input.currentHeadCommit());
            insert.setBoolean(7, input.workingTreeClean());
            insert.setString(8, SerializationSupport.toBase64(input));
            insert.setString(9, SerializationSupport.toBase64(report));
            insert.setBoolean(10, report.complete());
            insert.setString(11, report.completenessMessage());
            insert.executeUpdate();
        }
        pruneScanHistory(connection, projectId);
        return scanId;
    }

    private void pruneScanHistory(Connection connection, String projectId) throws SQLException {
        try (PreparedStatement stmt = connection.prepareStatement("""
                delete from scans where project_id = ? and id not in (
                  select id from (select id from scans where project_id = ? order by created_at desc limit 7) as t
                )
                """)) {
            stmt.setString(1, projectId);
            stmt.setString(2, projectId);
            stmt.executeUpdate();
        }
    }

    private void updateScanReport(Connection connection, String scanId, ScanReport report) throws SQLException {
        try (PreparedStatement update = connection.prepareStatement("update scans set report_json = ?, complete = ?, completeness_message = ? where id = ?")) {
            update.setString(1, SerializationSupport.toBase64(report));
            update.setBoolean(2, report.complete());
            update.setString(3, report.completenessMessage());
            update.setString(4, scanId);
            update.executeUpdate();
        }
    }

    private ScanEntry scanFromRow(ResultSet rs) throws SQLException {
        ScanInput input = SerializationSupport.fromBase64(rs.getString("raw_input_json"), ScanInput.class);
        ScanReport report = SerializationSupport.fromBase64(rs.getString("report_json"), ScanReport.class);
        return new ScanEntry(rs.getString("id"), rs.getString("project_id"), input, report, rs.getTimestamp("created_at").toInstant());
    }

    private void persistSourcePoms(Connection connection, String scanId, ScanInput input) throws SQLException {
        java.util.Set<String> paths = new LinkedHashSet<>();
        // Include all discovered POM files, not just those with components
        paths.addAll(input.fileHashes().keySet());
        for (ScanComponent c : input.components()) {
            if (c.sourceFilePath() != null && !c.sourceFilePath().isBlank()) {
                paths.add(c.sourceFilePath());
            }
        }
        try (PreparedStatement del = connection.prepareStatement("delete from source_poms where scan_id = ?")) {
            del.setString(1, scanId);
            del.executeUpdate();
        }
        try (PreparedStatement ins = connection.prepareStatement(
                "insert into source_poms(scan_id, file_path, pom_xml) values (?, ?, ?)")) {
            for (String filePath : paths) {
                try {
                    Path pomPath = Path.of(filePath);
                    if (!pomPath.isAbsolute()) pomPath = Path.of(input.workingTreePath()).resolve(pomPath);
                    String raw = Files.readString(pomPath);
                    ins.setString(1, scanId);
                    ins.setString(2, filePath);
                    ins.setString(3, raw);
                    ins.executeUpdate();
                } catch (IOException e) {
                    LOGGER.warning(() -> "Could not snapshot POM: " + filePath + " — " + e.getMessage());
                }
            }
        }
    }

    synchronized Map<String, String> loadSourcePoms(String scanId) {
        try (Connection connection = connection();
             PreparedStatement ps = connection.prepareStatement(
                     "select file_path, pom_xml from source_poms where scan_id = ? order by file_path")) {
            ps.setString(1, scanId);
            Map<String, String> result = new LinkedHashMap<>();
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) result.put(rs.getString("file_path"), rs.getString("pom_xml"));
            }
            return result;
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to load source POMs", e);
        }
    }

    synchronized Map<String, String> loadPomFiles(String scanId) {
        try (Connection connection = connection();
             PreparedStatement ps = connection.prepareStatement(
                     "select file_path, pom_xml from generated_poms where scan_id = ? order by file_path")) {
            ps.setString(1, scanId);
            Map<String, String> result = new LinkedHashMap<>();
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) result.put(rs.getString("file_path"), rs.getString("pom_xml"));
            }
            return result;
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to load generated POMs", e);
        }
    }

    synchronized void saveEnforcerResult(String scanId, EnforcerStatus status,
                                         String rawOutput, List<TransitiveConflictFinding> findings,
                                         List<String> staleExclusions,
                                         List<TransitiveConflictFinding> phase2Findings,
                                         int exclusionsStripped, List<String> depMgmtRemoved,
                                         List<String> phase2Pins) {
        try (Connection c = connection();
             PreparedStatement ps = c.prepareStatement(
                     "merge into enforcer_results (scan_id, status, raw_output, findings_blob, stale_exclusions_json, phase2_findings_blob, exclusions_stripped, dep_mgmt_removed_json, phase2_pins_json) key (scan_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            ps.setString(1, scanId);
            ps.setString(2, status.name());
            ps.setString(3, rawOutput == null ? "" : rawOutput);
            ps.setString(4, SerializationSupport.toBase64(new java.util.ArrayList<>(findings)));
            ps.setString(5, toJsonStringArray(staleExclusions));
            ps.setString(6, phase2Findings == null ? "" : SerializationSupport.toBase64(new java.util.ArrayList<>(phase2Findings)));
            ps.setInt(7, exclusionsStripped);
            ps.setString(8, toJsonStringArray(depMgmtRemoved));
            ps.setString(9, toJsonStringArray(phase2Pins));
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.warning(() -> "Failed to save enforcer result for scan " + scanId + ": " + e.getMessage());
        }
    }

    private static String toJsonStringArray(List<String> list) {
        if (list == null || list.isEmpty()) return "[]";
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(list.get(i).replace("\\", "\\\\").replace("\"", "\\\"")).append("\"");
        }
        return sb.append("]").toString();
    }

    private static List<String> fromJsonStringArray(String json) {
        if (json == null || json.isBlank()) return List.of();
        List<String> result = new ArrayList<>();
        for (com.google.gson.JsonElement e : com.google.gson.JsonParser.parseString(json).getAsJsonArray()) {
            result.add(e.getAsString());
        }
        return result;
    }

    synchronized Map<String, EnforcerResultEntry> getEnforcerResults(List<String> scanIds) {
        if (scanIds.isEmpty()) return Map.of();
        Map<String, EnforcerResultEntry> result = new LinkedHashMap<>();
        for (String id : scanIds) {
            EnforcerResultEntry entry = getEnforcerResult(id);
            if (entry != null) result.put(id, entry);
        }
        return result;
    }

    synchronized EnforcerResultEntry getEnforcerResult(String scanId) {
        try (Connection c = connection();
             PreparedStatement ps = c.prepareStatement(
                     "select status, raw_output, findings_blob, stale_exclusions_json, phase2_findings_blob, exclusions_stripped, dep_mgmt_removed_json, phase2_pins_json from enforcer_results where scan_id = ?")) {
            ps.setString(1, scanId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                EnforcerStatus status = EnforcerStatus.valueOf(rs.getString("status"));
                String rawOutput = rs.getString("raw_output");
                @SuppressWarnings("unchecked")
                List<TransitiveConflictFinding> findings = SerializationSupport.fromBase64(rs.getString("findings_blob"), java.util.ArrayList.class);
                List<String> staleExclusions = fromJsonStringArray(rs.getString("stale_exclusions_json"));
                String p2blob = rs.getString("phase2_findings_blob");
                @SuppressWarnings("unchecked")
                List<TransitiveConflictFinding> phase2Findings = (p2blob == null || p2blob.isBlank())
                        ? null : SerializationSupport.fromBase64(p2blob, java.util.ArrayList.class);
                int exclusionsStripped = rs.getInt("exclusions_stripped");
                List<String> depMgmtRemoved = fromJsonStringArray(rs.getString("dep_mgmt_removed_json"));
                List<String> phase2Pins = fromJsonStringArray(rs.getString("phase2_pins_json"));
                return new EnforcerResultEntry(status, rawOutput,
                        findings == null ? List.of() : findings, staleExclusions, phase2Findings,
                        exclusionsStripped, depMgmtRemoved, phase2Pins);
            }
        } catch (SQLException | IllegalArgumentException e) {
            LOGGER.warning(() -> "Failed to load enforcer result for scan " + scanId + ": " + e.getMessage());
            return null;
        }
    }

    record EnforcerResultEntry(EnforcerStatus status, String rawOutput,
                               List<TransitiveConflictFinding> findings, List<String> staleExclusions,
                               List<TransitiveConflictFinding> phase2Findings,
                               int exclusionsStripped, List<String> depMgmtRemoved,
                               List<String> phase2Pins) {}
}

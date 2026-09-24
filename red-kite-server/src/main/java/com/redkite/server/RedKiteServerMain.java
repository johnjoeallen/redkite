package com.redkite.server;

import com.redkite.core.domain.*;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

import static com.redkite.server.Http.*;
import static com.redkite.server.Html.*;
import static com.redkite.server.Pages.*;

public class RedKiteServerMain {
    private static final Logger LOGGER = Logger.getLogger(RedKiteServerMain.class.getName());
    private final Store store;
    private final Pages pages;
    private final PageHandlers pageHandlers;
    private final ScanApiHandlers scanApi;
    private final RemediationHandlers remediation;
    private final ConfigHandlers config;
    private final HttpServer server;

    public RedKiteServerMain(String jdbcUrl, String dbUser, String dbPassword, int port) throws IOException {
        this.store = Store.connect(jdbcUrl, dbUser, dbPassword);
        java.nio.file.Path defaultDataDir = java.nio.file.Path.of(System.getProperty("user.home"), ".redkite");
        this.pages = new Pages(java.nio.file.Path.of(System.getProperty("redkite.prefs.file",
                defaultDataDir.resolve("preferences.properties").toString())));
        EnforcerAnalysis analysis = new EnforcerAnalysis(store);
        PomChanges pomChanges = new PomChanges(store, analysis);
        ScanPageRenderer scanPage = new ScanPageRenderer(store, new ComponentCardRenderer(store));
        this.pageHandlers = new PageHandlers(store, pages, scanPage,
                new EnforcerSectionRenderer(store, analysis), new LogModalRenderer(store, analysis));
        this.scanApi = new ScanApiHandlers(store, analysis, pomChanges);
        this.remediation = new RemediationHandlers(store, pomChanges);
        this.config = new ConfigHandlers(store, pages);
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.server.setExecutor(Executors.newCachedThreadPool());
        registerContexts();
    }

    public static void main(String[] args) throws Exception {
        java.nio.file.Path dataDir = java.nio.file.Path.of(System.getProperty("user.home"), ".redkite");
        Files.createDirectories(dataDir);
        loadConfigFileDefaults(dataDir.resolve("redkite.properties"));

        for (String arg : args) {
            if ("--drop-db".equals(arg)) {
                java.nio.file.Path dbFile = dataDir.resolve("redkite.mv.db");
                java.nio.file.Path traceFile = dataDir.resolve("redkite.trace.db");
                boolean deleted = Files.deleteIfExists(dbFile);
                Files.deleteIfExists(traceFile);
                System.out.println(deleted ? "Database dropped: " + dbFile : "No database file found at " + dbFile);
                return;
            }
        }

        String jdbcUrl = System.getProperty("redkite.db.url",
                "jdbc:h2:" + dataDir.resolve("redkite") + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE");
        String dbUser = System.getProperty("redkite.db.user", "sa");
        String dbPassword = System.getProperty("redkite.db.password", "");
        int port = Integer.parseInt(System.getProperty("redkite.port", "6502"));
        RedKiteServerMain app = new RedKiteServerMain(jdbcUrl, dbUser, dbPassword, port);
        app.start();
        System.out.println(BRAND + " server listening on http://localhost:" + port);
        new CountDownLatch(1).await();
    }

    /** Applies {@code redkite.*} keys from {@code ~/.redkite/redkite.properties} (if present) as
     *  system-property defaults — a persistent alternative to passing {@code -Dredkite.xxx=...}
     *  on every launch. An explicit {@code -D} flag on the command line always wins: this only
     *  ever fills in a property that isn't already set, so precedence stays flag > file > compiled-
     *  in default. {@code ${user.home}} in a value is expanded, since the bundled default file
     *  needs a portable way to express a path under the user's home directory. */
    static void loadConfigFileDefaults(java.nio.file.Path configFile) {
        if (!Files.exists(configFile)) return;
        java.util.Properties fileProps = new java.util.Properties();
        try (var reader = Files.newBufferedReader(configFile)) {
            fileProps.load(reader);
        } catch (IOException e) {
            LOGGER.warning(() -> "Failed to read config file " + configFile + ": " + e.getMessage());
            return;
        }
        String userHome = System.getProperty("user.home");
        for (String key : fileProps.stringPropertyNames()) {
            if (!key.startsWith("redkite.") || System.getProperty(key) != null) continue;
            String value = fileProps.getProperty(key);
            if (value != null && !value.isBlank()) {
                System.setProperty(key, value.replace("${user.home}", userHome));
            }
        }
    }

    public void start() {
        server.start();
    }

    /** The port actually bound — differs from the requested one when that was 0 (any free port). */
    int port() {
        return server.getAddress().getPort();
    }

    void stop() {
        server.stop(0);
    }

    private void registerContexts() {
        server.createContext("/health", exchange -> safeHandle(exchange, pageHandlers::handleHealth));
        server.createContext("/", exchange -> safeHandle(exchange, pageHandlers::handleIndex));
        server.createContext("/logo.svg", exchange -> safeHandle(exchange, pages::handleLogo));
        server.createContext("/projects", exchange -> safeHandle(exchange, pageHandlers::handleProjects));
        server.createContext("/scans", exchange -> safeHandle(exchange, pageHandlers::handleScans));
        server.createContext("/api/scan", exchange -> safeHandle(exchange, scanApi::handleApiScan));
        server.createContext("/api/scan-status", exchange -> safeHandle(exchange, scanApi::handleApiScanStatus));
        server.createContext("/api/scans/pom", exchange -> safeHandle(exchange, scanApi::handleApiScanPom));
        server.createContext("/api/scans/pom/write", exchange -> safeHandle(exchange, scanApi::handleApiScanPomWrite));
        server.createContext("/api/metadata/clear", exchange -> safeHandle(exchange, scanApi::handleApiMetadataClear));
        server.createContext("/api/projects", exchange -> safeHandle(exchange, scanApi::handleApiProjects));
        server.createContext("/api/prefs", exchange -> safeHandle(exchange, config::handleApiPrefs));
        server.createContext("/api/scans/enforcer", exchange -> safeHandle(exchange, scanApi::handleApiEnforcerResults));
        server.createContext("/api/scans/remediation/apply", exchange -> safeHandle(exchange, remediation::handleApiRemediationApply));
        server.createContext("/api/scans/remediation/apply-batch", exchange -> safeHandle(exchange, remediation::handleApiRemediationApplyBatch));
        server.createContext("/api/scans/remediation/apply-status", exchange -> safeHandle(exchange, remediation::handleApiRemediationApplyStatus));
        server.createContext("/api/scans/remediation/resolve", exchange -> safeHandle(exchange, remediation::handleApiRemediationResolve));
        server.createContext("/api/scans/remediation/plan", exchange -> safeHandle(exchange, remediation::handleApiRemediationPlan));
        server.createContext("/config", exchange -> safeHandle(exchange, config::handleConfig));
        server.createContext("/api/config", exchange -> safeHandle(exchange, config::handleApiConfig));
        server.createContext("/api/config/license-ranks", exchange -> safeHandle(exchange, config::handleApiConfigLicenseRanks));
    }

    private void safeHandle(HttpExchange exchange, ExchangeHandler handler) throws IOException {
        try {
            handler.handle(exchange);
        } catch (Exception e) {
            LOGGER.log(java.util.logging.Level.SEVERE, "HTTP handler failed for " + exchange.getRequestURI(), e);
            String msg = causeChain(e);
            sendText(exchange, 500, BRAND + " error: " + escape(msg));
        }
    }
}

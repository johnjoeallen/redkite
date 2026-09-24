package com.redkite.server;

import com.redkite.core.domain.ComponentCoordinate;
import com.redkite.maven.LicenseResolver;
import com.redkite.maven.PomFetchResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/** License lookups and their database cache, against an in-memory H2 store. */
class LicenseLookupTest {
    private static final ComponentCoordinate LIB = new ComponentCoordinate("g", "lib");
    private static final String POM = "<project><licenses><license><name>Apache-2.0</name></license>"
            + "<license><name>MIT</name></license></licenses></project>";

    private final AtomicInteger fetches = new AtomicInteger();
    private String savedRepos;
    private Store store;

    @BeforeEach
    void openStore() {
        // Keep Store's constructor away from the user's real Maven settings.
        savedRepos = System.getProperty("redkite.maven.repositories");
        System.setProperty("redkite.maven.repositories", "http://127.0.0.1:1/repo");
        store = Store.connect("jdbc:h2:mem:" + UUID.randomUUID() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1", "sa", "");
    }

    @AfterEach
    void restoreProperty() {
        if (savedRepos == null) System.clearProperty("redkite.maven.repositories");
        else System.setProperty("redkite.maven.repositories", savedRepos);
    }

    /** A fresh resolver per call, so only the database cache can prevent a second fetch. */
    private List<String> resolve() {
        store.licenseResolver = new LicenseResolver((groupId, artifactId, version) -> {
            fetches.incrementAndGet();
            return new PomFetchResult.Found(POM);
        });
        return store.licenses.resolveLicenses(LIB, "1.0");
    }

    private void setLicenseTtlMinutes(String minutes) throws Exception {
        try (Connection c = store.connection();
             PreparedStatement ps = c.prepareStatement("update rk_config set config_value = ? where config_key = ?")) {
            ps.setString(1, minutes);
            ps.setString(2, CacheTtlSettings.CONFIG_KEY_LICENSE_FRESH_TTL);
            assertEquals(1, ps.executeUpdate());
        }
    }

    @Test
    void resolvedLicensesAreCachedInTheDatabase() {
        assertEquals(List.of("Apache-2.0", "MIT"), resolve());
        assertEquals(List.of("Apache-2.0", "MIT"), resolve());
        assertEquals(1, fetches.get());
    }

    @Test
    void anExpiredCacheEntryIsResolvedAgain() throws Exception {
        setLicenseTtlMinutes("-1");
        assertEquals(List.of("Apache-2.0", "MIT"), resolve());
        assertEquals(List.of("Apache-2.0", "MIT"), resolve());
        assertEquals(2, fetches.get());
    }

    @Test
    void anUnreadableTtlFallsBackToTheDefault() throws Exception {
        setLicenseTtlMinutes("soon");
        resolve();
        resolve();
        assertEquals(1, fetches.get());
    }

    @Test
    void clearingTheCacheForcesAFreshLookup() {
        resolve();
        store.licenses.clearLicenseCache();
        resolve();
        assertEquals(2, fetches.get());
    }
}

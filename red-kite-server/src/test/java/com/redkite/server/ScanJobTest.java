package com.redkite.server;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Progress JSON of a running analysis. */
class ScanJobTest {
    @Test
    void scanPhasesJson() {
        String json = ScanJob.scanPhases(1, "a", 2, "b", 3, "c", 4, "d", 5, "e");
        assertTrue(json.startsWith("[{\"name\":\"Dependency analysis\",\"pct\":1,\"status\":\"a\"}"), json);
        assertTrue(json.endsWith("{\"name\":\"Dependency management\",\"pct\":5,\"status\":\"e\"}]"), json);
        assertTrue(json.contains("{\"name\":\"Update analysis\",\"pct\":4,\"status\":\"d\"}"), json);
    }
}

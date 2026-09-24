package com.redkite.server;

import com.redkite.core.domain.*;
import java.util.List;

final class ScanJob {
    enum Status { RUNNING, DONE, ERROR }
    volatile Status status = Status.RUNNING;
    volatile String phasesJson = scanPhases(0,"active",0,"pending",0,"pending",0,"pending",0,"pending");
    volatile String scanId;
    volatile String errorMessage;

    /** Last few lines of live Maven output (dependency:tree, enforcer, and any validation
     *  runs) across every stage of the scan, so the "Analysing" overlay can show a short
     *  scrolling tail the same way the apply overlay does. */
    private final RecentLines recentLines = new RecentLines();

    void appendLine(String line) {
        recentLines.append(line);
    }

    List<String> recentLinesSnapshot() {
        return recentLines.snapshot();
    }

    static String scanPhases(int p0, String s0, int p1, String s1, int p2, String s2,
                                     int p3, String s3, int p4, String s4) {
        return "[{\"name\":\"Dependency analysis\",\"pct\":" + p0 + ",\"status\":\"" + s0 + "\"},"
             + "{\"name\":\"Version metadata\",\"pct\":" + p1 + ",\"status\":\"" + s1 + "\"},"
             + "{\"name\":\"Vulnerability scan\",\"pct\":" + p2 + ",\"status\":\"" + s2 + "\"},"
             + "{\"name\":\"Update analysis\",\"pct\":" + p3 + ",\"status\":\"" + s3 + "\"},"
             + "{\"name\":\"Dependency management\",\"pct\":" + p4 + ",\"status\":\"" + s4 + "\"}]";
    }
}

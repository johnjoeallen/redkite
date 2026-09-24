package com.redkite.server;

import com.redkite.core.domain.*;
import java.util.List;

import static com.redkite.server.ScanJob.*;

final class ApplyJob {
    enum Status { RUNNING, DONE, FAILED, ERROR }
    enum Phase { PRE_VALIDATE, APPLYING, POST_VALIDATE }
    volatile Status status = Status.RUNNING;
    volatile Phase phase = Phase.PRE_VALIDATE;
    volatile boolean baselinePassed = true;
    volatile String failureMessage;
    volatile String attribution;
    volatile String revertedVersion;
    volatile String failedVersion;
    volatile String failureSignature;
    /** Exact Maven command line run for the failing post-apply validation, so the UI can show
     *  the user exactly what RedKite ran (also persisted to {@code .redkite/work/build.log}). */
    volatile String failureCommand;
    /** Absolute path to the {@code .redkite/work/build.log} file ValidationRunner wrote for
     *  this failure, or {@code null} if it could not be determined. */
    volatile String failureLogPath;
    /** True when the fully-computed patched POM set turned out identical to what's already on
     *  disk — nothing was validated or written, since there was nothing to apply. */
    volatile boolean noChanges = false;

    /** Last few lines of live build output, oldest first, so the "Applying changes" panel can
     *  show a short scrolling tail without ever needing its own scrollbar. */
    private final RecentLines recentLines = new RecentLines();

    void appendLine(String line) {
        recentLines.append(line);
    }

    List<String> recentLinesSnapshot() {
        return recentLines.snapshot();
    }
}

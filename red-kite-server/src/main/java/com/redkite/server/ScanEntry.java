package com.redkite.server;

import com.redkite.core.domain.*;
import java.time.Instant;

record ScanEntry(String id, String projectId, ScanInput input, ScanReport report, Instant createdAt) implements java.io.Serializable {
}

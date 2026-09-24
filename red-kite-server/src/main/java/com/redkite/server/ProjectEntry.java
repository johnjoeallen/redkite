package com.redkite.server;

import com.redkite.core.domain.*;
import java.time.Instant;

record ProjectEntry(String id, String name, String rootPath, Instant createdAt, Instant updatedAt) implements java.io.Serializable {
}

package com.redkite.git;

import java.nio.file.Path;
import java.util.Map;

public record WorkingCopyState(
        Path repoRoot,
        String branch,
        String headCommit,
        boolean clean,
        Map<String, String> fileHashes) {
}

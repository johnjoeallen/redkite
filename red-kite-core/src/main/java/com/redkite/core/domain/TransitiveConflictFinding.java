package com.redkite.core.domain;

import java.io.Serializable;
import java.util.List;

public record TransitiveConflictFinding(
        String groupId,
        String artifactId,
        String resolvedVersion,
        List<String> conflictingVersions,
        List<String> dependencyPaths,
        String ruleName,
        String sourcePom,
        List<ConflictCandidateAction> candidateActions
) implements Serializable {}

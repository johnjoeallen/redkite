package com.redkite.core.domain;

import java.io.Serializable;
import java.time.Instant;

public record ProviderRateLimitState(
        String provider,
        Instant rateLimitedAt,
        Instant retryAfterAt,
        int consecutiveRateLimits,
        Instant cooldownUntil,
        Instant lastSuccessAt) implements Serializable {
}

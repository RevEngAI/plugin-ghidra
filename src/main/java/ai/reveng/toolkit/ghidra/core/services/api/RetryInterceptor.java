package ai.reveng.toolkit.ghidra.core.services.api;

import okhttp3.Interceptor;
import okhttp3.Response;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Optional;
import java.util.Set;

/// Retries idempotent requests that the server answered with a 5xx or a 429.
///
/// The wait doubles from {@link #baseDelay} on each attempt, unless the response carries a
/// `Retry-After`, which wins. A `Retry-After` longer than {@link #maxDelay} is not waited out: the
/// response goes back to the caller as it is, since blocking a Ghidra task for minutes is worse than
/// failing. POST and PATCH are never retried, because the first attempt may already have taken effect.
///
/// Installed ahead of the logging interceptor, so every attempt is logged.
public class RetryInterceptor implements Interceptor {

    private static final Set<String> IDEMPOTENT_METHODS = Set.of("GET", "HEAD", "PUT", "DELETE", "OPTIONS");

    /// Pauses between attempts; tests replace it so they need not sleep.
    @FunctionalInterface
    public interface Sleeper {
        void sleep(Duration duration) throws InterruptedException;
    }

    private final int maxAttempts;
    private final Duration baseDelay;
    private final Duration maxDelay;
    private final Sleeper sleeper;

    public RetryInterceptor(int maxAttempts, Duration baseDelay, Duration maxDelay, Sleeper sleeper) {
        this.maxAttempts = maxAttempts;
        this.baseDelay = baseDelay;
        this.maxDelay = maxDelay;
        this.sleeper = sleeper;
    }

    /// Four attempts, waiting 1 s, 2 s and 4 s in between, and at most 30 s for a `Retry-After`.
    public static RetryInterceptor standard() {
        return new RetryInterceptor(4, Duration.ofSeconds(1), Duration.ofSeconds(30),
                duration -> Thread.sleep(duration.toMillis()));
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        var request = chain.request();
        var response = chain.proceed(request);
        if (!IDEMPOTENT_METHODS.contains(request.method())) {
            return response;
        }
        for (int attempt = 1; attempt < maxAttempts && isRetryable(response.code()); attempt++) {
            var delay = delayBefore(attempt, response);
            if (delay.isEmpty()) {
                return response;
            }
            response.close();
            try {
                sleeper.sleep(delay.get());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("Interrupted while waiting to retry " + request.url());
            }
            response = chain.proceed(request);
        }
        return response;
    }

    private static boolean isRetryable(int code) {
        return code == 429 || (code >= 500 && code < 600);
    }

    /// How long to wait before attempt `attempt + 1`, or empty when the server asked for longer than
    /// this interceptor is willing to wait.
    private Optional<Duration> delayBefore(int attempt, Response response) {
        var retryAfter = retryAfter(response.header("Retry-After"));
        if (retryAfter.isPresent()) {
            return retryAfter.get().compareTo(maxDelay) <= 0 ? retryAfter : Optional.empty();
        }
        var backoff = baseDelay.multipliedBy(1L << (attempt - 1));
        return Optional.of(backoff.compareTo(maxDelay) <= 0 ? backoff : maxDelay);
    }

    /// `Retry-After` is either a number of seconds or an HTTP date.
    static Optional<Duration> retryAfter(String header) {
        if (header == null || header.isBlank()) {
            return Optional.empty();
        }
        var value = header.trim();
        try {
            return Optional.of(Duration.ofSeconds(Math.max(0, Long.parseLong(value))));
        } catch (NumberFormatException notSeconds) {
            try {
                var at = ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME);
                var wait = Duration.between(ZonedDateTime.now(at.getZone()), at);
                return Optional.of(wait.isNegative() ? Duration.ZERO : wait);
            } catch (DateTimeParseException notADate) {
                return Optional.empty();
            }
        }
    }
}

package ai.reveng.toolkit.ghidra.core.services.api;

import javax.annotation.Nullable;
import java.time.Duration;
import java.util.Objects;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.function.Predicate;

/// Polls a server-side job until it reaches a final status, for every job the plugin waits on
/// (analysis, function matching, Similar Functions, AI decompilation).
///
/// Polls start {@link #interval} apart. While the status stays the same the wait doubles, up to
/// {@link #maxInterval}; any change resets it, so an active job is followed closely and a long,
/// quiet one is not hammered. Polling always ends: when the status is final, when it is one the
/// caller does not recognise, when {@link #timeLimit} is reached, or when the caller cancels.
///
/// A failed fetch ends polling by rethrowing its exception, unless {@link #retrying} marks it as
/// worth retrying; those back off separately, up to a number of consecutive failures.
public final class StatusPoller<S> {

    /// What a fetched status means for the wait.
    public enum Verdict {
        /// Still running; poll again.
        WAIT,
        /// Final, whether it succeeded or failed; the caller reads which from the status.
        DONE,
        /// A status the caller does not model. Waiting on it could last for ever, so polling ends.
        UNRECOGNISED
    }

    /// Why polling ended.
    public enum Ending { DONE, UNRECOGNISED, TIMED_OUT, CANCELLED }

    /// @param status the last status fetched, or null when none was
    public record Result<S>(Ending ending, @Nullable S status, Duration waited) {}

    @FunctionalInterface
    public interface Fetch<S, E extends Exception> {
        S get() throws E;
    }

    /// Longest single sleep, so a cancellation is noticed promptly even during a long backoff.
    private static final long CANCEL_CHECK_MS = 200;

    private final Duration interval;
    private final Duration maxInterval;
    private final Duration timeLimit;
    private Predicate<Exception> retryable = e -> false;
    private int maxConsecutiveFailures = 1;
    private Duration maxRetryBackoff;

    public StatusPoller(Duration interval, Duration maxInterval, Duration timeLimit) {
        this.interval = interval;
        this.maxInterval = maxInterval.compareTo(interval) < 0 ? interval : maxInterval;
        this.timeLimit = timeLimit;
        this.maxRetryBackoff = this.maxInterval;
    }

    /// Retry a fetch that fails with an exception {@code retryable} accepts, backing off up to
    /// {@code maxBackoff}, and give up on the {@code maxConsecutiveFailures}th failure in a row.
    public StatusPoller<S> retrying(Predicate<Exception> retryable, int maxConsecutiveFailures, Duration maxBackoff) {
        this.retryable = retryable;
        this.maxConsecutiveFailures = maxConsecutiveFailures;
        this.maxRetryBackoff = maxBackoff;
        return this;
    }

    /// Poll until {@code classify} reports a final or unrecognised status, the time limit is reached
    /// or {@code cancelled} turns true. {@code classify} sees every fetched status exactly once, in
    /// order, so it may also act on them (update the UI, trigger a follow-up step).
    ///
    /// @throws E                   the fetch failed, and was not retryable or failed too often in a row
    /// @throws InterruptedException the polling thread was interrupted while waiting
    public <E extends Exception> Result<S> poll(Fetch<S, E> fetch, Function<S, Verdict> classify,
                                                BooleanSupplier cancelled) throws E, InterruptedException {
        long start = System.nanoTime();
        S last = null;
        boolean fetched = false;
        long delay = interval.toMillis();
        long retryDelay = interval.toMillis();
        int failures = 0;
        while (true) {
            if (cancelled.getAsBoolean()) {
                return result(Ending.CANCELLED, last, start);
            }
            S current;
            try {
                current = fetch.get();
                failures = 0;
                retryDelay = interval.toMillis();
            } catch (Exception e) {
                if (!retryable.test(e) || ++failures >= maxConsecutiveFailures) {
                    throw e;
                }
                if (!sleepWithinLimit(retryDelay, start, cancelled)) {
                    return result(cancelled.getAsBoolean() ? Ending.CANCELLED : Ending.TIMED_OUT, last, start);
                }
                retryDelay = Math.min(retryDelay * 2, maxRetryBackoff.toMillis());
                continue;
            }

            if (fetched && Objects.equals(current, last)) {
                delay = Math.min(delay * 2, maxInterval.toMillis());
            } else {
                delay = interval.toMillis();
            }
            last = current;
            fetched = true;

            switch (classify.apply(current)) {
                case DONE -> {
                    return result(Ending.DONE, current, start);
                }
                case UNRECOGNISED -> {
                    return result(Ending.UNRECOGNISED, current, start);
                }
                case WAIT -> {
                    if (!sleepWithinLimit(delay, start, cancelled)) {
                        return result(cancelled.getAsBoolean() ? Ending.CANCELLED : Ending.TIMED_OUT, last, start);
                    }
                }
            }
        }
    }

    public Duration timeLimit() {
        return timeLimit;
    }

    /// Sleep for {@code millis}, in short steps so a cancellation cuts it short.
    ///
    /// @return false, without sleeping, if the sleep would run past the time limit; false if
    ///     cancelled while sleeping; true otherwise
    private boolean sleepWithinLimit(long millis, long start, BooleanSupplier cancelled) throws InterruptedException {
        long elapsed = (System.nanoTime() - start) / 1_000_000;
        if (elapsed + millis > timeLimit.toMillis()) {
            return false;
        }
        long deadline = System.nanoTime() + millis * 1_000_000;
        long remaining;
        while ((remaining = (deadline - System.nanoTime()) / 1_000_000) > 0) {
            if (cancelled.getAsBoolean()) {
                return false;
            }
            Thread.sleep(Math.min(remaining, CANCEL_CHECK_MS));
        }
        return !cancelled.getAsBoolean();
    }

    private static <S> Result<S> result(Ending ending, @Nullable S status, long start) {
        return new Result<>(ending, status, Duration.ofNanos(System.nanoTime() - start));
    }

    /// "3 hours" / "30 minute(s)" / "45 second(s)", rounded, for messages that say how long the plugin
    /// waited. A wait that hit its time limit stops just short of it, so it is rounded to the nearest unit.
    public static String describe(Duration duration) {
        long seconds = duration.toSeconds();
        if (seconds >= 2 * 3600) {
            return Math.round(seconds / 3600.0) + " hours";
        }
        return seconds >= 60 ? Math.round(seconds / 60.0) + " minute(s)" : seconds + " second(s)";
    }
}

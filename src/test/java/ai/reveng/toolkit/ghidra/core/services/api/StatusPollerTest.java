package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.core.services.api.StatusPoller.Ending;
import ai.reveng.toolkit.ghidra.core.services.api.StatusPoller.Verdict;
import org.junit.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class StatusPollerTest {

    private static Verdict classify(String status) {
        return switch (status) {
            case "DONE", "FAILED" -> Verdict.DONE;
            case "RUNNING", "STEP1", "STEP2" -> Verdict.WAIT;
            default -> Verdict.UNRECOGNISED;
        };
    }

    private static StatusPoller.Fetch<String, RuntimeException> sequence(String... statuses) {
        Iterator<String> it = List.of(statuses).iterator();
        return () -> it.hasNext() ? it.next() : statuses[statuses.length - 1];
    }

    @Test
    public void endsOnFinalStatus() throws Exception {
        var result = new StatusPoller<String>(Duration.ofMillis(1), Duration.ofMillis(1), Duration.ofSeconds(10))
                .poll(sequence("RUNNING", "RUNNING", "FAILED"), StatusPollerTest::classify, () -> false);
        assertEquals(Ending.DONE, result.ending());
        assertEquals("FAILED", result.status());
    }

    @Test
    public void endsOnUnrecognisedStatusInsteadOfPollingForEver() throws Exception {
        var polls = new AtomicInteger();
        var result = new StatusPoller<String>(Duration.ofMillis(1), Duration.ofMillis(1), Duration.ofSeconds(10))
                .poll(() -> {
                    polls.incrementAndGet();
                    return "CANCELLED";
                }, StatusPollerTest::classify, () -> false);
        assertEquals(Ending.UNRECOGNISED, result.ending());
        assertEquals("CANCELLED", result.status());
        assertEquals(1, polls.get());
    }

    /// A clock that only moves when the poller sleeps, so waits are exact on any machine.
    private static final class FakeClock {
        long nanos;
        final List<Long> sleeps = new ArrayList<>();

        <S> StatusPoller<S> drive(StatusPoller<S> poller) {
            return poller.withClock(() -> nanos, millis -> {
                sleeps.add(millis);
                nanos += millis * 1_000_000;
            });
        }
    }

    @Test
    public void endsAtTheTimeLimit() throws Exception {
        var clock = new FakeClock();
        var result = clock.drive(new StatusPoller<String>(Duration.ofMillis(5), Duration.ofMillis(5), Duration.ofMillis(100)))
                .poll(sequence("RUNNING"), StatusPollerTest::classify, () -> false);
        assertEquals(Ending.TIMED_OUT, result.ending());
        assertEquals("RUNNING", result.status());
        assertEquals(Duration.ofMillis(100), result.waited());
        assertEquals(20, clock.sleeps.size());
    }

    @Test
    public void endsWhenCancelled() throws Exception {
        var polls = new AtomicInteger();
        var result = new StatusPoller<String>(Duration.ofMillis(1), Duration.ofMillis(1), Duration.ofSeconds(10))
                .poll(() -> "RUNNING", s -> {
                    polls.incrementAndGet();
                    return classify(s);
                }, () -> polls.get() >= 3);
        assertEquals(Ending.CANCELLED, result.ending());
        assertEquals(3, polls.get());
    }

    @Test
    public void cancellingCutsALongWaitShort() throws Exception {
        long start = System.nanoTime();
        var polls = new AtomicInteger();
        var result = new StatusPoller<String>(Duration.ofSeconds(30), Duration.ofSeconds(30), Duration.ofMinutes(5))
                .poll(() -> {
                    polls.incrementAndGet();
                    return "RUNNING";
                }, StatusPollerTest::classify, () -> System.nanoTime() - start > 300_000_000L);
        assertEquals(Ending.CANCELLED, result.ending());
        assertEquals(1, polls.get());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toSeconds() < 5);
    }

    @Test
    public void backsOffWhileTheStatusIsUnchangedAndResetsOnChange() throws Exception {
        var clock = new FakeClock();
        var result = clock.drive(new StatusPoller<String>(Duration.ofMillis(20), Duration.ofMillis(80), Duration.ofSeconds(10)))
                .poll(sequence("RUNNING", "RUNNING", "RUNNING", "RUNNING", "STEP1", "STEP2", "DONE"),
                        StatusPollerTest::classify, () -> false);
        assertEquals(Ending.DONE, result.ending());
        // RUNNING x4: 20, then 40, then 80, then 80 (capped); after each change it is back to 20
        assertEquals(List.of(20L, 40L, 80L, 80L, 20L, 20L), clock.sleeps);
    }

    @Test
    public void retriesRetryableFailuresThenGivesUp() {
        var calls = new AtomicInteger();
        var poller = new StatusPoller<String>(Duration.ofMillis(1), Duration.ofMillis(1), Duration.ofSeconds(10))
                .retrying(e -> e instanceof ApiException api && api.getCode() == 503, 4, Duration.ofMillis(1));
        var thrown = assertThrows(ApiException.class, () -> poller.poll(() -> {
            calls.incrementAndGet();
            throw new ApiException(503, "Service Unavailable");
        }, StatusPollerTest::classify, () -> false));
        assertEquals(503, thrown.getCode());
        assertEquals(4, calls.get());
    }

    @Test
    public void recoversFromARetryableFailure() throws Exception {
        var calls = new AtomicInteger();
        var result = new StatusPoller<String>(Duration.ofMillis(1), Duration.ofMillis(1), Duration.ofSeconds(10))
                .retrying(e -> e instanceof ApiException, 4, Duration.ofMillis(1))
                .poll(() -> {
                    if (calls.incrementAndGet() == 1) {
                        throw new ApiException(503, "Service Unavailable");
                    }
                    return "DONE";
                }, StatusPollerTest::classify, () -> false);
        assertEquals(Ending.DONE, result.ending());
    }

    @Test
    public void rethrowsAFailureThatIsNotRetryable() {
        var calls = new AtomicInteger();
        var poller = new StatusPoller<String>(Duration.ofMillis(1), Duration.ofMillis(1), Duration.ofSeconds(10));
        assertThrows(ApiException.class, () -> poller.poll(() -> {
            calls.incrementAndGet();
            throw new ApiException(404, "Not Found");
        }, StatusPollerTest::classify, () -> false));
        assertEquals(1, calls.get());
    }

    @Test
    public void describesWaits() {
        assertEquals("3 hours", StatusPoller.describe(Duration.ofHours(3).minusSeconds(4)));
        assertEquals("30 minute(s)", StatusPoller.describe(Duration.ofMinutes(30).minusSeconds(3)));
        assertEquals("45 second(s)", StatusPoller.describe(Duration.ofSeconds(45)));
    }
}

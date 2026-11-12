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

    @Test
    public void endsAtTheTimeLimit() throws Exception {
        var result = new StatusPoller<String>(Duration.ofMillis(5), Duration.ofMillis(5), Duration.ofMillis(100))
                .poll(sequence("RUNNING"), StatusPollerTest::classify, () -> false);
        assertEquals(Ending.TIMED_OUT, result.ending());
        assertEquals("RUNNING", result.status());
        assertTrue(result.waited().toMillis() <= 100);
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
        List<Long> pollTimes = new ArrayList<>();
        var result = new StatusPoller<String>(Duration.ofMillis(20), Duration.ofMillis(80), Duration.ofSeconds(10))
                .poll(sequence("RUNNING", "RUNNING", "RUNNING", "RUNNING", "STEP1", "STEP2", "DONE"), s -> {
                    pollTimes.add(System.nanoTime() / 1_000_000);
                    return classify(s);
                }, () -> false);
        assertEquals(Ending.DONE, result.ending());
        List<Long> gaps = new ArrayList<>();
        for (int i = 1; i < pollTimes.size(); i++) {
            gaps.add(pollTimes.get(i) - pollTimes.get(i - 1));
        }
        // RUNNING x4: 20, then 40, then 80 (capped); after a change it is back to 20
        assertTrue("gaps: " + gaps, gaps.get(0) >= 20 && gaps.get(0) < 40);
        assertTrue("gaps: " + gaps, gaps.get(1) >= 40);
        assertTrue("gaps: " + gaps, gaps.get(2) >= 80);
        assertTrue("gaps: " + gaps, gaps.get(4) < 40);
        assertTrue("gaps: " + gaps, gaps.get(5) < 40);
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

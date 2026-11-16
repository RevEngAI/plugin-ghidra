package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.BatchRenameInputBody;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AutoUnstripStatus;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.sync.AutoUnstripSyncService;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.FunctionSignatureBatch;

/**
 * Integration tests for the post-auto-unstrip sync (PLU-300): once the server-side auto-unstrip pass
 * completes, the recovered function names must be pulled into Ghidra.
 */
public class AutoUnstripSyncTest extends RevEngMockableHeadedIntegrationTest {

    private static final ReaiLoggingService NOOP_LOG = new ReaiLoggingService() {
        @Override public void info(String message) {}
        @Override public void warn(String message) {}
        @Override public void error(String message) {}
    };

    /// Mock API that scripts auto-unstrip status responses and records rename calls.
    private static class UnstripApi extends UnimplementedAPI {
        final List<BatchRenameInputBody> renameCalls = new ArrayList<>();
        final Deque<AutoUnstripStatus> unstripStatuses = new ArrayDeque<>();
        List<FunctionInfo> functions = List.of();
        volatile int getFunctionInfoCalls = 0;
        /// When set, a function info fetch (the start of a sync) blocks until it is released.
        volatile CountDownLatch inSync;
        volatile CountDownLatch releaseSync;

        @Override
        public AnalysisStatus status(TypedApiInterface.AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(TypedApiInterface.AnalysisID analysisID) {
            getFunctionInfoCalls++;
            if (inSync != null) {
                inSync.countDown();
                try {
                    releaseSync.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            return functions;
        }

        @Override
        public FunctionSignatureBatch listFunctionSignatures(List<TypedApiInterface.FunctionID> functionIDs,
                                                             boolean includeDataTypes) {
            return FunctionSignatureBatch.empty();
        }

        @Override
        public long batchRenameFunctions(BatchRenameInputBody request) {
            renameCalls.add(request);
            return request.getFunctions().size();
        }

        /// Thrown, in order, by the first status polls before {@link #unstripStatuses} is consulted.
        final Deque<RuntimeException> failures = new ArrayDeque<>();
        final AtomicInteger statusCalls = new AtomicInteger();
        /// When set, a status poll blocks until it is released.
        volatile CountDownLatch inPoll;
        volatile CountDownLatch releasePoll;

        @Override
        public AutoUnstripStatus getAutoUnstripStatus(TypedApiInterface.AnalysisID analysisID) throws ApiException {
            statusCalls.incrementAndGet();
            if (inPoll != null) {
                inPoll.countDown();
                try {
                    releasePoll.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            var failure = failures.poll();
            if (failure instanceof WrappedApiException wrapped) {
                throw wrapped.apiException;
            }
            if (failure != null) {
                throw failure;
            }
            return unstripStatuses.size() > 1 ? unstripStatuses.poll() : unstripStatuses.peek();
        }
    }

    /// Lets an {@link ApiException} sit in the failure script next to runtime exceptions.
    private static class WrappedApiException extends RuntimeException {
        final ApiException apiException;

        WrappedApiException(int code) {
            this.apiException = new ApiException(code, "HTTP " + code);
        }
    }

    /// Records every message the service surfaces to the user.
    private static class Announcements implements BiConsumer<String, Boolean> {
        final List<String> warnings = new CopyOnWriteArrayList<>();
        final List<String> all = new CopyOnWriteArrayList<>();

        @Override
        public void accept(String message, Boolean warning) {
            all.add(message);
            if (warning) {
                warnings.add(message);
            }
        }
    }

    private record Fixture(GhidraRevengService service, GhidraRevengService.AnalysedProgram analysed, Function function) {}

    private Fixture setUp(UnstripApi api) throws Exception {
        api.functions = List.of(new FunctionInfo(new TypedApiInterface.FunctionID(7), "recovered_name", "recovered_name", 0x4000L, 0x100));
        var service = new GhidraRevengService(api);

        var builder = newX64Program();
        builder.createMemory("mem", "0x4000", 0x100);
        Function function = builder.createEmptyFunction(null, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();

        var programWithID = service.registerAnalysisForProgram(program, new TypedApiInterface.AnalysisID(1));
        service.registerFinishedAnalysisForProgram(programWithID, TaskMonitor.DUMMY);
        var analysed = service.getAnalysedProgram(program).orElseThrow();
        // The initial pull already fetched the function info; reset so a later fetch signals a sync ran.
        api.getFunctionInfoCalls = 0;
        return new Fixture(service, analysed, function);
    }

    private static boolean waitUntil(java.util.function.BooleanSupplier condition, long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (!condition.getAsBoolean() && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        return condition.getAsBoolean();
    }

    @Test
    public void syncsRecoveredNamesWhenUnstripAlreadyComplete() throws Exception {
        var api = new UnstripApi();
        api.unstripStatuses.add(AutoUnstripStatus.COMPLETED);
        var fixture = setUp(api);

        var syncService = new AutoUnstripSyncService(fixture.service(), NOOP_LOG, (m, w) -> {});
        try {
            syncService.pollAndSync(fixture.analysed(), true);
            assertTrue("a completed unstrip should trigger a sync",
                    waitUntil(() -> api.getFunctionInfoCalls > 0, 5000));
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void doesNotResyncWhenAlreadyCompleteOnFirstPollAndResyncDisabled() throws Exception {
        var api = new UnstripApi();
        api.unstripStatuses.add(AutoUnstripStatus.COMPLETED);
        var fixture = setUp(api);

        var syncService = new AutoUnstripSyncService(fixture.service(), NOOP_LOG, (m, w) -> {});
        try {
            syncService.pollAndSync(fixture.analysed(), false);
            Thread.sleep(1000);
            assertEquals("an already-complete unstrip must not be re-synced when resync is disabled",
                    0, api.getFunctionInfoCalls);
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void syncsAfterUnstripTransitionsToComplete() throws Exception {
        var api = new UnstripApi();
        api.unstripStatuses.add(AutoUnstripStatus.RUNNING);
        api.unstripStatuses.add(AutoUnstripStatus.COMPLETED);
        var fixture = setUp(api);

        var syncService = new AutoUnstripSyncService(fixture.service(), NOOP_LOG, (m, w) -> {});
        try {
            syncService.pollAndSync(fixture.analysed(), false);
            assertTrue("a running unstrip that later completes triggers a sync",
                    waitUntil(() -> api.getFunctionInfoCalls > 0, 10000));
        } finally {
            syncService.dispose();
        }
    }

    private static AutoUnstripSyncService fastService(Fixture fixture, BiConsumer<String, Boolean> notifier,
                                                      Duration maxPollDuration) {
        return new AutoUnstripSyncService(fixture.service(), NOOP_LOG, notifier,
                Duration.ofMillis(50), maxPollDuration);
    }

    @Test
    public void stopPollingDuringAPollEndsPolling() throws Exception {
        var api = new UnstripApi();
        api.unstripStatuses.add(AutoUnstripStatus.RUNNING);
        api.inPoll = new CountDownLatch(1);
        api.releasePoll = new CountDownLatch(1);
        var fixture = setUp(api);

        var syncService = fastService(fixture, (m, w) -> {}, Duration.ofMinutes(1));
        try {
            syncService.pollAndSync(fixture.analysed(), true);
            assertTrue(api.inPoll.await(5, TimeUnit.SECONDS));
            assertTrue(syncService.stopPolling(fixture.analysed().analysisID()));
            api.inPoll = null;
            api.releasePoll.countDown();
            Thread.sleep(500);
            assertEquals("a poll running when polling stops must not schedule another", 1, api.statusCalls.get());
            assertFalse("polling is no longer active", syncService.stopPolling(fixture.analysed().analysisID()));
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void givesUpAndWarnsWhenUnstripNeverFinishes() throws Exception {
        var api = new UnstripApi();
        api.unstripStatuses.add(AutoUnstripStatus.RUNNING);
        var fixture = setUp(api);
        var announcements = new Announcements();

        var syncService = fastService(fixture, announcements, Duration.ofMillis(400));
        try {
            syncService.pollAndSync(fixture.analysed(), true);
            assertTrue("running out of time is reported", waitUntil(() -> !announcements.warnings.isEmpty(), 5000));
            int calls = api.statusCalls.get();
            Thread.sleep(300);
            assertEquals("no polls after giving up", calls, api.statusCalls.get());
            assertTrue(announcements.warnings.get(0).contains("stopped waiting"));
            assertEquals(1, announcements.warnings.size());
            assertEquals(0, api.getFunctionInfoCalls);
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void retriesServerErrorsAndSyncsOnceUnstripCompletes() throws Exception {
        var api = new UnstripApi();
        api.failures.add(new WrappedApiException(503));
        api.failures.add(new WrappedApiException(502));
        api.unstripStatuses.add(AutoUnstripStatus.COMPLETED);
        var fixture = setUp(api);
        var announcements = new Announcements();

        var syncService = fastService(fixture, announcements, Duration.ofMinutes(1));
        try {
            syncService.pollAndSync(fixture.analysed(), true);
            assertTrue("a 5xx is retried and the later completion syncs",
                    waitUntil(() -> api.getFunctionInfoCalls > 0, 5000));
            assertEquals(3, api.statusCalls.get());
            assertTrue("a transient error is not shown as a failure", announcements.warnings.isEmpty());
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void stopsAndWarnsOnClientError() throws Exception {
        var api = new UnstripApi();
        api.failures.add(new WrappedApiException(404));
        api.unstripStatuses.add(AutoUnstripStatus.COMPLETED);
        var fixture = setUp(api);
        var announcements = new Announcements();

        var syncService = fastService(fixture, announcements, Duration.ofMinutes(1));
        try {
            syncService.pollAndSync(fixture.analysed(), true);
            assertTrue(waitUntil(() -> !announcements.warnings.isEmpty(), 5000));
            assertTrue(announcements.warnings.get(0).contains("HTTP 404"));
            Thread.sleep(300);
            assertEquals("a 4xx is not retried", 1, api.statusCalls.get());
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void reportsUnexpectedErrorsInsteadOfDyingSilently() throws Exception {
        var api = new UnstripApi();
        api.failures.add(new IllegalArgumentException("malformed body"));
        var fixture = setUp(api);
        var announcements = new Announcements();

        var syncService = fastService(fixture, announcements, Duration.ofMinutes(1));
        try {
            syncService.pollAndSync(fixture.analysed(), true);
            assertTrue("an unexpected error is reported", waitUntil(() -> !announcements.warnings.isEmpty(), 5000));
            assertTrue(announcements.warnings.get(0).contains("malformed body"));
            assertFalse(syncService.stopPolling(fixture.analysed().analysisID()));
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void doesNotSyncAProgramDetachedWhilePolling() throws Exception {
        var api = new UnstripApi();
        api.unstripStatuses.add(AutoUnstripStatus.COMPLETED);
        api.inPoll = new CountDownLatch(1);
        api.releasePoll = new CountDownLatch(1);
        var fixture = setUp(api);
        var announcements = new Announcements();

        var syncService = fastService(fixture, announcements, Duration.ofMinutes(1));
        try {
            syncService.pollAndSync(fixture.analysed(), true);
            assertTrue(api.inPoll.await(5, TimeUnit.SECONDS));
            var program = fixture.analysed().program();
            program.withTransaction("detach", () -> fixture.service().removeProgramAssociation(program));
            api.releasePoll.countDown();
            Thread.sleep(500);
            assertEquals("a detached program is not synced", 0, api.getFunctionInfoCalls);
            assertTrue("nothing is reported as failed", announcements.warnings.isEmpty());
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void detachDuringTheSyncCancelsItWithoutAWarning() throws Exception {
        var api = new UnstripApi();
        api.unstripStatuses.add(AutoUnstripStatus.COMPLETED);
        var fixture = setUp(api);
        api.inSync = new CountDownLatch(1);
        api.releaseSync = new CountDownLatch(1);
        var announcements = new Announcements();

        var syncService = fastService(fixture, announcements, Duration.ofMinutes(1));
        try {
            syncService.pollAndSync(fixture.analysed(), true);
            assertTrue(api.inSync.await(5, TimeUnit.SECONDS));
            // What the Detach action does while the sync is running.
            assertTrue("a running sync can still be stopped", syncService.stopPolling(fixture.analysed().analysisID()));
            var program = fixture.analysed().program();
            program.withTransaction("detach", () -> fixture.service().removeProgramAssociation(program));
            api.releaseSync.countDown();
            Thread.sleep(500);
            assertTrue("a sync stopped by Detach is not reported as failed", announcements.warnings.isEmpty());
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void doesNotSyncAProgramReattachedToAnotherAnalysisWhilePolling() throws Exception {
        var api = new UnstripApi();
        api.unstripStatuses.add(AutoUnstripStatus.COMPLETED);
        api.inPoll = new CountDownLatch(1);
        api.releasePoll = new CountDownLatch(1);
        var fixture = setUp(api);

        var syncService = fastService(fixture, (m, w) -> {}, Duration.ofMinutes(1));
        try {
            syncService.pollAndSync(fixture.analysed(), true);
            assertTrue(api.inPoll.await(5, TimeUnit.SECONDS));
            var program = fixture.analysed().program();
            program.withTransaction("detach", () -> fixture.service().removeProgramAssociation(program));
            var reattached = fixture.service().registerAnalysisForProgram(program, new TypedApiInterface.AnalysisID(2));
            fixture.service().registerFinishedAnalysisForProgram(reattached, TaskMonitor.DUMMY);
            api.getFunctionInfoCalls = 0;
            api.releasePoll.countDown();
            Thread.sleep(500);
            assertEquals("the old analysis is not synced into the re-attached program", 0, api.getFunctionInfoCalls);
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void stopsQuietlyWhenUnstripNeverStarts() throws Exception {
        var api = new UnstripApi();
        api.unstripStatuses.add(AutoUnstripStatus.UNINITIALISED);
        var fixture = setUp(api);
        var announcements = new Announcements();

        var syncService = fastService(fixture, announcements, Duration.ofMillis(400));
        try {
            syncService.pollAndSync(fixture.analysed(), false);
            assertTrue("polling ends", waitUntil(() -> !syncService.stopPolling(fixture.analysed().analysisID()), 5000));
            assertTrue("an unstrip that never started is neither announced nor reported", announcements.all.isEmpty());
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void pointsAtTheApiKeyWhenTheStatusCheckIsRefused() throws Exception {
        var api = new UnstripApi();
        api.failures.add(new WrappedApiException(401));
        var fixture = setUp(api);
        var announcements = new Announcements();

        var syncService = fastService(fixture, announcements, Duration.ofMinutes(1));
        try {
            syncService.pollAndSync(fixture.analysed(), true);
            assertTrue(waitUntil(() -> !announcements.warnings.isEmpty(), 5000));
            assertTrue(announcements.warnings.get(0).contains("API key"));
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void namesTheOutageWhenTheTimeLimitIsSpentRetrying() throws Exception {
        var api = new UnstripApi();
        for (int i = 0; i < 100; i++) {
            api.failures.add(new WrappedApiException(503));
        }
        api.unstripStatuses.add(AutoUnstripStatus.COMPLETED);
        var fixture = setUp(api);
        var announcements = new Announcements();

        var syncService = fastService(fixture, announcements, Duration.ofMillis(400));
        try {
            syncService.pollAndSync(fixture.analysed(), true);
            assertTrue(waitUntil(() -> !announcements.warnings.isEmpty(), 5000));
            assertTrue(announcements.warnings.get(0).contains("could not be checked"));
            assertTrue(announcements.warnings.get(0).contains("HTTP 503"));
        } finally {
            syncService.dispose();
        }
    }
}

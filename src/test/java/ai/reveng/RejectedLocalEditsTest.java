package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.BatchRenameInputBody;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.sync.LocalEditSyncService;
import ai.reveng.toolkit.ghidra.core.services.sync.UnpushedEdits;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/// Failures that sending again cannot fix: an edit the portal turns down, and a refused API key.
public class RejectedLocalEditsTest extends RevEngMockableHeadedIntegrationTest {

    /// Two functions, at 0x4000 (id 1) and 0x4100 (id 2).
    private static class PickyApi extends UnimplementedAPI {
        final Map<Long, String> renamed = new ConcurrentHashMap<>();
        final AtomicInteger renameRequests = new AtomicInteger();
        /// The portal validates the whole request, so one name it refuses fails the batch.
        volatile String refusedPrefix = "bad_";
        volatile boolean keyRefused;

        @Override
        public AnalysisStatus status(AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
            return List.of(
                    new FunctionInfo(new FunctionID(1), "FUN_00004000", "FUN_00004000", 0x4000L, 0x100),
                    new FunctionInfo(new FunctionID(2), "FUN_00004100", "FUN_00004100", 0x4100L, 0x100));
        }

        @Override
        public long batchRenameFunctions(BatchRenameInputBody request) throws ApiException {
            renameRequests.incrementAndGet();
            if (keyRefused) {
                throw new ApiException(401, "Unauthorized");
            }
            if (request.getFunctions().stream().anyMatch(item -> item.getNewName().startsWith(refusedPrefix))) {
                throw new ApiException(422, "Unprocessable Entity");
            }
            request.getFunctions().forEach(item -> renamed.put(item.getFunctionId(), item.getNewName()));
            return request.getFunctions().size();
        }
    }

    private static class RecordingLog implements ReaiLoggingService {
        final List<String> warnings = new CopyOnWriteArrayList<>();
        @Override public void info(String message) {}
        @Override public void warn(String message) { warnings.add(message); }
        @Override public void error(String message) {}
    }

    private final PickyApi api = new PickyApi();
    private final RecordingLog log = new RecordingLog();
    private final List<String> statusWarnings = new CopyOnWriteArrayList<>();
    private final List<String> statusInfos = new CopyOnWriteArrayList<>();
    private Program program;
    private Function first;
    private Function second;
    private LocalEditSyncService sync;

    @Before
    public void analyse() throws Exception {
        var service = new GhidraRevengService(api);
        var builder = newX64Program();
        builder.createMemory("code", "0x4000", 0x200);
        first = builder.createEmptyFunction("FUN_00004000", "0x4000", 0x100, new IntegerDataType());
        second = builder.createEmptyFunction("FUN_00004100", "0x4100", 0x100, new IntegerDataType());
        program = builder.getProgram();
        var withId = service.registerAnalysisForProgram(program, new AnalysisID(1));
        service.registerFinishedAnalysisForProgram(withId, TaskMonitor.DUMMY);
        // A retry after a wait only happens when the portal cannot be reached, which these tests
        // never do; one that came anyway would show up as an extra request.
        sync = new LocalEditSyncService(service, log,
                (message, warning) -> (warning ? statusWarnings : statusInfos).add(message),
                List.of(Duration.ofHours(1)));
        sync.attach(program);
    }

    @After
    public void disposeSync() {
        if (sync != null) {
            sync.dispose();
        }
    }

    private void rename(Function function, String newName) throws Exception {
        program.withTransaction("rename", () -> function.setName(newName, SourceType.USER_DEFINED));
        program.flushEvents();
    }

    private boolean marked(Function function) {
        return UnpushedEdits.isMarked(program, UnpushedEdits.Kind.NAME, function.getEntryPoint());
    }

    @Test
    public void anEditThePortalTurnsDownDoesNotHoldBackTheOthers() throws Exception {
        // Both in one debounce window, so they go up as one batch, which the portal refuses.
        rename(first, "good_one");
        rename(second, "bad_two");

        waitForCondition(() -> !statusWarnings.isEmpty(), "the rejected edit should be reported");
        assertEquals(Map.of(1L, "good_one"), api.renamed);
        assertFalse("the accepted rename is no longer waiting", marked(first));
        assertTrue("the rejected rename stays for the next sync", marked(second));
        assertTrue(statusWarnings.get(0), statusWarnings.get(0).contains("will not be retried"));
        assertTrue(log.warnings.stream().anyMatch(warning -> warning.contains("\"bad_two\"")));

        // Nothing is sent after that: a rejected edit is not retried automatically.
        int requests = api.renameRequests.get();
        Thread.sleep(1_000);
        assertEquals(requests, api.renameRequests.get());
        assertEquals(1, statusWarnings.size());
    }

    @Test
    public void anEditTurnedDownAgainIsNotReportedAgain() throws Exception {
        rename(second, "bad_two");
        waitForCondition(() -> !statusWarnings.isEmpty(), "the rejected edit should be reported");

        // Another rejected edit to the same function sends both again; only the new one is news.
        rename(first, "bad_one");
        waitForCondition(() -> statusWarnings.size() == 2, "the second rejected edit should be reported");
        assertTrue(statusWarnings.get(1), statusWarnings.get(1).contains("did not take 1 local edit"));
    }

    @Test
    public void aRefusedKeyIsReportedOnceAndResumesWhenAPushSucceeds() throws Exception {
        api.keyRefused = true;
        rename(first, "first_name");
        waitForCondition(() -> !statusWarnings.isEmpty(), "the refused key should be reported");
        assertTrue(statusWarnings.get(0), statusWarnings.get(0).contains("API key"));

        // Each rename is tried once by itself and once by the retry that follows its failure.
        rename(first, "first_name_again");
        waitForCondition(() -> api.renameRequests.get() >= 4, "the second rename should be tried");
        Thread.sleep(500);
        assertEquals("one report while the key is refused: " + statusWarnings, 1, statusWarnings.size());
        int requestsWhileRefused = api.renameRequests.get();
        Thread.sleep(1_000);
        assertEquals("no retries while the key is refused", requestsWhileRefused, api.renameRequests.get());

        api.keyRefused = false;
        rename(second, "second_name");
        waitForCondition(() -> api.renamed.size() == 2, "the earlier rename should follow the one that got through");
        assertEquals(Map.of(1L, "first_name_again", 2L, "second_name"), api.renamed);
        // The mock records the rename inside the send, and the mark is cleared only once the send returns.
        waitForCondition(() -> !marked(first), "the earlier rename should no longer be marked");
        waitForCondition(() -> !statusInfos.isEmpty(), "the edits that followed should be reported");
        assertTrue(statusInfos.get(0), statusInfos.get(0).contains("pushed 1 local edit"));
    }
}

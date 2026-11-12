package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.BatchRenameInputBody;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.FunctionSignatureBatch;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.sync.LocalEditSyncService;
import ai.reveng.toolkit.ghidra.core.services.sync.UnpushedEdits;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/// A local edit whose push fails is reported, stays marked as unpushed, and goes up on the next sync.
public class UnpushedLocalEditsTest extends RevEngMockableHeadedIntegrationTest {

    private static final long FUNCTION_ID = 1;

    /// One function at 0x4000. Its portal name is whatever was last pushed, unless a test sets one.
    private static class FlakyApi extends UnimplementedAPI {
        final Map<Long, String> renamed = new ConcurrentHashMap<>();
        volatile String remoteName = "FUN_00004000";
        volatile boolean renameThrows;
        volatile boolean renameSkipped;
        volatile boolean typesThrow;

        @Override
        public AnalysisStatus status(AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
            return List.of(new FunctionInfo(new FunctionID(FUNCTION_ID), remoteName, remoteName, 0x4000L, 0x100));
        }

        @Override
        public List<ServerDataType> listAnalysisDataTypes(AnalysisID analysisID, long offset, long limit) {
            if (typesThrow) {
                // How TypedApiImplementation wraps an ApiException from this call.
                throw new RuntimeException(new ApiException(503, "Service Unavailable"));
            }
            return List.of();
        }

        @Override
        public FunctionSignatureBatch listFunctionSignatures(List<FunctionID> functionIDs, boolean includeDataTypes) {
            return FunctionSignatureBatch.empty();
        }

        @Override
        public long batchRenameFunctions(BatchRenameInputBody request) throws ApiException {
            if (renameThrows) {
                throw new ApiException(503, "Service Unavailable");
            }
            if (renameSkipped) {
                return 0;
            }
            for (var item : request.getFunctions()) {
                renamed.put(item.getFunctionId(), item.getNewName());
                remoteName = item.getNewName();
            }
            return request.getFunctions().size();
        }
    }

    private static class RecordingLog implements ReaiLoggingService {
        final List<String> warnings = new CopyOnWriteArrayList<>();
        @Override public void info(String message) {}
        @Override public void warn(String message) { warnings.add(message); }
        @Override public void error(String message) {}
    }

    private final FlakyApi api = new FlakyApi();
    private final RecordingLog log = new RecordingLog();
    private final List<String> statusWarnings = new CopyOnWriteArrayList<>();
    private GhidraRevengService service;
    private Function function;
    private Program program;
    private LocalEditSyncService sync;

    @Before
    public void analyse() throws Exception {
        service = new GhidraRevengService(api);
        var builder = newX64Program();
        builder.createMemory("code", "0x4000", 0x200);
        function = builder.createEmptyFunction("FUN_00004000", "0x4000", 0x100, new IntegerDataType());
        program = builder.getProgram();
        var withId = service.registerAnalysisForProgram(program, new AnalysisID(1));
        service.registerFinishedAnalysisForProgram(withId, TaskMonitor.DUMMY);
    }

    @After
    public void disposeSync() {
        if (sync != null) {
            sync.dispose();
        }
    }

    private void listen() {
        sync = new LocalEditSyncService(service, log, (message, warning) -> {
            if (warning) {
                statusWarnings.add(message);
            }
        });
        sync.attach(program);
    }

    private void rename(String newName) throws Exception {
        program.withTransaction("rename", () -> function.setName(newName, SourceType.USER_DEFINED));
        program.flushEvents();
    }

    private boolean nameMarked() {
        return UnpushedEdits.isMarked(program, UnpushedEdits.Kind.NAME, function.getEntryPoint());
    }

    private GhidraRevengService.SyncSummary syncWithPortal() throws Exception {
        return service.syncAnalysisUpdates(service.getAnalysedProgram(program).orElseThrow(), TaskMonitor.DUMMY, log);
    }

    @Test
    public void aFailedRenameIsReportedAndSentByTheNextSync() throws Exception {
        listen();
        api.renameThrows = true;
        rename("mine");

        waitForCondition(() -> !statusWarnings.isEmpty(), "the failed push should reach the status bar");
        assertTrue(statusWarnings.get(0), statusWarnings.get(0).contains("mine"));
        assertTrue(log.warnings.contains(statusWarnings.get(0)));
        assertTrue(api.renamed.isEmpty());
        assertTrue(nameMarked());

        api.renameThrows = false;
        var summary = syncWithPortal();

        assertEquals(Map.of(FUNCTION_ID, "mine"), api.renamed);
        assertEquals(1, summary.pushedLocalEdits());
        assertEquals(0, summary.failedLocalEdits());
        assertEquals("the edit went up first, so it is no conflict", 0, summary.nameConflicts());
        assertFalse(nameMarked());
    }

    @Test
    public void aRenameThePortalSkippedCountsAsFailed() throws Exception {
        listen();
        api.renameSkipped = true;
        rename("mine");

        waitForCondition(() -> !statusWarnings.isEmpty(), "a renamed_count of zero should be reported");
        assertTrue(nameMarked());
    }

    @Test
    public void aSuccessfulRenameLeavesNothingMarked() throws Exception {
        listen();
        rename("mine");

        waitForCondition(() -> api.renamed.size() == 1, "the rename should be pushed");
        waitForCondition(() -> !nameMarked(), "the mark should be cleared once the push succeeded");
        assertTrue(statusWarnings.isEmpty());
    }

    /// A RuntimeException used to die unseen inside the discarded future.
    @Test
    public void anUncheckedFailureInATypePushIsReported() throws Exception {
        listen();
        api.typesThrow = true;
        program.withTransaction("retype", () -> function.setReturnType(new LongDataType(), SourceType.USER_DEFINED));
        program.flushEvents();

        waitForCondition(() -> !statusWarnings.isEmpty(), "the failed type push should reach the status bar");
        assertTrue(UnpushedEdits.isMarked(program, UnpushedEdits.Kind.TYPES, function.getEntryPoint()));
    }

    @Test
    public void reportsANameBothSidesChanged() throws Exception {
        // Renamed without the listener, so the local name never went up and is not marked as unpushed:
        // it looks like an edit that reached the portal before the portal's copy was renamed again.
        rename("mine");
        api.remoteName = "theirs";

        var summary = syncWithPortal();

        assertEquals(1, summary.nameConflicts());
        assertEquals("mine", function.getName());
        assertTrue(log.warnings.stream().anyMatch(warning -> warning.contains("theirs")));
    }
}

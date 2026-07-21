package ai.reveng;

import ai.reveng.model.BatchRenameInputBody;
import ai.reveng.model.FunctionDataTypesList;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AutoUnstripStatus;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.sync.AutoUnstripSyncService;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.jetbrains.annotations.Nullable;
import org.junit.Test;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Integration tests for the post-auto-unstrip sync (PLU-300): once the server-side auto-unstrip pass
 * completes, the recovered function names must be pulled into Ghidra.
 */
public class AutoUnstripSyncTest extends RevEngMockableHeadedIntegrationTest {

    private static final ReaiLoggingService NOOP_LOG = new ReaiLoggingService() {
        @Override public void info(String message) {}
        @Override public void warn(String message) {}
        @Override public void error(String message) {}
        @Override public void export(String targetDirectoryPath, String exportedFileName) {}
    };

    /// Mock API that scripts auto-unstrip status responses and records rename calls.
    private static class UnstripApi extends UnimplementedAPI {
        final List<BatchRenameInputBody> renameCalls = new ArrayList<>();
        final Deque<AutoUnstripStatus> unstripStatuses = new ArrayDeque<>();
        List<FunctionInfo> functions = List.of();
        int getFunctionInfoCalls = 0;

        @Override
        public AnalysisStatus status(TypedApiInterface.AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(TypedApiInterface.AnalysisID analysisID) {
            getFunctionInfoCalls++;
            return functions;
        }

        @Override
        public FunctionDataTypesList listFunctionDataTypesForAnalysis(TypedApiInterface.AnalysisID analysisID, @Nullable List<TypedApiInterface.FunctionID> ids) {
            try {
                return FunctionDataTypesList.fromJson("{\"total_count\":0,\"total_data_types_count\":0,\"items\":[]}");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void batchRenameFunctions(BatchRenameInputBody request) {
            renameCalls.add(request);
        }

        @Override
        public AutoUnstripStatus getAutoUnstripStatus(TypedApiInterface.AnalysisID analysisID) {
            return unstripStatuses.size() > 1 ? unstripStatuses.poll() : unstripStatuses.peek();
        }
    }

    private record Fixture(GhidraRevengService service, GhidraRevengService.AnalysedProgram analysed, Function function) {}

    private Fixture setUp(UnstripApi api) throws Exception {
        api.functions = List.of(new FunctionInfo(new TypedApiInterface.FunctionID(7), "recovered_name", "recovered_name", 0x4000L, 0x100));
        var service = new GhidraRevengService(api);

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
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

        var syncService = new AutoUnstripSyncService(fixture.service(), NOOP_LOG);
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

        var syncService = new AutoUnstripSyncService(fixture.service(), NOOP_LOG);
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

        var syncService = new AutoUnstripSyncService(fixture.service(), NOOP_LOG);
        try {
            syncService.pollAndSync(fixture.analysed(), false);
            assertTrue("a running unstrip that later completes triggers a sync",
                    waitUntil(() -> api.getFunctionInfoCalls > 0, 10000));
        } finally {
            syncService.dispose();
        }
    }
}

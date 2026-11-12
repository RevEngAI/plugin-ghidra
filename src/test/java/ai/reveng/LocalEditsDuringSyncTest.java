package ai.reveng;

import ai.reveng.model.BatchFunctionSignatureEntry;
import ai.reveng.model.BatchRenameInputBody;
import ai.reveng.model.CreateAnalysisDataTypesInputBody;
import ai.reveng.model.UpdateFunctionSignatureInputBody;
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
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/// Edits the analyst makes while a sync is running are pushed; only the changes the sync itself
/// writes are kept from going back up.
public class LocalEditsDuringSyncTest extends RevEngMockableHeadedIntegrationTest {

    private static final ReaiLoggingService NOOP_LOG = new ReaiLoggingService() {
        @Override public void info(String message) {}
        @Override public void warn(String message) {}
        @Override public void error(String message) {}
    };

    /// Each analysis holds one function at 0x4000, with the analysis id as its function id.
    private static class RecordingApi extends UnimplementedAPI {
        final Map<Long, String> renamed = new ConcurrentHashMap<>();
        final List<FunctionID> pushedSignatures = new CopyOnWriteArrayList<>();
        final Map<Integer, String> remoteNames = new ConcurrentHashMap<>();
        /// The portal's return type for every function, or null when it holds no signatures.
        volatile String remoteReturnType;
        /// When set, the next sync of analysis 1 waits for it while reading the portal's names.
        volatile CountDownLatch holdSyncOfAnalysis1;
        final CountDownLatch syncWaiting = new CountDownLatch(1);
        private long nextDataTypeId = 100;

        @Override
        public AnalysisStatus status(AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
            var hold = holdSyncOfAnalysis1;
            if (hold != null && analysisID.id() == 1) {
                syncWaiting.countDown();
                try {
                    hold.await(30, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            var name = remoteNames.getOrDefault(analysisID.id(), "FUN_00004000");
            return List.of(new FunctionInfo(new FunctionID(analysisID.id()), name, name, 0x4000L, 0x100));
        }

        @Override
        public FunctionSignatureBatch listFunctionSignatures(List<FunctionID> functionIDs, boolean includeDataTypes) {
            if (remoteReturnType == null) {
                return FunctionSignatureBatch.empty();
            }
            var entries = functionIDs.stream().map(id -> {
                var entry = new BatchFunctionSignatureEntry();
                entry.setAnalysisId(id.value());
                entry.setFunctionId(id.value());
                entry.setFunctionName("FUN_00004000");
                entry.setHasSignature(true);
                entry.setSourceType(BatchFunctionSignatureEntry.SourceTypeEnum.USER);
                entry.setReturnDataTypeId(1L);
                entry.setParameters(List.of());
                return entry;
            }).toList();
            var returnType = new ServerDataType(1L, "", remoteReturnType, ServerDataType.Kind.BASE,
                    4L, "AUTO", false, null, null, null);
            Map<AnalysisID, List<ServerDataType>> types = new ConcurrentHashMap<>();
            functionIDs.forEach(id -> types.put(new AnalysisID((int) id.value()), List.of(returnType)));
            return new FunctionSignatureBatch(entries, types);
        }

        @Override
        public void batchRenameFunctions(BatchRenameInputBody request) {
            for (var item : request.getFunctions()) {
                renamed.put(item.getFunctionId(), item.getNewName());
            }
        }

        @Override
        public List<ServerDataType> listAnalysisDataTypes(AnalysisID analysisID, long offset, long limit) {
            return List.of();
        }

        @Override
        public synchronized List<ServerDataType> createAnalysisDataTypes(AnalysisID analysisID,
                                                                         CreateAnalysisDataTypesInputBody request) {
            return request.getDataTypes().stream()
                    .map(type -> new ServerDataType(nextDataTypeId++, "", "pushed",
                            ServerDataType.Kind.BASE, null, "USER", false, null, null, null))
                    .toList();
        }

        @Override
        public void updateFunctionSignature(AnalysisID analysisID, FunctionID functionID,
                                            UpdateFunctionSignatureInputBody signature) {
            pushedSignatures.add(functionID);
        }
    }

    private final RecordingApi api = new RecordingApi();
    private final GhidraRevengService service = new GhidraRevengService(api);
    private LocalEditSyncService sync;

    @After
    public void tearDown() {
        var hold = api.holdSyncOfAnalysis1;
        if (hold != null) {
            hold.countDown();
        }
        if (sync != null) {
            sync.dispose();
        }
    }

    /// A function whose signature came from Ghidra's analysis, as on a real binary; ProgramBuilder
    /// would otherwise stamp it user-defined, which a pull leaves alone.
    private Function analysedFunction(String name, int analysisId) throws Exception {
        var builder = newX64Program(name);
        builder.createMemory("code", "0x4000", 0x200);
        Function function = builder.createEmptyFunction(
                "FUN_00004000", "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();
        program.withTransaction("analysis signature", () -> function.setSignatureSource(SourceType.ANALYSIS));
        var withId = service.registerAnalysisForProgram(program, new AnalysisID(analysisId));
        service.registerFinishedAnalysisForProgram(withId, TaskMonitor.DUMMY);
        return function;
    }

    private void listenTo(Function... functions) {
        sync = new LocalEditSyncService(service, env.getTool().getService(ReaiLoggingService.class));
        for (Function function : functions) {
            sync.attach(function.getProgram());
        }
    }

    private static void edit(Function function, String description, Runnable change) {
        var program = function.getProgram();
        program.withTransaction(description, change::run);
        program.flushEvents();
    }

    private GhidraRevengService.SyncSummary syncWithPortal(Function function) throws Exception {
        return service.syncAnalysisUpdates(
                service.getAnalysedProgram(function.getProgram()).orElseThrow(), TaskMonitor.DUMMY, NOOP_LOG);
    }

    @Test
    public void editsMadeWhileASyncWaitsOnThePortalArePushed() throws Exception {
        Function inA = analysedFunction("a", 1);
        Function inB = analysedFunction("b", 2);
        listenTo(inA, inB);

        var hold = new CountDownLatch(1);
        api.holdSyncOfAnalysis1 = hold;
        Thread syncing = new Thread(() -> {
            try {
                syncWithPortal(inA);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        syncing.start();
        assertTrue("the sync should be waiting on the portal", api.syncWaiting.await(30, TimeUnit.SECONDS));

        // In the program being synced, and in another one.
        edit(inA, "rename", () -> rethrow(() -> inA.setName("mine_a", SourceType.USER_DEFINED)));
        edit(inB, "rename", () -> rethrow(() -> inB.setName("mine_b", SourceType.USER_DEFINED)));
        edit(inB, "retype", () -> rethrow(() -> inB.setReturnType(new LongDataType(), SourceType.USER_DEFINED)));

        waitForCondition(() -> api.renamed.size() == 2 && !api.pushedSignatures.isEmpty(),
                "edits made during the sync should be pushed while it is still running");
        assertEquals(Map.of(1L, "mine_a", 2L, "mine_b"), api.renamed);
        assertEquals(List.of(new FunctionID(2)), api.pushedSignatures);

        hold.countDown();
        syncing.join(30_000);
        assertEquals("the sync keeps the analyst's name", "mine_a", inA.getName());
    }

    @Test
    public void whatTheSyncAppliesIsNotPushedBack() throws Exception {
        Function function = analysedFunction("a", 1);
        listenTo(function);
        api.remoteNames.put(1, "theirs");
        api.remoteReturnType = "int";

        var summary = syncWithPortal(function);
        assertEquals("theirs", function.getName());
        assertEquals(1, summary.appliedSignatures());
        assertEquals("int", function.getReturnType().getName());

        // Past the debounce, so anything the sync's own events had scheduled would have gone up.
        Thread.sleep(1_000);
        assertTrue("renames pushed: " + api.renamed, api.renamed.isEmpty());
        assertTrue("signatures pushed: " + api.pushedSignatures, api.pushedSignatures.isEmpty());
    }

    private interface Edit {
        void run() throws Exception;
    }

    private static void rethrow(Edit edit) {
        try {
            edit.run();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

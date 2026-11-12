package ai.reveng;

import ai.reveng.model.BatchRenameInputBody;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.sync.LocalEditSyncService;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.Assert.assertEquals;

/// One {@link LocalEditSyncService} serves every open program, so its debounce must not let an edit in
/// one program cancel a pending push for another program that happens to have a function at the same
/// address.
public class LocalEditSyncAcrossProgramsTest extends RevEngMockableHeadedIntegrationTest {

    private static final long ENTRY = 0x4000L;

    /// Each analysis holds one function at {@link #ENTRY}, with the analysis id as its function id.
    private static class RecordingApi extends UnimplementedAPI {
        final Map<Long, String> renamed = new ConcurrentHashMap<>();

        @Override
        public AnalysisStatus status(AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
            var id = new FunctionID(analysisID.id());
            return List.of(new FunctionInfo(id, "FUN_00004000", "FUN_00004000", ENTRY, 0x100));
        }

        @Override
        public List<ServerDataType> listAnalysisDataTypes(AnalysisID analysisID, long offset, long limit) {
            return List.of();
        }

        @Override
        public long batchRenameFunctions(BatchRenameInputBody request) {
            for (var item : request.getFunctions()) {
                renamed.put(item.getFunctionId(), item.getNewName());
            }
            return request.getFunctions().size();
        }
    }

    private LocalEditSyncService sync;

    @After
    public void disposeSync() {
        if (sync != null) {
            sync.dispose();
        }
    }

    private Function analysedFunction(GhidraRevengService service, String name, long analysisId) throws Exception {
        var builder = newX64Program(name);
        builder.createMemory("code", "0x4000", 0x200);
        Function function = builder.createEmptyFunction("FUN_00004000", "0x4000", 0x100, new IntegerDataType());
        var program = builder.getProgram();
        var withId = service.registerAnalysisForProgram(program, new AnalysisID((int) analysisId));
        service.registerFinishedAnalysisForProgram(withId, TaskMonitor.DUMMY);
        return function;
    }

    private static void rename(Function function, String newName) throws Exception {
        Program program = function.getProgram();
        int tx = program.startTransaction("rename");
        try {
            function.setName(newName, SourceType.USER_DEFINED);
        } finally {
            program.endTransaction(tx, true);
        }
        program.flushEvents();
    }

    @Test
    public void editsAtTheSameAddressInTwoProgramsAreBothPushed() throws Exception {
        var api = new RecordingApi();
        var service = new GhidraRevengService(api);
        Function inA = analysedFunction(service, "a", 1);
        Function inB = analysedFunction(service, "b", 2);

        sync = new LocalEditSyncService(service, env.getTool().getService(ReaiLoggingService.class),
                (message, warning) -> {});
        sync.attach(inA.getProgram());
        sync.attach(inB.getProgram());

        // Both inside one debounce window, which is where the second used to cancel the first.
        rename(inA, "renamed_in_a");
        rename(inB, "renamed_in_b");

        waitForCondition(() -> api.renamed.size() == 2, "both renames should be pushed");
        assertEquals(Map.of(1L, "renamed_in_a", 2L, "renamed_in_b"), api.renamed);
    }
}

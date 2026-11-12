package ai.reveng;

import ai.reveng.model.BatchRenameInputBody;
import ai.reveng.model.CreateAnalysisDataTypesInputBody;
import ai.reveng.model.UpdateFunctionSignatureInputBody;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.sync.LocalEditSyncService;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/// What the reactive push sends, and how many requests it takes.
public class LocalEditSyncScopeTest extends RevEngMockableHeadedIntegrationTest {

    private static final String SYNCED_TAG = "REVENGAI_SYNCED";
    private static final long[] ENTRIES = {0x4000L, 0x4100L, 0x4200L};

    /// One function per entry in {@link #ENTRIES}, with ids 1, 2 and 3.
    private static class RecordingApi extends UnimplementedAPI {
        final List<BatchRenameInputBody> renameRequests = new CopyOnWriteArrayList<>();
        final List<FunctionID> pushedSignatures = new CopyOnWriteArrayList<>();
        private final AtomicInteger nextDataTypeId = new AtomicInteger(100);

        @Override
        public AnalysisStatus status(AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
            return java.util.stream.IntStream.range(0, ENTRIES.length)
                    .mapToObj(i -> new FunctionInfo(new FunctionID(i + 1), "FUN_" + i, "FUN_" + i, ENTRIES[i], 0x100))
                    .toList();
        }

        @Override
        public long batchRenameFunctions(BatchRenameInputBody request) {
            renameRequests.add(request);
            return request.getFunctions().size();
        }

        @Override
        public List<ServerDataType> listAnalysisDataTypes(AnalysisID analysisID, long offset, long limit) {
            return List.of();
        }

        @Override
        public List<ServerDataType> createAnalysisDataTypes(AnalysisID analysisID,
                                                            CreateAnalysisDataTypesInputBody request) {
            return request.getDataTypes().stream()
                    .map(type -> new ServerDataType(nextDataTypeId.getAndIncrement(), "", "pushed",
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
    private Program program;
    private Function first;
    private LocalEditSyncService sync;

    @Before
    public void analyse() throws Exception {
        var service = new GhidraRevengService(api);
        var builder = newX64Program();
        builder.createMemory("code", "0x4000", 0x400);
        for (long entry : ENTRIES) {
            builder.createEmptyFunction(null, "0x" + Long.toHexString(entry), 0x100, new IntegerDataType());
        }
        program = builder.getProgram();
        first = program.getFunctionManager().getFunctionAt(address(ENTRIES[0]));
        program.withTransaction("give it a parameter", () -> rethrow(() -> first.replaceParameters(
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS,
                new ParameterImpl("count", new IntegerDataType(), program))));

        var withId = service.registerAnalysisForProgram(program, new AnalysisID(1));
        service.registerFinishedAnalysisForProgram(withId, TaskMonitor.DUMMY);
        sync = new LocalEditSyncService(service, env.getTool().getService(ReaiLoggingService.class),
                (message, warning) -> {});
        sync.attach(program);
    }

    @After
    public void disposeSync() {
        if (sync != null) {
            sync.dispose();
        }
    }

    private ghidra.program.model.address.Address address(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private void edit(String description, Edit change) {
        program.withTransaction(description, () -> rethrow(change));
        program.flushEvents();
    }

    private static boolean tagged(Function function) {
        return function.getTags().stream().anyMatch(tag -> SYNCED_TAG.equals(tag.getName()));
    }

    @Test
    public void renamesInOneProgramGoUpInOneRequest() throws Exception {
        for (int i = 0; i < ENTRIES.length; i++) {
            var function = program.getFunctionManager().getFunctionAt(address(ENTRIES[i]));
            var name = "renamed_" + i;
            edit("rename", () -> function.setName(name, SourceType.USER_DEFINED));
        }

        waitForCondition(() -> !api.renameRequests.isEmpty(), "the renames should be pushed");
        Thread.sleep(1_000);
        assertEquals("one request for all three renames", 1, api.renameRequests.size());
        var pushed = api.renameRequests.get(0).getFunctions().stream()
                .collect(java.util.stream.Collectors.toMap(item -> item.getFunctionId(), item -> item.getNewName()));
        assertEquals(Map.of(1L, "renamed_0", 2L, "renamed_1", 3L, "renamed_2"), pushed);
    }

    @Test
    public void localVariableEditsPushNothingButAParameterRenameDoes() throws Exception {
        edit("add a local", () -> first.addLocalVariable(
                new LocalVariableImpl("local", new IntegerDataType(), -0x10, program), SourceType.USER_DEFINED));
        var local = first.getLocalVariables()[0];
        edit("rename the local", () -> local.setName("renamed_local", SourceType.USER_DEFINED));
        edit("retype the local", () -> local.setDataType(new LongDataType(), SourceType.USER_DEFINED));

        // Past the debounce, so any push these had scheduled would have gone up.
        Thread.sleep(1_000);
        assertTrue("signatures pushed: " + api.pushedSignatures, api.pushedSignatures.isEmpty());

        edit("rename the parameter", () -> first.getParameter(0).setName("renamed_count", SourceType.USER_DEFINED));
        waitForCondition(() -> !api.pushedSignatures.isEmpty(), "a parameter rename should push the signature");
        assertEquals(List.of(new FunctionID(1)), api.pushedSignatures);
    }

    @Test
    public void aFunctionCreatedAgainKeepsItsTag() throws Exception {
        assertTrue(tagged(first));
        var entry = first.getEntryPoint();
        var body = new AddressSet(first.getBody());
        edit("delete", () -> program.getFunctionManager().removeFunction(entry));
        edit("create again", () -> program.getFunctionManager()
                .createFunction(null, entry, body, SourceType.USER_DEFINED));

        var recreated = program.getFunctionManager().getFunctionAt(entry);
        waitForCondition(() -> tagged(recreated), "the re-created function should be tagged again");
    }

    @Test
    public void aNewFunctionAtAnUnmappedAddressIsNotTagged() throws Exception {
        var entry = address(0x4300L);
        edit("create", () -> program.getFunctionManager()
                .createFunction(null, entry, new AddressSet(entry, address(0x43ffL)), SourceType.USER_DEFINED));

        Thread.sleep(500);
        assertFalse(tagged(program.getFunctionManager().getFunctionAt(entry)));
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

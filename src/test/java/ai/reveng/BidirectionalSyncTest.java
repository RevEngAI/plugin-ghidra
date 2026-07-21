package ai.reveng;

import ai.reveng.model.BatchRenameInputBody;
import ai.reveng.model.FunctionDataTypesList;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.DataTypePushResult;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.DataTypePushStatus;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionDataTypeUpdate;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.sync.LocalEditSyncService;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.jetbrains.annotations.Nullable;
import org.junit.Test;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Integration tests for the bidirectional push-back of local edits (PLU-322): reactive rename and
 * type pushes, and the analysis-sync name reconciliation (canonify + push).
 */
public class BidirectionalSyncTest extends RevEngMockableHeadedIntegrationTest {

    /// Mock API that records push-back calls and can script data-type push outcomes.
    private static class CapturingApi extends UnimplementedAPI {
        final List<BatchRenameInputBody> renameCalls = new ArrayList<>();
        final List<List<FunctionDataTypeUpdate>> typePushCalls = new ArrayList<>();
        final Deque<DataTypePushStatus> scriptedStatuses = new ArrayDeque<>();
        long currentVersion = 0;
        Map<String, String> canonicalMapping = Map.of();
        List<FunctionInfo> functions = List.of();

        @Override
        public AnalysisStatus status(TypedApiInterface.AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(TypedApiInterface.AnalysisID analysisID) {
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
        public Optional<VersionedFunctionTypes> getFunctionDataTypesWithVersion(TypedApiInterface.FunctionID functionID) {
            return Optional.of(new VersionedFunctionTypes(null, currentVersion));
        }

        @Override
        public List<DataTypePushResult> pushFunctionDataTypes(TypedApiInterface.AnalysisID analysisID, List<FunctionDataTypeUpdate> updates) {
            typePushCalls.add(updates);
            var status = scriptedStatuses.isEmpty() ? DataTypePushStatus.UPDATED : scriptedStatuses.poll();
            return updates.stream()
                    .map(u -> new DataTypePushResult(u.functionID(), status, null))
                    .toList();
        }

        @Override
        public Map<String, String> canonicalizeFunctionNames(List<String> names) {
            return canonicalMapping;
        }
    }

    private GhidraRevengService.AnalysedProgram register(GhidraRevengService service, Program program) throws Exception {
        var programWithID = service.registerAnalysisForProgram(program, new TypedApiInterface.AnalysisID(1));
        service.registerFinishedAnalysisForProgram(programWithID, TaskMonitor.DUMMY);
        return service.getAnalysedProgram(program).orElseThrow();
    }

    @Test
    public void pushFunctionRename_sendsLocalNameToPortal() throws Exception {
        var api = new CapturingApi();
        api.functions = List.of(new FunctionInfo(new TypedApiInterface.FunctionID(7), "orig", "orig", 0x4000L, 0x100));
        var service = new GhidraRevengService(api);

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createMemory("mem", "0x4000", 0x100);
        Function function = builder.createEmptyFunction(null, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();
        var analysed = register(service, program);

        program.withTransaction("rename", () -> {
            try {
                function.setName("user_chosen_name", SourceType.USER_DEFINED);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        service.pushFunctionRename(analysed, function);

        assertEquals(1, api.renameCalls.size());
        var item = api.renameCalls.get(0).getFunctions().get(0);
        assertEquals(7L, item.getFunctionId().longValue());
        assertEquals("user_chosen_name", item.getNewName());
    }

    @Test
    public void pushFunctionRename_qualifiesNameWithNamespace() throws Exception {
        var api = new CapturingApi();
        api.functions = List.of(new FunctionInfo(new TypedApiInterface.FunctionID(7), "orig", "orig", 0x4000L, 0x100));
        var service = new GhidraRevengService(api);

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createMemory("mem", "0x4000", 0x100);
        Function function = builder.createEmptyFunction(null, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();
        var analysed = register(service, program);

        program.withTransaction("rename in namespace", () -> {
            try {
                var namespace = program.getSymbolTable().createNameSpace(
                        program.getGlobalNamespace(), "MyClass", SourceType.USER_DEFINED);
                function.setParentNamespace(namespace);
                function.setName("method", SourceType.USER_DEFINED);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        service.pushFunctionRename(analysed, function);

        var item = api.renameCalls.get(0).getFunctions().get(0);
        assertEquals("MyClass::method", item.getNewName());
    }

    @Test
    public void pushFunctionTypes_retriesOnVersionConflictWithLatestVersion() throws Exception {
        var api = new CapturingApi();
        api.functions = List.of(new FunctionInfo(new TypedApiInterface.FunctionID(7), "orig", "orig", 0x4000L, 0x100));
        api.currentVersion = 42;
        api.scriptedStatuses.add(DataTypePushStatus.VERSION_CONFLICT);
        api.scriptedStatuses.add(DataTypePushStatus.UPDATED);
        var service = new GhidraRevengService(api);

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createMemory("mem", "0x4000", 0x100);
        Function function = builder.createEmptyFunction(null, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();
        var analysed = register(service, program);

        boolean pushed = service.pushFunctionTypes(analysed, function);

        assertTrue("push should succeed after retrying the conflict", pushed);
        assertEquals("one conflicting attempt then one successful attempt", 2, api.typePushCalls.size());
        assertEquals(7L, api.typePushCalls.get(0).get(0).functionID().value());
        assertEquals("version fetched before each attempt", 42L, api.typePushCalls.get(0).get(0).version());
    }

    private static final ReaiLoggingService NOOP_LOG = new ReaiLoggingService() {
        @Override public void info(String message) {}
        @Override public void warn(String message) {}
        @Override public void error(String message) {}
        @Override public void export(String targetDirectoryPath, String exportedFileName) {}
    };

    @Test
    public void reactiveListener_pushesTypesWhenLocalVariableEdited() throws Exception {
        var api = new CapturingApi();
        api.functions = List.of(new FunctionInfo(new TypedApiInterface.FunctionID(7), "orig", "orig", 0x4000L, 0x100));
        var service = new GhidraRevengService(api);

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createMemory("mem", "0x4000", 0x100);
        Function function = builder.createEmptyFunction(null, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();
        register(service, program);

        var syncService = new LocalEditSyncService(service, NOOP_LOG);
        try {
            syncService.attach(program);

            program.withTransaction("add local variable", () -> {
                try {
                    function.addLocalVariable(
                            new LocalVariableImpl("renamed_local", IntegerDataType.dataType, -0x8, program),
                            SourceType.USER_DEFINED);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            program.flushEvents();
            waitForSwing();

            long deadline = System.currentTimeMillis() + 5000;
            while (api.typePushCalls.isEmpty() && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }

            assertEquals("editing a variable pushes the function's types once", 1, api.typePushCalls.size());
            assertEquals(7L, api.typePushCalls.get(0).get(0).functionID().value());
        } finally {
            syncService.dispose();
        }
    }

    @Test
    public void syncAnalysisUpdates_canonicalizesInvalidRemoteNameAndPushesItBack() throws Exception {
        var api = new CapturingApi();
        api.functions = List.of(
                new FunctionInfo(new TypedApiInterface.FunctionID(1), "valid_name", "valid_name", 0x4000L, 0x100),
                new FunctionInfo(new TypedApiInterface.FunctionID(2), "bad name!", "bad name!", 0x5000L, 0x100));
        api.canonicalMapping = Map.of("bad name!", "bad_name");
        var service = new GhidraRevengService(api);

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createMemory("a", "0x4000", 0x100);
        builder.createMemory("b", "0x5000", 0x100);
        builder.createEmptyFunction(null, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        Function invalidNamed = builder.createEmptyFunction(null, "0x5000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();
        var analysed = register(service, program);

        var summary = service.syncAnalysisUpdates(analysed, TaskMonitor.DUMMY);

        assertEquals("invalid remote name is canonicalized locally", "bad_name", invalidNamed.getName());
        assertEquals(1, summary.canonicalizedNames());

        boolean canonicalPushedBack = api.renameCalls.stream()
                .flatMap(call -> call.getFunctions().stream())
                .anyMatch(item -> item.getFunctionId() == 2L && "bad_name".equals(item.getNewName()));
        assertTrue("the canonicalized name is pushed back to the portal", canonicalPushedBack);
    }
}

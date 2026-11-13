package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.CreateAnalysisDataTypesInputBody;
import ai.reveng.model.UpdateAnalysisDataTypesInputBody;
import ai.reveng.model.UpdateFunctionSignatureInputBody;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.UnresolvedDataTypesException;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.sync.LocalEditSyncService;
import ai.reveng.toolkit.ghidra.core.services.sync.UnpushedEdits;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/// Tests how {@link GhidraRevengService#pushFunctionTypes} composes the two halves of the write
/// path: batch data-type management, then one signature write per function.
public class PushFunctionTypesTest extends RevEngMockableHeadedIntegrationTest {

    private static final long FIRST_ADDRESS = 0x4000L;
    private static final long SECOND_ADDRESS = 0x4200L;

    /// Records every write and assigns ids to created types the way the server does.
    private static class RecordingApi extends UnimplementedAPI {
        final List<String> calls = new CopyOnWriteArrayList<>();
        final List<UpdateFunctionSignatureInputBody> signatures = new CopyOnWriteArrayList<>();
        final List<FunctionID> signedFunctions = new CopyOnWriteArrayList<>();
        final List<UpdateAnalysisDataTypesInputBody> updates = new CopyOnWriteArrayList<>();
        /// Types the server leaves out of its create response, so they never get an id.
        volatile Set<String> uncreatable = Set.of();
        private long nextId = 100;

        @Override
        public AnalysisStatus status(AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
            return List.of(
                    new FunctionInfo(new FunctionID(1), "first", "first", FIRST_ADDRESS, 0x100),
                    new FunctionInfo(new FunctionID(2), "second", "second", SECOND_ADDRESS, 0x100));
        }

        @Override
        public List<ServerDataType> listAnalysisDataTypes(AnalysisID analysisID, long offset, long limit) {
            calls.add("list");
            return List.of();
        }

        @Override
        public List<ServerDataType> createAnalysisDataTypes(AnalysisID analysisID,
                                                            CreateAnalysisDataTypesInputBody request) {
            calls.add("create");
            List<ServerDataType> created = new ArrayList<>();
            for (var entry : request.getDataTypes()) {
                Object instance = entry.getActualInstance();
                if (uncreatable.contains(string(instance, "getName"))) {
                    continue;
                }
                created.add(new ServerDataType(nextId++, string(instance, "getNamespace"),
                        string(instance, "getName"),
                        ServerDataType.Kind.fromJson(string(instance, "getKind")),
                        null, "USER", false, null, null, null));
            }
            return created;
        }

        @Override
        public List<ServerDataType> updateAnalysisDataTypes(AnalysisID analysisID,
                                                            UpdateAnalysisDataTypesInputBody request) {
            calls.add("update");
            updates.add(request);
            return List.of();
        }

        /// When true, answer a signature write the way the portal answers one for a function it never
        /// extracted a signature for.
        boolean noExtractedSignature = false;

        @Override
        public void updateFunctionSignature(AnalysisID analysisID, FunctionID functionID,
                                            UpdateFunctionSignatureInputBody signature) throws ApiException {
            calls.add("signature");
            if (noExtractedSignature) {
                throw new ApiException(404, "no signature to edit");
            }
            signedFunctions.add(functionID);
            signatures.add(signature);
        }

        private static String string(Object target, String method) {
            try {
                Object value = target.getClass().getMethod(method).invoke(target);
                return value == null ? null : value.toString();
            } catch (ReflectiveOperationException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private record Fixture(GhidraRevengService service,
                           RecordingApi api,
                           GhidraRevengService.AnalysedProgram analysedProgram,
                           List<Function> functions) {}

    /// Two functions sharing a struct, so the union of their closures is smaller than the sum.
    private Fixture twoFunctionsSharingAStruct() throws Exception {
        var api = new RecordingApi();
        var service = new GhidraRevengService(api);

        var builder = newX64Program("push");
        builder.createMemory("code", "0x4000", 0x400);
        var program = builder.getProgram();

        var shared = new StructureDataType("shared_state", 0);
        shared.add(new IntegerDataType(), "count", null);

        Function first = builder.createEmptyFunction("first", "0x4000", 0x100, new IntegerDataType(),
                new ParameterImpl("state", new PointerDataType(shared), program));
        Function second = builder.createEmptyFunction("second", "0x4200", 0x100, new IntegerDataType(),
                new ParameterImpl("state", new PointerDataType(shared), program));

        var programWithID = service.registerAnalysisForProgram(program, new AnalysisID(1));
        var analysedProgram = service.registerFinishedAnalysisForProgram(programWithID, TaskMonitor.DUMMY);

        // Only what the push itself does is of interest, not what attaching the analysis did.
        api.calls.clear();
        return new Fixture(service, api, analysedProgram, List.of(first, second));
    }

    /// The type pass is a batch and the signature write is not, which is the whole reason the two
    /// services are separate: several functions cost one resolve over the union of their types and
    /// then one write each.
    @Test
    public void multiFunctionPushResolvesTypesOnceThenWritesEachSignature() throws Exception {
        var fixture = twoFunctionsSharingAStruct();

        int pushed = fixture.service().pushFunctionTypes(fixture.analysedProgram(), fixture.functions())
                .signaturesWritten();

        assertEquals("both signatures written", 2, pushed);
        assertEquals("one catalogue read for the whole push", 1, count(fixture.api(), "list"));
        assertEquals("one create pass over the union of both closures", 1, count(fixture.api(), "create"));
        assertEquals("one definition pass", 1, count(fixture.api(), "update"));
        assertEquals("and one signature write per function", 2, count(fixture.api(), "signature"));
        assertEquals(List.of(new FunctionID(1), new FunctionID(2)), fixture.api().signedFunctions);

        assertEquals("every type is resolved before any signature names one",
                List.of("list", "create", "update", "signature", "signature"), fixture.api().calls);
    }

    /// The signature names ids the type pass just minted, not names.
    @Test
    public void writtenSignaturesNameTheIdsTheTypePassMinted() throws Exception {
        var fixture = twoFunctionsSharingAStruct();
        fixture.service().pushFunctionTypes(fixture.analysedProgram(), fixture.functions());

        var signature = fixture.api().signatures.get(0);
        assertEquals(1, signature.getParameters().size());
        assertEquals(Long.valueOf(0), signature.getParameters().get(0).getOrdinal());
        assertEquals("state", signature.getParameters().get(0).getName());
        assertNotNull("the parameter's type resolved to an id",
                signature.getParameters().get(0).getDataTypeId());
        assertNotNull("so did the return type", signature.getReturnDataTypeId());
    }

    /// A second push of the same functions must resolve everything it created the first time round
    /// rather than creating it again — this is the reactive case, which repeats on every edit.
    @Test
    public void pushingTwiceCreatesNothingTheSecondTime() throws Exception {
        var fixture = twoFunctionsSharingAStruct();

        fixture.service().pushFunctionTypes(fixture.analysedProgram(), fixture.functions());
        int createsAfterFirst = count(fixture.api(), "create");
        fixture.service().pushFunctionTypes(fixture.analysedProgram(), fixture.functions());

        assertTrue("the first push created the analysis' types", createsAfterFirst > 0);
        assertEquals("the second push resolved them", createsAfterFirst, count(fixture.api(), "create"));
    }

    /// The reactive push reports what it achieved, because the two halves fail independently: the
    /// portal declines a signature write for a function it never extracted one for, and the types
    /// have gone up regardless by then.
    @Test
    public void singleFunctionPushReportsTheSignatureWrite() throws Exception {
        var fixture = twoFunctionsSharingAStruct();

        var outcome = fixture.service().pushFunctionTypes(
                fixture.analysedProgram(), fixture.functions().get(0));

        assertEquals(GhidraRevengService.TypePushOutcome.SIGNATURE_WRITTEN, outcome);
    }

    @Test
    public void singleFunctionPushReportsTypesOnlyWhenThePortalHasNoExtractedSignature() throws Exception {
        var fixture = twoFunctionsSharingAStruct();
        fixture.api().noExtractedSignature = true;

        var outcome = fixture.service().pushFunctionTypes(
                fixture.analysedProgram(), fixture.functions().get(0));

        assertEquals("a declined signature write must not hide the types that were written",
                GhidraRevengService.TypePushOutcome.TYPES_ONLY, outcome);
        assertTrue("the types still went up", count(fixture.api(), "create") > 0);
    }

    @Test
    public void singleFunctionPushReportsAFunctionTheAnalysisDoesNotKnow() throws Exception {
        var fixture = twoFunctionsSharingAStruct();
        // The mock analysis reports only the two functions the fixture matched, so a third one —
        // an unanalysed function, or one Ghidra found and the server did not — has no FunctionID.
        var program = fixture.analysedProgram().program();
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x4300);
        Function unmatched = program.withTransaction("add an unmatched function", () -> {
            new CreateFunctionCmd("unmatched", address, null, SourceType.USER_DEFINED).applyTo(program);
            return program.getFunctionManager().getFunctionAt(address);
        });
        assertNotNull("the fixture needs a function outside the analysis", unmatched);

        var outcome = fixture.service().pushFunctionTypes(fixture.analysedProgram(), unmatched);

        assertEquals(GhidraRevengService.TypePushOutcome.NOT_MATCHED, outcome);
    }

    /// A function whose parameter points at a struct with `members` members of distinct struct types,
    /// so its closure holds a little over `members` types.
    private static Function functionReachingStructs(ghidra.program.database.ProgramBuilder builder, String name,
                                                    String address, int members) throws Exception {
        var state = new StructureDataType(name + "_state", 0);
        for (int i = 0; i < members; i++) {
            state.add(new StructureDataType(name + "_member_" + i, 4), "m" + i, null);
        }
        return builder.createEmptyFunction(name, address, 0x100, new IntegerDataType(),
                new ParameterImpl("state", new PointerDataType(state), builder.getProgram()));
    }

    /// Two functions that each reach about 300 types, under the 500-type closure cap on their own
    /// but over it together. Capping the union left some of the second function's types without an
    /// id, and its struct then went up with null member types, erasing them on the portal.
    @Test
    public void aBatchOverTheClosureCapSendsNoNullTypeIds() throws Exception {
        var api = new RecordingApi();
        var service = new GhidraRevengService(api);
        var builder = newX64Program("push");
        builder.createMemory("code", "0x4000", 0x400);
        Function first = functionReachingStructs(builder, "first", "0x4000", 300);
        Function second = functionReachingStructs(builder, "second", "0x4200", 300);
        var programWithID = service.registerAnalysisForProgram(builder.getProgram(), new AnalysisID(1));
        var analysedProgram = service.registerFinishedAnalysisForProgram(programWithID, TaskMonitor.DUMMY);

        var push = service.pushFunctionTypes(analysedProgram, List.of(first, second));

        assertEquals("nothing held back: " + push.withheld(), 0, push.withheld().size());
        assertEquals("both signatures written", 2, push.signaturesWritten());
        List<Long> referenced = new ArrayList<>();
        java.util.Map<String, Integer> stateMembers = new java.util.HashMap<>();
        for (var request : api.updates) {
            for (var entry : request.getDataTypes()) {
                referenced.addAll(referencedIds(entry.getActualInstance()));
                if (entry.getActualInstance() instanceof ai.reveng.model.UpdateStructDataType struct) {
                    stateMembers.put(struct.getName(), struct.getDefinition().getMembers().size());
                }
            }
        }
        assertEquals("both structs were written in full",
                java.util.Map.of("first_state", 300, "second_state", 300), stateMembers);
        assertFalse("no type write names a null type", referenced.contains(null));
        for (var signature : api.signatures) {
            assertNotNull(signature.getReturnDataTypeId());
            signature.getParameters().forEach(parameter -> assertNotNull(parameter.getDataTypeId()));
        }
    }

    /// Every `data_type_id` an update body refers to, nulls included.
    private static List<Long> referencedIds(Object update) {
        List<Long> ids = new ArrayList<>();
        if (update instanceof ai.reveng.model.UpdateStructDataType struct) {
            struct.getDefinition().getMembers().forEach(member -> ids.add(member.getDataTypeId()));
        } else if (update instanceof ai.reveng.model.UpdateUnionDataType union) {
            union.getDefinition().getMembers().forEach(member -> ids.add(member.getDataTypeId()));
        } else if (update instanceof ai.reveng.model.UpdatePointerDataType pointer) {
            ids.add(pointer.getDefinition().getPointeeDataTypeId());
        } else if (update instanceof ai.reveng.model.UpdateTypedefDataType typedef) {
            ids.add(typedef.getDefinition().getTargetDataTypeId());
        } else if (update instanceof ai.reveng.model.UpdateArrayDataType array) {
            ids.add(array.getDefinition().getElementDataTypeId());
        } else if (update instanceof ai.reveng.model.UpdateFunctionDataType function) {
            function.getDefinition().getParameters().forEach(parameter -> ids.add(parameter.getDataTypeId()));
            ids.add(function.getDefinition().getReturnDataTypeId());
        }
        return ids;
    }

    /// The first function takes a pointer to a struct the server never gives an id; the second
    /// only takes an int.
    private Fixture oneFunctionWithAnUnresolvableType() throws Exception {
        var api = new RecordingApi();
        api.uncreatable = Set.of("orphan_t");
        var service = new GhidraRevengService(api);
        var builder = newX64Program("push");
        builder.createMemory("code", "0x4000", 0x400);
        var program = builder.getProgram();
        var orphan = new StructureDataType("orphan_t", 0);
        orphan.add(new IntegerDataType(), "count", null);
        Function first = builder.createEmptyFunction("first", "0x4000", 0x100, new IntegerDataType(),
                new ParameterImpl("state", new PointerDataType(orphan), program));
        Function second = builder.createEmptyFunction("second", "0x4200", 0x100, new IntegerDataType(),
                new ParameterImpl("count", new IntegerDataType(), program));
        var programWithID = service.registerAnalysisForProgram(program, new AnalysisID(1));
        var analysedProgram = service.registerFinishedAnalysisForProgram(programWithID, TaskMonitor.DUMMY);
        api.calls.clear();
        return new Fixture(service, api, analysedProgram, List.of(first, second));
    }

    @Test
    public void aFunctionReachingATypeWithNoIdIsNotSentAndStaysUnpushed() throws Exception {
        var fixture = oneFunctionWithAnUnresolvableType();
        var program = fixture.analysedProgram().program();
        Function first = fixture.functions().get(0);
        Function second = fixture.functions().get(1);
        fixture.functions().forEach(function ->
                UnpushedEdits.mark(program, UnpushedEdits.Kind.TYPES, function.getEntryPoint()));

        var flush = fixture.service().pushUnpushedEdits(fixture.analysedProgram());

        assertEquals("only the second signature went up", List.of(new FunctionID(2)), fixture.api().signedFunctions);
        assertTrue("the held-back edit is still marked",
                UnpushedEdits.isMarked(program, UnpushedEdits.Kind.TYPES, first.getEntryPoint()));
        assertFalse("the other one went up",
                UnpushedEdits.isMarked(program, UnpushedEdits.Kind.TYPES, second.getEntryPoint()));
        assertEquals(1, flush.pushed());
        assertEquals(1, flush.rejected().size());
        var rejected = flush.rejected().get(0);
        assertTrue(rejected.edit(), rejected.edit().contains("\"first\""));
        assertTrue(rejected.error().getMessage(), rejected.error().getMessage().contains("orphan_t"));
        for (var request : fixture.api().updates) {
            for (var entry : request.getDataTypes()) {
                assertFalse("no type write names a null type",
                        referencedIds(entry.getActualInstance()).contains(null));
            }
        }
    }

    @Test
    public void singleFunctionPushThrowsWhenATypeHasNoId() throws Exception {
        var fixture = oneFunctionWithAnUnresolvableType();
        try {
            fixture.service().pushFunctionTypes(fixture.analysedProgram(), fixture.functions().get(0));
            fail("the push should have been held back");
        } catch (UnresolvedDataTypesException e) {
            assertTrue(e.typeNames().toString(), e.typeNames().contains("orphan_t"));
        }
        assertTrue("no signature was sent", fixture.api().signedFunctions.isEmpty());
    }

    /// The reactive push holds the edit back, keeps it marked, and reports it like any other edit the
    /// portal did not take.
    @Test
    public void aReactiveEditReachingATypeWithNoIdIsReportedAndKept() throws Exception {
        var fixture = oneFunctionWithAnUnresolvableType();
        var program = fixture.analysedProgram().program();
        Function second = fixture.functions().get(1);
        List<String> warnings = new CopyOnWriteArrayList<>();
        var sync = new LocalEditSyncService(fixture.service(), new ReaiLoggingService() {
            @Override public void info(String message) {}
            @Override public void warn(String message) {}
            @Override public void error(String message) {}
        }, (message, warning) -> {
            if (warning) {
                warnings.add(message);
            }
        }, List.of(Duration.ofHours(1)));
        sync.attach(program);
        try {
            var orphan = new StructureDataType("orphan_t", 0);
            orphan.add(new IntegerDataType(), "count", null);
            program.withTransaction("retype", () ->
                    second.setReturnType(new PointerDataType(orphan), SourceType.USER_DEFINED));
            program.flushEvents();

            waitForCondition(() -> !warnings.isEmpty(), "the held-back edit should be reported");
            assertTrue(warnings.get(0), warnings.get(0).contains("did not take"));
            assertTrue("the edit is kept for the next sync",
                    UnpushedEdits.isMarked(program, UnpushedEdits.Kind.TYPES, second.getEntryPoint()));
            assertFalse("its signature was never sent", fixture.api().signedFunctions.contains(new FunctionID(2)));
        } finally {
            sync.dispose();
        }
    }

    private static int count(RecordingApi api, String call) {
        return (int) api.calls.stream().filter(call::equals).count();
    }
}

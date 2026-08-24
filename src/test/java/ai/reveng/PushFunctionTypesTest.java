package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.CreateAnalysisDataTypesInputBody;
import ai.reveng.model.UpdateAnalysisDataTypesInputBody;
import ai.reveng.model.UpdateFunctionSignatureInputBody;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/// Tests how {@link GhidraRevengService#pushFunctionTypes} composes the two halves of the write
/// path: batch data-type management, then one signature write per function.
public class PushFunctionTypesTest extends RevEngMockableHeadedIntegrationTest {

    private static final long FIRST_ADDRESS = 0x4000L;
    private static final long SECOND_ADDRESS = 0x4200L;

    /// Records every write and assigns ids to created types the way the server does.
    private static class RecordingApi extends UnimplementedAPI {
        final List<String> calls = new ArrayList<>();
        final List<UpdateFunctionSignatureInputBody> signatures = new ArrayList<>();
        final List<FunctionID> signedFunctions = new ArrayList<>();
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

        int pushed = fixture.service().pushFunctionTypes(fixture.analysedProgram(), fixture.functions());

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

    private static int count(RecordingApi api, String call) {
        return (int) api.calls.stream().filter(call::equals).count();
    }
}

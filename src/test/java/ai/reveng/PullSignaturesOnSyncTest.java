package ai.reveng;

import ai.reveng.model.BatchFunctionSignatureEntry;
import ai.reveng.model.BatchRenameInputBody;
import ai.reveng.model.CreateAnalysisDataTypesInputBody;
import ai.reveng.model.SignatureParameterEntry;
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
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/// The portal -> Ghidra half of "Sync With Portal": the signature the portal holds, and the data
/// types it names, land on the matched function.
///
/// The case that matters most here is the second sync. An applied signature is stamped
/// {@link SourceType#ANALYSIS}, so a guard of "apply only to a default signature" made every sync
/// after the first a no-op and a portal-side edit could never arrive.
public class PullSignaturesOnSyncTest extends RevEngMockableHeadedIntegrationTest {

    private static final long ADDRESS = 0x4000L;
    private static final long FUNCTION_ID = 7;
    /// The local function carries the portal's name from the start, so the name reconciliation in
    /// sync has nothing to do and only the signature half of it is under test.
    private static final String FUNCTION_NAME = "target";

    private static final ReaiLoggingService NOOP_LOG = new ReaiLoggingService() {
        @Override public void info(String message) {}
        @Override public void warn(String message) {}
        @Override public void error(String message) {}
    };

    /// Serves whatever signature the test currently wants the portal to hold.
    private static class SignatureApi extends UnimplementedAPI {
        /// The name of the return type the portal reports, or null when it holds no signature.
        String remoteReturnType;
        /// The function name carried on the signature entry, which need not be the local name.
        String remoteSignatureName = FUNCTION_NAME;
        /// The name the portal gives the single parameter, or null for a parameter it does not name.
        String remoteParameterName = "count";
        /// What the portal reports as `has_signature`; the generated model lets a JSON null through.
        Boolean remoteHasSignature = true;
        /// Calls of {@link #getFunctionInfo} after which the portal stops listing the function.
        int functionInfoCallsBeforeRemoval = Integer.MAX_VALUE;
        /// The `source_type` the portal reports for its signature.
        BatchFunctionSignatureEntry.SourceTypeEnum remoteSourceType;
        /// When true the portal holds only the `undefined f(void)` placeholder extraction stores for a
        /// function Ghidra had no signature for.
        boolean remotePlaceholder = false;
        /// Every function a signature was pushed for.
        final List<FunctionID> pushedSignatures = new ArrayList<>();
        private long nextDataTypeId = 100;

        @Override
        public AnalysisStatus status(AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
            if (functionInfoCallsBeforeRemoval-- <= 0) {
                return List.of();
            }
            return List.of(new FunctionInfo(
                    new FunctionID(FUNCTION_ID), FUNCTION_NAME, FUNCTION_NAME, ADDRESS, 0x100));
        }

        @Override
        public FunctionSignatureBatch listFunctionSignatures(List<FunctionID> functionIDs,
                                                            boolean includeDataTypes) {
            var entry = new BatchFunctionSignatureEntry();
            entry.setAnalysisId(1L);
            entry.setFunctionId(FUNCTION_ID);
            entry.setFunctionName(remoteSignatureName);
            entry.setHasSignature(remoteHasSignature);
            if (remotePlaceholder) {
                entry.setSourceType(BatchFunctionSignatureEntry.SourceTypeEnum.SYSTEM);
                entry.setReturnDataTypeId(0L);
                entry.setParameters(List.of());
                var undefined = new ServerDataType(0L, "", "undefined", ServerDataType.Kind.BASE,
                        1L, "AUTO", false, null, null, null);
                return new FunctionSignatureBatch(List.of(entry),
                        Map.of(new AnalysisID(1), List.of(undefined)));
            }
            if (remoteReturnType == null) {
                return FunctionSignatureBatch.empty();
            }
            entry.setSourceType(remoteSourceType);
            entry.setReturnDataTypeId(1L);
            var parameter = new SignatureParameterEntry();
            parameter.setOrdinal(0L);
            parameter.setName(remoteParameterName);
            parameter.setDataTypeId(1L);
            parameter.setBitLength(32L);
            entry.setParameters(List.of(parameter));
            var returnType = new ServerDataType(1L, "", remoteReturnType, ServerDataType.Kind.BASE,
                    4L, "AUTO", false, null, null, null);
            return new FunctionSignatureBatch(List.of(entry),
                    Map.of(new AnalysisID(1), List.of(returnType)));
        }

        @Override
        public long batchRenameFunctions(BatchRenameInputBody request) {
            // A name pushback is not what these tests are about; accept and ignore it.
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

    private record Fixture(GhidraRevengService service, GhidraRevengService.AnalysedProgram analysed,
                           Function function) {}

    /// Attach an analysis that holds no signature yet, so the attach-time pull leaves the local
    /// signature alone and each test can decide what the portal gains afterwards.
    private Fixture attachWithoutRemoteSignature(SignatureApi api) throws Exception {
        return attachWithoutRemoteSignature(api, SourceType.ANALYSIS);
    }

    private Fixture attachWithoutRemoteSignature(SignatureApi api, SourceType localSignatureSource)
            throws Exception {
        var service = new GhidraRevengService(api);
        var builder = newX64Program();
        builder.createMemory("mem", "0x4000", 0x100);
        Function function = builder.createEmptyFunction(
                FUNCTION_NAME, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();
        // ProgramBuilder stamps a new function's signature USER_DEFINED, which the pull is required
        // to leave alone. A real stripped binary's signature comes from Ghidra's own analysis, and
        // that is the case under test: it is neither hand-written nor default, so the old
        // "default signatures only" guard skipped exactly these.
        program.withTransaction("set the local signature's source", () ->
                function.setSignatureSource(localSignatureSource));

        var programWithID = service.registerAnalysisForProgram(program, new AnalysisID(1));
        service.registerFinishedAnalysisForProgram(programWithID, TaskMonitor.DUMMY);
        return new Fixture(service, service.getAnalysedProgram(program).orElseThrow(), function);
    }

    @Test
    public void appliesThePortalSignature() throws Exception {
        var api = new SignatureApi();
        var fixture = attachWithoutRemoteSignature(api);

        api.remoteReturnType = "int";
        var summary = fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);

        assertEquals("sync should report the signature it applied", 1, summary.appliedSignatures());
        assertEquals("the portal's return type should be on the local function",
                "int", fixture.function().getReturnType().getName());
    }

    @Test
    public void appliesTheNewSignatureWhenThePortalChangesItAfterAnEarlierSync() throws Exception {
        var api = new SignatureApi();
        var fixture = attachWithoutRemoteSignature(api);

        api.remoteReturnType = "int";
        fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);
        assertEquals("int", fixture.function().getReturnType().getName());

        // The analyst edits the signature in the portal; a second sync has to bring that down even
        // though the first sync already put a signature on the function.
        api.remoteReturnType = "char";
        var summary = fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);

        assertEquals("the changed signature should be applied by the second sync",
                1, summary.appliedSignatures());
        assertEquals("char", fixture.function().getReturnType().getName());
    }

    @Test
    public void appliesNothingWhenThePortalSignatureIsAlreadyTheLocalOne() throws Exception {
        var api = new SignatureApi();
        var fixture = attachWithoutRemoteSignature(api);

        api.remoteReturnType = "int";
        fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);
        var summary = fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);

        assertEquals("an unchanged signature should not be re-applied", 0, summary.appliedSignatures());
        assertEquals("int", fixture.function().getReturnType().getName());
    }

    /// The portal names a function that Ghidra still calls `FUN_...`, and sync applies names in a
    /// separate pass. If the signature comparison counts that name difference, every function differs
    /// on every sync, is re-applied, and is reported for ever.
    @Test
    public void appliesNothingASecondTimeWhenOnlyTheSignaturesFunctionNameDiffers() throws Exception {
        var api = new SignatureApi();
        var fixture = attachWithoutRemoteSignature(api);

        api.remoteSignatureName = "a_name_ghidra_does_not_have";
        api.remoteReturnType = "int";
        var first = fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);
        var second = fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);

        assertEquals("the changed return type is applied once", 1, first.appliedSignatures());
        assertEquals("and not again, because only the signature's function name differs",
                0, second.appliedSignatures());
    }

    /// A parameter the portal does not name must not read as a difference either: Ghidra names an
    /// unnamed parameter `param_N` on apply, so counting that would reintroduce the same loop.
    @Test
    public void appliesNothingASecondTimeWhenThePortalLeavesAParameterUnnamed() throws Exception {
        var api = new SignatureApi();
        var fixture = attachWithoutRemoteSignature(api);

        api.remoteReturnType = "int";
        api.remoteParameterName = null;
        fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);
        var second = fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);

        assertEquals(0, second.appliedSignatures());
    }

    @Test
    public void leavesASignatureTheAnalystWroteAlone() throws Exception {
        var api = new SignatureApi();
        var fixture = attachWithoutRemoteSignature(api);
        var function = fixture.function();
        var program = fixture.analysed().program();

        program.withTransaction("set a user-defined signature", () -> {
            function.setReturnType(new CharDataType(), SourceType.USER_DEFINED);
            function.setSignatureSource(SourceType.USER_DEFINED);
        });

        api.remoteReturnType = "int";
        var summary = fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);

        assertEquals("a signature the analyst set must not be overwritten by the portal's",
                0, summary.appliedSignatures());
        assertEquals("char", function.getReturnType().getName());
    }

    /// Extraction stores `undefined f(void)` for every function Ghidra had nothing for. Applying it
    /// erased real DWARF and analysis signatures on every QA binary.
    @Test
    public void doesNotApplyThePortalsPlaceholderSignature() throws Exception {
        var api = new SignatureApi();
        api.remotePlaceholder = true;
        var fixture = attachWithoutRemoteSignature(api, SourceType.IMPORTED);

        var summary = fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);

        assertEquals(0, summary.appliedSignatures());
        assertEquals("the local signature survives attach and sync",
                "undefined8", fixture.function().getReturnType().getName());
    }

    /// A placeholder is a stored row the signature PUT accepts, so it is exactly where the better
    /// local signature can be pushed.
    @Test
    public void pushesTheLocalSignatureWhenThePortalOnlyHasAPlaceholder() throws Exception {
        var api = new SignatureApi();
        api.remotePlaceholder = true;
        var fixture = attachWithoutRemoteSignature(api, SourceType.IMPORTED);

        var summary = fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);

        assertEquals(1, summary.pushedTypeSets());
        assertEquals(List.of(new FunctionID(FUNCTION_ID)), api.pushedSignatures);
    }

    /// A function Ghidra knows nothing about has nothing worth pushing over the placeholder.
    @Test
    public void doesNotPushADefaultLocalSignatureOverAPlaceholder() throws Exception {
        var api = new SignatureApi();
        api.remotePlaceholder = true;
        var fixture = attachWithoutRemoteSignature(api, SourceType.DEFAULT);

        fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);

        assertTrue(api.pushedSignatures.isEmpty());
    }

    /// A signature the server extracted itself is what server-side Ghidra worked out, so it never
    /// replaces one local analysis inferred or debug info supplied.
    @Test
    public void aSignatureTheServerExtractedDoesNotReplaceALocalAnalysisOne() throws Exception {
        var api = new SignatureApi();
        api.remoteSourceType = BatchFunctionSignatureEntry.SourceTypeEnum.SYSTEM;
        var fixture = attachWithoutRemoteSignature(api);

        api.remoteReturnType = "int";
        var summary = fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);

        assertEquals(0, summary.appliedSignatures());
        assertEquals("undefined8", fixture.function().getReturnType().getName());
    }

    @Test
    public void aSignatureTheServerExtractedStillFillsADefaultLocalOne() throws Exception {
        var api = new SignatureApi();
        api.remoteSourceType = BatchFunctionSignatureEntry.SourceTypeEnum.SYSTEM;
        var fixture = attachWithoutRemoteSignature(api, SourceType.DEFAULT);

        api.remoteReturnType = "int";
        var summary = fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);

        assertEquals(1, summary.appliedSignatures());
        assertEquals("int", fixture.function().getReturnType().getName());
    }

    /// An edit made in the portal still beats what Ghidra inferred.
    @Test
    public void aSignatureEditedInThePortalReplacesALocalAnalysisOne() throws Exception {
        var api = new SignatureApi();
        api.remoteSourceType = BatchFunctionSignatureEntry.SourceTypeEnum.USER;
        var fixture = attachWithoutRemoteSignature(api);

        api.remoteReturnType = "int";
        var summary = fixture.service().syncAnalysisUpdates(fixture.analysed(), TaskMonitor.DUMMY, NOOP_LOG);

        assertEquals(1, summary.appliedSignatures());
        assertEquals("int", fixture.function().getReturnType().getName());
    }

    @Test
    public void nullHasSignatureIsTreatedAsNoSignature() throws Exception {
        var api = new SignatureApi();
        api.remoteReturnType = "int";
        api.remoteHasSignature = null;

        var fixture = attachWithoutRemoteSignature(api);

        assertEquals("undefined8", fixture.function().getReturnType().getName());
    }

    /// The function list can change between the attach-time association and the pull that follows.
    @Test
    public void functionNoLongerListedByThePortalIsSkipped() throws Exception {
        var api = new SignatureApi();
        api.functionInfoCallsBeforeRemoval = 1;

        var fixture = attachWithoutRemoteSignature(api);

        assertEquals(FUNCTION_NAME, fixture.function().getName());
    }

    /// A failure while pulling must not leave the program's transaction open.
    @Test
    public void failedPullDoesNotLeakTransaction() throws Exception {
        var api = new SignatureApi() {
            int calls = 0;

            @Override
            public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
                // The pull runs after the attach-time association; make it fail there.
                if (calls++ == 0) {
                    return super.getFunctionInfo(analysisID);
                }
                throw new RuntimeException("simulated failure");
            }
        };
        var service = new GhidraRevengService(api);
        var builder = newX64Program();
        builder.createMemory("mem", "0x4000", 0x100);
        builder.createEmptyFunction(FUNCTION_NAME, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();
        var programWithID = service.registerAnalysisForProgram(program, new AnalysisID(1));

        try {
            service.registerFinishedAnalysisForProgram(programWithID, TaskMonitor.DUMMY);
        } catch (RuntimeException expected) {
            // the transaction is what matters
        }

        assertNull("transaction must be closed", program.getCurrentTransactionInfo());
    }
}

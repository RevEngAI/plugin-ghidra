package ai.reveng;

import ai.reveng.model.BatchFunctionSignatureEntry;
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
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

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

        @Override
        public AnalysisStatus status(AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
            return List.of(new FunctionInfo(
                    new FunctionID(FUNCTION_ID), FUNCTION_NAME, FUNCTION_NAME, ADDRESS, 0x100));
        }

        @Override
        public FunctionSignatureBatch listFunctionSignatures(List<FunctionID> functionIDs,
                                                            boolean includeDataTypes) {
            if (remoteReturnType == null) {
                return FunctionSignatureBatch.empty();
            }
            var entry = new BatchFunctionSignatureEntry();
            entry.setAnalysisId(1L);
            entry.setFunctionId(FUNCTION_ID);
            entry.setFunctionName(FUNCTION_NAME);
            entry.setHasSignature(true);
            entry.setReturnDataTypeId(1L);
            entry.setParameters(List.of());
            var returnType = new ServerDataType(1L, "", remoteReturnType, ServerDataType.Kind.BASE,
                    4L, "AUTO", false, null, null, null);
            return new FunctionSignatureBatch(List.of(entry),
                    Map.of(new AnalysisID(1), List.of(returnType)));
        }

        @Override
        public void batchRenameFunctions(BatchRenameInputBody request) {
            // A name pushback is not what these tests are about; accept and ignore it.
        }
    }

    private record Fixture(GhidraRevengService service, GhidraRevengService.AnalysedProgram analysed,
                           Function function) {}

    /// Attach an analysis that holds no signature yet, so the attach-time pull leaves the local
    /// signature alone and each test can decide what the portal gains afterwards.
    private Fixture attachWithoutRemoteSignature(SignatureApi api) throws Exception {
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
        program.withTransaction("mark the signature analysis-derived", () ->
                function.setSignatureSource(SourceType.ANALYSIS));

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
}

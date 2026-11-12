package ai.reveng;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.FunctionSignatureBatch;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/// A load whose pull fails part way must leave the program as it was, and loading it again must work.
public class IncompleteLoadTest extends RevEngMockableHeadedIntegrationTest {

    private static final String REVENG_TAG = "REVENGAI_SYNCED";
    private static final String REVENG_BOOKMARK_TYPE = "RevEng.AI";

    /// Serves one function, and fails the signature request while `portalDown` is set, as a 503 would.
    private static class FlakyPortal extends UnimplementedAPI {
        boolean portalDown = true;

        @Override
        public AnalysisStatus status(TypedApiInterface.AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(TypedApiInterface.AnalysisID analysisID) {
            return List.of(
                    new FunctionInfo(new TypedApiInterface.FunctionID(1), "portal_name", "portal_name", 0x4000L, 0x100)
            );
        }

        @Override
        public FunctionSignatureBatch listFunctionSignatures(List<TypedApiInterface.FunctionID> functionIDs,
                                                             boolean includeDataTypes) {
            if (portalDown) {
                throw new RuntimeException("HTTP 503 — Service Unavailable");
            }
            return FunctionSignatureBatch.empty();
        }
    }

    @Test
    public void failedPullLeavesProgramUnattachedAndRetrySucceeds() throws Exception {
        var portal = new FlakyPortal();
        var service = new GhidraRevengService(portal);
        var builder = newX64Program();
        builder.createMemory("matched", "0x4000", 0x100);
        Function function = builder.createEmptyFunction(null, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();
        var originalName = function.getName();

        var programWithID = service.registerAnalysisForProgram(program, new TypedApiInterface.AnalysisID(1));
        var error = assertThrows(RuntimeException.class,
                () -> service.registerFinishedAnalysisForProgram(programWithID, TaskMonitor.DUMMY));
        assertEquals("HTTP 503 — Service Unavailable", error.getMessage());

        assertTrue("the analysis should stay associated so the load can be retried",
                service.getKnownProgram(program).isPresent());
        assertTrue("a program whose pull failed must not count as analysed",
                service.getAnalysedProgram(program).isEmpty());
        assertFalse("the function should not be marked as synced", hasRevEngTag(function));
        assertEquals("the function should not keep a RevEng bookmark",
                0, program.getBookmarkManager().getBookmarks(function.getEntryPoint(), REVENG_BOOKMARK_TYPE).length);
        assertEquals("nothing was pulled, so the name is unchanged", originalName, function.getName());

        portal.portalDown = false;
        var analysedProgram = service.registerFinishedAnalysisForProgram(programWithID, TaskMonitor.DUMMY);

        assertTrue("the retried load should attach the program", service.getAnalysedProgram(program).isPresent());
        assertEquals(1, analysedProgram.getIDForFunction(function).orElseThrow().functionID().value());
        assertTrue("the function should be marked as synced", hasRevEngTag(function));
        assertEquals("the retried load should pull the portal name", "portal_name", function.getName());
    }

    @Test
    public void loadingAnAlreadyAttachedProgramAgainReplacesTheAssociation() throws Exception {
        var portal = new FlakyPortal();
        portal.portalDown = false;
        var service = new GhidraRevengService(portal);
        var builder = newX64Program();
        builder.createMemory("matched", "0x4000", 0x100);
        Function function = builder.createEmptyFunction(null, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();

        var programWithID = service.registerAnalysisForProgram(program, new TypedApiInterface.AnalysisID(1));
        service.registerFinishedAnalysisForProgram(programWithID, TaskMonitor.DUMMY);
        // Programs saved half attached before this was fixed still carry the property maps
        var analysedProgram = service.registerFinishedAnalysisForProgram(programWithID, TaskMonitor.DUMMY);

        assertEquals(1, analysedProgram.getIDForFunction(function).orElseThrow().functionID().value());
        assertEquals("the function should carry exactly one RevEng bookmark",
                1, program.getBookmarkManager().getBookmarks(function.getEntryPoint(), REVENG_BOOKMARK_TYPE).length);
        assertTrue(hasRevEngTag(function));
    }

    private static boolean hasRevEngTag(Function function) {
        return function.getTags().stream().anyMatch(tag -> tag.getName().equals(REVENG_TAG));
    }
}

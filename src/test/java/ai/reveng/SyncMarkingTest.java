package ai.reveng;

import ai.reveng.model.FunctionDataTypesList;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import org.jetbrains.annotations.Nullable;
import org.junit.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SyncMarkingTest extends RevEngMockableHeadedIntegrationTest {

    private static final String REVENG_TAG = "REVENGAI_MATCH";
    private static final String REVENG_BOOKMARK_TYPE = "RevEng.AI";

    @Test
    public void testSyncMarksMatchedFunctions() throws Exception {
        var service = new GhidraRevengService(new UnimplementedAPI() {
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
            public FunctionDataTypesList listFunctionDataTypesForAnalysis(TypedApiInterface.AnalysisID analysisID, @Nullable List<TypedApiInterface.FunctionID> ids) {
                try {
                    return FunctionDataTypesList.fromJson("{\"total_count\":0,\"total_data_types_count\":0,\"items\":[]}");
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        });

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createMemory("matched", "0x4000", 0x100);
        builder.createMemory("unmatched", "0x5000", 0x100);
        Function matchedFunc = builder.createEmptyFunction(null, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        Function unmatchedFunc = builder.createEmptyFunction(null, "0x5000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();

        var programWithID = service.registerAnalysisForProgram(program, new TypedApiInterface.AnalysisID(1));
        service.registerFinishedAnalysisForProgram(programWithID, ghidra.util.task.TaskMonitor.DUMMY);

        assertTrue("matched function should have the RevEng tag", hasRevEngTag(matchedFunc));
        assertTrue("matched function should have a RevEng bookmark",
                program.getBookmarkManager().getBookmarks(matchedFunc.getEntryPoint(), REVENG_BOOKMARK_TYPE).length > 0);

        assertFalse("unmatched function should not have the RevEng tag", hasRevEngTag(unmatchedFunc));
        assertEquals("unmatched function should not have a RevEng bookmark",
                0, program.getBookmarkManager().getBookmarks(unmatchedFunc.getEntryPoint(), REVENG_BOOKMARK_TYPE).length);

        program.withTransaction("cleanup", () -> service.removeProgramAssociation(program));
        assertFalse("tag removed after detach", hasRevEngTag(matchedFunc));
        assertEquals("bookmark removed after detach",
                0, program.getBookmarkManager().getBookmarks(matchedFunc.getEntryPoint(), REVENG_BOOKMARK_TYPE).length);
    }

    private static boolean hasRevEngTag(Function function) {
        return function.getTags().stream().anyMatch(tag -> tag.getName().equals(REVENG_TAG));
    }
}

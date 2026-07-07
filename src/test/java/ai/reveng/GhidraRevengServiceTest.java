package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class GhidraRevengServiceTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void testKnownProgramLookupIsNetworkFree() throws Exception {
        var tool = env.getTool();
        var mock = new OfflineAfterSetupAPI();
        var service = addMockedService(tool, mock);

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        var program = programWithID.program();

        mock.offline = true;
        var freshService = new GhidraRevengService(mock);
        int statusCallsBefore = mock.statusCalls;

        assertTrue("known program must resolve from local state without the network",
                freshService.getKnownProgram(program).isPresent());
        assertTrue("analysed program must resolve from local state without the network",
                freshService.getAnalysedProgram(program).isPresent());
        assertEquals("navigation/enablement lookups must not call status()",
                statusCallsBefore, mock.statusCalls);
    }

    static class OfflineAfterSetupAPI extends UnimplementedAPI {
        volatile boolean offline = false;
        int statusCalls = 0;

        @Override
        public AnalysisID analyse(AnalysisOptionsBuilder options) throws ApiException {
            return new AnalysisID(1);
        }

        @Override
        public AnalysisStatus status(AnalysisID analysisID) throws ApiException {
            statusCalls++;
            if (offline) {
                throw new ApiException("simulated offline");
            }
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
            return List.of(new FunctionInfo(new FunctionID(1), "f1", "f1_mangled", 0x1000L, 10));
        }
    }
}

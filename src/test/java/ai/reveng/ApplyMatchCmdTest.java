package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.binarysimilarity.cmds.ApplyMatchCmd;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.BinaryHash;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.math.BigDecimal;
import java.util.List;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

public class ApplyMatchCmdTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void testFailedServerRenameDoesNotLeakTransaction() throws Exception {
        var tool = env.getTool();
        var service = addMockedService(tool, new RenameFailsAPI());

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var func1 = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        var program = programWithID.program();
        var analysedProgram = service.getAnalysedProgram(program).orElseThrow();

        var match = new FunctionMatch(
                new FunctionID(999),
                new FunctionID(2),
                "renamed_func",
                "renamed_func_mangled",
                "libfoo.so",
                new BinaryHash("abc123"),
                false,
                BigDecimal.valueOf(0.9),
                BigDecimal.valueOf(0.9));
        var ghidraMatch = new GhidraFunctionMatchWithSignature(func1, match, null);

        var cmd = new ApplyMatchCmd(service, analysedProgram, ghidraMatch, true);
        try {
            cmd.applyWithTransaction();
            fail("expected the server rename to throw while offline");
        } catch (RuntimeException expected) {
            // the whole point: it throws, but the transaction must still be closed
        }

        assertNull("transaction must be closed even when the server rename fails",
                program.getCurrentTransactionInfo());
    }

    static class RenameFailsAPI extends UnimplementedAPI {
        @Override
        public AnalysisID analyse(AnalysisOptionsBuilder options) throws ApiException {
            return new AnalysisID(1);
        }

        @Override
        public AnalysisStatus status(AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
            return List.of(new FunctionInfo(new FunctionID(1), "f1", "f1_mangled", 0x1000L, 10));
        }

        @Override
        public void renameFunction(FunctionID id, String newName, String newNameMangled) {
            throw new RuntimeException("simulated offline rename failure");
        }
    }
}

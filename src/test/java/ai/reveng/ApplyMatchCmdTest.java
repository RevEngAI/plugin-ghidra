package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.binarysimilarity.cmds.ApplyMatchCmd;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.BinaryHash;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.math.BigDecimal;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ApplyMatchCmdTest extends RevEngMockableHeadedIntegrationTest {

    private GhidraRevengService.AnalysedProgram analysedProgram;

    @Test
    public void testFailedServerRenameDoesNotLeakTransaction() throws Exception {
        var tool = env.getTool();
        var service = addMockedService(tool, new RenameFailsAPI());

        var builder = newX64Program();
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
                BigDecimal.valueOf(0.9),
                null);
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

    @Test
    public void testTransferNameLeavesSignatureAlone() throws Exception {
        var function = setUpFunction();

        assertTrue(apply(function, matchWithSignature(function), ApplyMatchCmd.Transfer.NAME));

        assertEquals("renamed_func", function.getName());
        assertEquals("the signature must not be transferred", 0, function.getParameterCount());
    }

    @Test
    public void testTransferSignatureKeepsName() throws Exception {
        var function = setUpFunction();
        var originalName = function.getName();

        assertTrue(apply(function, matchWithSignature(function), ApplyMatchCmd.Transfer.SIGNATURE));

        assertEquals("the name must not be transferred", originalName, function.getName());
        assertEquals("the function must stay in its namespace",
                function.getProgram().getGlobalNamespace(), function.getParentNamespace());
        assertEquals(2, function.getParameterCount());
        assertEquals(IntegerDataType.dataType.getName(), function.getReturnType().getName());
        assertEquals("buf", function.getParameter(1).getName());
    }

    @Test
    public void testTransferNameAndSignature() throws Exception {
        var function = setUpFunction();

        assertTrue(apply(function, matchWithSignature(function), ApplyMatchCmd.Transfer.NAME_AND_SIGNATURE));

        assertEquals("renamed_func", function.getName());
        assertEquals(2, function.getParameterCount());
        assertEquals("buf", function.getParameter(1).getName());
    }

    @Test
    public void testTransferSignatureWithoutOneDoesNothing() throws Exception {
        var function = setUpFunction();
        var originalName = function.getName();
        var match = new GhidraFunctionMatchWithSignature(function, functionMatch(), null);

        assertFalse(apply(function, match, ApplyMatchCmd.Transfer.SIGNATURE));
        assertEquals(originalName, function.getName());
    }

    private Function setUpFunction() throws Exception {
        var service = addMockedService(env.getTool(), new RenameFailsAPI());
        var builder = newX64Program();
        var function = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        analysedProgram = service.getAnalysedProgram(builder.getProgram()).orElseThrow();
        return function;
    }

    /// Applied without a service, as the matching dialog does, so nothing is pushed to the portal
    private boolean apply(Function function, GhidraFunctionMatchWithSignature match, ApplyMatchCmd.Transfer transfer) {
        var program = function.getProgram();
        var cmd = new ApplyMatchCmd(null, analysedProgram, match, false, transfer);
        var tx = program.startTransaction("test");
        boolean applied = false;
        try {
            applied = cmd.applyTo(program);
        } finally {
            program.endTransaction(tx, applied);
        }
        return applied;
    }

    private static FunctionMatch functionMatch() {
        return new FunctionMatch(
                new FunctionID(1),
                new FunctionID(2),
                "renamed_func",
                "renamed_func_mangled",
                "libfoo.so",
                new BinaryHash("abc123"),
                false,
                BigDecimal.valueOf(0.9),
                BigDecimal.valueOf(0.9),
                null);
    }

    private static GhidraFunctionMatchWithSignature matchWithSignature(Function function) {
        var signature = new FunctionDefinitionDataType("renamed_func");
        signature.setReturnType(IntegerDataType.dataType);
        signature.setArguments(
                new ParameterDefinitionImpl("len", IntegerDataType.dataType, null),
                new ParameterDefinitionImpl("buf", PointerDataType.dataType, null));
        return new GhidraFunctionMatchWithSignature(function, functionMatch(), signature);
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

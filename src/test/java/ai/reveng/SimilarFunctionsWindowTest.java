package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching.SimilarFunctionsWindow;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch;
import ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import javax.swing.*;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class SimilarFunctionsWindowTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void testSimilarFunctionsWindowBasics() throws Exception {
        var tool = env.getTool();

        var mockApi = new SimilarFunctionsMockAPI();
        var service = addMockedService(tool, mockApi);

        var binarySimilarityPlugin = env.addPlugin(BinarySimilarityPlugin.class);

        // Create a program with two functions
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var func1 = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var func2 = builder.createEmptyFunction(null, "0x2000", 10, Undefined.getUndefinedDataType(4));

        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);

        env.showTool(programWithID.program());

        // Get the SimilarFunctionsWindow
        var similarFunctionsWindow = getComponentProvider(SimilarFunctionsWindow.class);
        assertNotNull("SimilarFunctionsWindow should exist", similarFunctionsWindow);

        // Get internal fields for testing
        @SuppressWarnings("unchecked")
        Map<Function, List<FunctionMatch>> matchCache =
                (Map<Function, List<FunctionMatch>>) getInstanceField("matchCache", similarFunctionsWindow);
        JTable matchesTable = (JTable) getInstanceField("matchesTable", similarFunctionsWindow);
        JLabel statusLabel = (JLabel) getInstanceField("statusLabel", similarFunctionsWindow);

        // Make sure the window is hidden initially
        similarFunctionsWindow.setVisible(false);

        // Navigate to function 1 while window is hidden - should not fetch
        goTo(tool, programWithID.program(), func1.getEntryPoint());
        waitForTasks();
        assertFalse("Cache should be empty when window is hidden", matchCache.containsKey(func1));

        // Now make the window visible and navigate again - should trigger fetch
        similarFunctionsWindow.setVisible(true);
        goTo(tool, programWithID.program(), func2.getEntryPoint());
        waitForTasks();
        waitForSwing();

        // Check that matches were fetched and cached
        assertTrue("Cache should contain func2 after navigation", matchCache.containsKey(func2));

        // Check that the table is populated
        assertEquals("Table should have 2 rows (2 matches)", 2, matchesTable.getRowCount());

        // Check status label shows the function name
        assertTrue("Status label should mention func2",
                statusLabel.getText().contains("2") || statusLabel.getText().contains("similar"));

        // Navigate to func1 (window still visible)
        goTo(tool, programWithID.program(), func1.getEntryPoint());
        waitForTasks();
        waitForSwing();

        // Check that func1 is now cached
        assertTrue("Cache should contain func1", matchCache.containsKey(func1));
        assertEquals("Table should still have 2 rows", 2, matchesTable.getRowCount());
    }

    @Test
    public void testSimilarFunctionsWindowCaching() throws Exception {
        var tool = env.getTool();

        var mockApi = new SimilarFunctionsMockAPI();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var func1 = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var func2 = builder.createEmptyFunction(null, "0x2000", 10, Undefined.getUndefinedDataType(4));

        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(programWithID.program());

        var similarFunctionsWindow = getComponentProvider(SimilarFunctionsWindow.class);
        similarFunctionsWindow.setVisible(true);

        // Navigate to func1
        goTo(tool, programWithID.program(), func1.getEntryPoint());
        waitForTasks();
        waitForSwing();

        int callCountAfterFirst = mockApi.functionMatchingCallCount;
        assertTrue("Should have called function matching API", callCountAfterFirst > 0);

        // Navigate to func2
        goTo(tool, programWithID.program(), func2.getEntryPoint());
        waitForTasks();
        waitForSwing();

        int callCountAfterSecond = mockApi.functionMatchingCallCount;
        assertTrue("Should have called function matching API again for func2",
                callCountAfterSecond > callCountAfterFirst);

        // Navigate back to func1 - should use cache, not call API
        goTo(tool, programWithID.program(), func1.getEntryPoint());
        waitForTasks();
        waitForSwing();

        assertEquals("Should not call API when using cache",
                callCountAfterSecond, mockApi.functionMatchingCallCount);
    }

    @Test
    public void testSimilarFunctionsWindowTableSelection() throws Exception {
        var tool = env.getTool();

        var mockApi = new SimilarFunctionsMockAPI();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var func1 = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));

        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(programWithID.program());

        var similarFunctionsWindow = getComponentProvider(SimilarFunctionsWindow.class);
        similarFunctionsWindow.setVisible(true);

        // Navigate to func1
        goTo(tool, programWithID.program(), func1.getEntryPoint());
        waitForTasks();
        waitForSwing();

        JTable matchesTable = (JTable) getInstanceField("matchesTable", similarFunctionsWindow);

        // Select the first row
        runSwing(() -> matchesTable.setRowSelectionInterval(0, 0));
        waitForTasks();
        waitForSwing();

        // Check that assembly was fetched (the API should have been called)
        assertTrue("Assembly should have been fetched for selected match",
                mockApi.assemblyCallCount > 0);
    }

    /**
     * Mock API that provides function matching and assembly responses
     */
    static class SimilarFunctionsMockAPI extends UnimplementedAPI {
        int functionMatchingCallCount = 0;
        int assemblyCallCount = 0;

        @Override
        public TypedApiInterface.AnalysisID analyse(AnalysisOptionsBuilder options) throws ApiException {
            return new TypedApiInterface.AnalysisID(1);
        }

        @Override
        public AnalysisStatus status(TypedApiInterface.AnalysisID analysisID) {
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(TypedApiInterface.AnalysisID analysisID) {
            return List.of(
                    new FunctionInfo(
                            new TypedApiInterface.FunctionID(1),
                            "portal_func_1",
                            "portal_func_1_mangled",
                            0x1000L,
                            10),
                    new FunctionInfo(
                            new TypedApiInterface.FunctionID(2),
                            "portal_func_2",
                            "portal_func_2_mangled",
                            0x2000L,
                            10)
            );
        }

        @Override
        public Basic getAnalysisBasicInfo(TypedApiInterface.AnalysisID analysisID) throws ApiException {
            var basic = new Basic();
            basic.setModelId(1);
            basic.setSha256Hash("abc123");
            basic.setBinaryName("test_binary");
            return basic;
        }

        @Override
        public StartMatchingOutputBody startFunctionsMatching(StartMatchingForFunctionsInputBody request) throws ApiException {
            functionMatchingCallCount++;
            var response = new StartMatchingOutputBody();
            response.setStatus(StartMatchingOutputBody.StatusEnum.COMPLETED);
            return response;
        }

        @Override
        public GetMatchesStatusOutputBody getFunctionsMatchingStatus(List<Long> functionIds) throws ApiException {
            var response = new GetMatchesStatusOutputBody();
            response.setStatus(GetMatchesStatusOutputBody.StatusEnum.COMPLETED);
            return response;
        }

        @Override
        public GetMatchesOutputBody getFunctionsMatches(List<Long> functionIds) throws ApiException {
            var response = new GetMatchesOutputBody();
            response.setStatus(GetMatchesOutputBody.StatusEnum.COMPLETED);

            // Get the function ID from the request
            Long originFunctionId = functionIds.get(0);

            var functionMatch = new ai.reveng.model.FunctionMatch();
            functionMatch.setFunctionId(originFunctionId);

            // Create two mock matched functions
            var match1 = new MatchedFunction();
            match1.setFunctionId(100L);
            match1.setFunctionName("similar_func_1");
            match1.setMangledName("similar_func_1_mangled");
            match1.setBinaryName("library.so");
            match1.setSha256Hash("def456");
            match1.setDebug(true);
            match1.setSimilarity(0.95);
            match1.setConfidence(0.90);

            var match2 = new MatchedFunction();
            match2.setFunctionId(101L);
            match2.setFunctionName("similar_func_2");
            match2.setMangledName("similar_func_2_mangled");
            match2.setBinaryName("other_lib.so");
            match2.setSha256Hash("ghi789");
            match2.setDebug(false);
            match2.setSimilarity(0.85);
            match2.setConfidence(0.80);

            functionMatch.setMatchedFunctions(List.of(match1, match2));
            response.setMatches(List.of(functionMatch));

            return response;
        }

        @Override
        public List<String> getAssembly(TypedApiInterface.FunctionID functionID) throws ApiException {
            assemblyCallCount++;

            // Return mock assembly instructions
            return List.of(
                    "push rbp",
                    "mov rbp, rsp",
                    "sub rsp, 0x20",
                    "mov [rbp-0x8], rdi",
                    "mov eax, [rbp-0x8]",
                    "add eax, 1",
                    "leave",
                    "ret"
            );
        }

        @Override
        public FunctionDataTypesList listFunctionDataTypesForFunctions(List<TypedApiInterface.FunctionID> functionIDs) {
            // Return empty list - no signatures available in mock
            var result = new FunctionDataTypesList();
            result.setItems(List.of());
            return result;
        }
    }
}

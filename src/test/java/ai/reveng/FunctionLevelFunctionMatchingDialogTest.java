package ai.reveng;

import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching.FunctionLevelFunctionMatchingDialog;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin;
import docking.DockingWindowManager;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import javax.swing.*;
import java.math.BigDecimal;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Integration tests for the FunctionLevelFunctionMatchingDialog.
 * Tests dialog opening, display, and interaction with mocked API responses.
 */
public class FunctionLevelFunctionMatchingDialogTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void testDialogOpensWithMockedService() throws Exception {
        var tool = env.getTool();

        // Create a mock API that returns the necessary data for the dialog
        var mockApi = new FunctionMatchingMockApi();
        var service = addMockedService(tool, mockApi);

        // Add the BinarySimilarity plugin which provides the dialog actions
        env.addPlugin(BinarySimilarityPlugin.class);

        // Create a test program with a function
        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        var testFunction = builder.createEmptyFunction("test_function", "0x1000", 50, Undefined.getUndefinedDataType(4));

        // Register the program as analyzed (this triggers associateFunctionInfo internally)
        var analysedProgram = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);

        // Show the tool with the program
        env.showTool(analysedProgram.program());
        waitForSwing();

        // Create and show the dialog
        FunctionLevelFunctionMatchingDialog dialog = runSwing(() ->
            new FunctionLevelFunctionMatchingDialog(tool, analysedProgram, testFunction)
        );

        // Show dialog without blocking, then wait for it to appear
        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(FunctionLevelFunctionMatchingDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        // Verify the dialog is visible
        assertTrue("Dialog should be visible", foundDialog.isVisible());

        // Verify the dialog has the correct title
        assertTrue("Dialog title should contain 'Function Matching'",
                foundDialog.getTitle().contains("Function Matching"));

        // Get internal components for verification
        JTable resultsTable = (JTable) getInstanceField("resultsTable", foundDialog);
        assertNotNull("Results table should exist", resultsTable);

        JSlider thresholdSlider = (JSlider) getInstanceField("thresholdSlider", foundDialog);
        assertNotNull("Threshold slider should exist", thresholdSlider);
        assertEquals("Default threshold should be 70", 70, thresholdSlider.getValue());

        // Close the dialog
        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testDialogHasResultsTableConfigured() throws Exception {
        var tool = env.getTool();

        // Create a mock API with function matching results
        var mockApi = new FunctionMatchingMockApi();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        var testFunction = builder.createEmptyFunction("test_function", "0x1000", 50, Undefined.getUndefinedDataType(4));

        var analysedProgram = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(analysedProgram.program());
        waitForSwing();

        // Create the dialog
        FunctionLevelFunctionMatchingDialog dialog = runSwing(() ->
            new FunctionLevelFunctionMatchingDialog(tool, analysedProgram, testFunction)
        );

        // Show dialog without blocking, then wait for it to appear
        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(FunctionLevelFunctionMatchingDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        // Verify the table exists and is configured for sorting
        JTable resultsTable = (JTable) getInstanceField("resultsTable", foundDialog);
        assertNotNull("Results table should exist", resultsTable);
        assertTrue("Results table should have auto row sorter enabled", resultsTable.getAutoCreateRowSorter());

        // Close the dialog
        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testAssemblyComparisonPanelExists() throws Exception {
        var tool = env.getTool();

        var mockApi = new FunctionMatchingMockApi();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        var testFunction = builder.createEmptyFunction("test_function", "0x1000", 50, Undefined.getUndefinedDataType(4));

        var analysedProgram = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(analysedProgram.program());
        waitForSwing();

        FunctionLevelFunctionMatchingDialog dialog = runSwing(() ->
            new FunctionLevelFunctionMatchingDialog(tool, analysedProgram, testFunction)
        );

        // Show dialog without blocking, then wait for it to appear
        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(FunctionLevelFunctionMatchingDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        // Verify assembly diff panel exists
        var assemblyDiffPanel = getInstanceField("assemblyDiffPanel", foundDialog);
        assertNotNull("Assembly diff panel should exist", assemblyDiffPanel);

        // Close the dialog
        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testFunctionMatchingTriggersAPICall() throws Exception {
        var tool = env.getTool();

        var mockApi = new FunctionMatchingMockApi();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        var testFunction = builder.createEmptyFunction("test_function", "0x1000", 50, Undefined.getUndefinedDataType(4));

        var analysedProgram = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(analysedProgram.program());
        waitForSwing();

        FunctionLevelFunctionMatchingDialog dialog = runSwing(() ->
            new FunctionLevelFunctionMatchingDialog(tool, analysedProgram, testFunction)
        );

        // Show dialog without blocking, then wait for it to appear
        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(FunctionLevelFunctionMatchingDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        // Verify the initial status message
        JLabel statusLabel = (JLabel) getInstanceField("statusLabel", foundDialog);
        assertNotNull("Status label should exist", statusLabel);
        assertTrue("Status should show ready message",
                statusLabel.getText().contains("Ready"));

        // Close the dialog
        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testClickMatchButtonPopulatesResultsTable() throws Exception {
        var tool = env.getTool();

        var mockApi = new FunctionMatchingMockApi();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        var testFunction = builder.createEmptyFunction("test_function", "0x1000", 50, Undefined.getUndefinedDataType(4));

        var analysedProgram = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(analysedProgram.program());
        waitForSwing();

        FunctionLevelFunctionMatchingDialog dialog = runSwing(() ->
            new FunctionLevelFunctionMatchingDialog(tool, analysedProgram, testFunction)
        );

        // Show dialog without blocking, then wait for it to appear
        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(FunctionLevelFunctionMatchingDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        // Get the results table before clicking
        JTable resultsTable = (JTable) getInstanceField("resultsTable", foundDialog);
        assertNotNull("Results table should exist", resultsTable);
        assertEquals("Results table should be empty initially", 0, resultsTable.getRowCount());

        // Find and click the "Match Functions" button
        JButton matchButton = findButtonByText(foundDialog.getComponent(), "Match Functions");
        assertNotNull("Match Functions button should exist", matchButton);

        pressButton(matchButton);

        // Wait for the API call to complete and results to be processed
        // The mock API returns COMPLETED status immediately, so we just need to wait for Swing
        waitForTasks();
        waitForSwing();

        // Wait for the table to be populated (poll with timeout)
        waitForCondition(() -> resultsTable.getRowCount() > 0,
                "Results table should have rows after matching");

        // Verify the table has the expected data from our mock
        assertTrue("Results table should have at least one row", resultsTable.getRowCount() > 0);

        // Verify the API was actually called
        assertTrue("Function matching API should have been called", mockApi.functionMatchingCalled);

        // Close the dialog
        close(foundDialog);
        waitForSwing();
    }

    /**
     * Mock API implementation for function matching dialog tests.
     * Provides necessary responses for the dialog to function without a real server.
     */
    static class FunctionMatchingMockApi extends UnimplementedAPI {
        private final AnalysisStatus currentStatus = AnalysisStatus.Complete;
        boolean functionMatchingCalled = false;

        @Override
        public TypedApiInterface.AnalysisID analyse(AnalysisOptionsBuilder options) {
            return new TypedApiInterface.AnalysisID(12345);
        }

        @Override
        public AnalysisStatus status(TypedApiInterface.AnalysisID analysisID) {
            return currentStatus;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(TypedApiInterface.AnalysisID analysisID) {
            // Return function info matching the test function we create
            return List.of(
                    new FunctionInfo(
                            new TypedApiInterface.FunctionID(100),
                            "test_function",
                            "test_function",
                            0x1000L,
                            50
                    )
            );
        }

        @Override
        public Basic getAnalysisBasicInfo(TypedApiInterface.AnalysisID analysisID) {
            // Create a Basic object with required fields
            var basic = new Basic();
            basic.setModelId(1);
            basic.setModelName("test-model");
            basic.setBinaryName("test_binary");
            basic.setSha256Hash("0".repeat(64));
            return basic;
        }

        @Override
        public FunctionMatchingResponse functionFunctionMatching(FunctionMatchingRequest request) {
            functionMatchingCalled = true;

            // Create a response with completed status and mock matches
            var response = new FunctionMatchingResponse();
            response.setStatus("COMPLETED");
            response.setProgress(100);

            // Create a match result using the SDK model types
            var functionMatch = new ai.reveng.model.FunctionMatch();
            functionMatch.setFunctionId(100L);

            // Create a matched function
            var matchedFunc = new MatchedFunction();
            matchedFunc.setFunctionId(200L);
            matchedFunc.setFunctionName("similar_function");
            matchedFunc.setMangledName("similar_function");
            matchedFunc.setSha256Hash("1".repeat(64));
            matchedFunc.setBinaryName("libc.so");
            matchedFunc.setBinaryId(1);
            matchedFunc.setFunctionVaddr(0x2000L);
            matchedFunc.setAnalysisId(12345);
            matchedFunc.setDebug(false);
            matchedFunc.setSimilarity(BigDecimal.valueOf(0.95));
            matchedFunc.setConfidence(BigDecimal.valueOf(0.87));

            functionMatch.setMatchedFunctions(List.of(matchedFunc));
            response.setMatches(List.of(functionMatch));

            return response;
        }

        @Override
        public List<String> getAssembly(TypedApiInterface.FunctionID functionID) {
            // Return some mock assembly for the diff display
            if (functionID.value() == 100) {
                // Local function assembly
                return List.of(
                        "push rbp",
                        "mov rbp, rsp",
                        "sub rsp, 0x20",
                        "mov [rbp-0x8], rdi",
                        "call 0x1234",
                        "leave",
                        "ret"
                );
            } else if (functionID.value() == 200) {
                // Matched function assembly (slightly different)
                return List.of(
                        "push rbp",
                        "mov rbp, rsp",
                        "sub rsp, 0x30",
                        "mov [rbp-0x8], rdi",
                        "mov [rbp-0x10], rsi",
                        "call 0x5678",
                        "leave",
                        "ret"
                );
            }
            return List.of();
        }

        @Override
        public FunctionDataTypesList listFunctionDataTypesForFunctions(List<TypedApiInterface.FunctionID> functionIDs) {
            // Return empty list - no type info available
            return new FunctionDataTypesList();
        }
    }
}
package ai.reveng;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionselection.FunctionSelectionPanel;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses.RecentAnalysisDialog;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisResultsLoaded;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryID;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.api.types.LegacyAnalysisResult;
import ai.reveng.model.FunctionDataTypesList;
import docking.DockingWindowManager;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.listing.Function;
import org.junit.Test;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/**
 * Integration tests for the RecentAnalysisDialog.
 * Tests dialog opening, analysis selection, event firing, and getKnownProgram behavior.
 */
public class RecentAnalysisDialogTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void testSelectRecentAnalysisFiresEventAndUpdatesKnownProgram() throws Exception {
        var tool = env.getTool();

        // Create a mock API that returns recent analyses
        var mockApi = new RecentAnalysesMockApi();
        var service = addMockedService(tool, mockApi);

        // Create a test program with matching hash and at least one function
        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x1000", 0x1000);
        builder.createEmptyFunction("main", "0x1000", 100, Undefined.getUndefinedDataType(4));
        var program = builder.getProgram();

        // Show the tool with the program
        env.showTool(program);
        waitForSwing();

        // Set up event listener to capture the analysis results loaded event
        AtomicBoolean eventReceived = new AtomicBoolean(false);
        AtomicReference<RevEngAIAnalysisResultsLoaded> receivedEvent = new AtomicReference<>();
        tool.addEventListener(RevEngAIAnalysisResultsLoaded.class, e -> {
            eventReceived.set(true);
            receivedEvent.set((RevEngAIAnalysisResultsLoaded) e);
        });

        // Verify the program is not known before the dialog interaction
        assertTrue("Program should not be known initially", service.getKnownProgram(program).isEmpty());

        // Create and show the dialog
        RecentAnalysisDialog dialog = runSwing(() ->
            new RecentAnalysisDialog(tool, program)
        );

        // Show dialog without blocking, then wait for it to appear
        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(RecentAnalysisDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        // Wait for the table model to load the data
        // The table model uses a background thread to load data
        var tableModelField = getInstanceField("recentAnalysesTableModel", foundDialog);
        assertNotNull("Table model should exist in dialog", tableModelField);
        @SuppressWarnings("unchecked")
        var tableModel = (docking.widgets.table.threaded.ThreadedTableModel<LegacyAnalysisResult, ?>) tableModelField;

        // Wait for the threaded table model to finish loading
        waitForTableModel(tableModel);
        waitForSwing();

        // Verify data was loaded
        assertTrue("Table should have data after loading", tableModel.getRowCount() > 0);

        // Find and click the "Pick most recent" button
        JButton pickMostRecentButton = findButtonByText(foundDialog.getComponent(), "Pick most recent");
        assertNotNull("Pick most recent button should exist", pickMostRecentButton);

        pressButton(pickMostRecentButton);
        waitForSwing();

        // Wait for the event to be fired
        waitForCondition(() -> eventReceived.get(),
                "Event should have been fired after selecting analysis");

        // Verify the event was fired with correct data
        assertNotNull("Event should have been captured", receivedEvent.get());

        GhidraRevengService.AnalysedProgram analysedProgram = receivedEvent.get().getProgramWithBinaryID();
        assertNotNull("Event should contain AnalysedProgram", analysedProgram);
        assertSame("Event program should be the same as our test program",
                program, analysedProgram.program());
        assertEquals("Event analysis ID should match mock data",
                RecentAnalysesMockApi.MOCK_ANALYSIS_ID, analysedProgram.analysisID().id());

        // Verify getKnownProgram returns the same program with the correct analysis ID
        var knownProgram = service.getKnownProgram(program);
        assertTrue("Program should be known after selection", knownProgram.isPresent());
        assertEquals("Known program analysis ID should match event analysis ID",
                analysedProgram.analysisID(), knownProgram.get().analysisID());
        assertSame("Known program should be the same instance as event program",
                analysedProgram.program(), knownProgram.get().program());
    }

    @Test
    public void testDialogShowsRecentAnalyses() throws Exception {
        var tool = env.getTool();

        var mockApi = new RecentAnalysesMockApi();
        addMockedService(tool, mockApi);

        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        builder.createMemory("test", "0x1000", 100);
        var program = builder.getProgram();

        env.showTool(program);
        waitForSwing();

        RecentAnalysisDialog dialog = runSwing(() ->
            new RecentAnalysisDialog(tool, program)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(RecentAnalysisDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        // Verify the dialog is visible
        assertTrue("Dialog should be visible", foundDialog.isVisible());

        // Verify the dialog has the correct title
        assertTrue("Dialog title should contain 'Recent Analyses'",
                foundDialog.getTitle().contains("Recent Analyses"));

        // Wait for table to load
        waitForTasks();
        waitForSwing();

        // Close the dialog
        close(foundDialog);
        waitForSwing();
    }

    /**
     * Mock API implementation for recent analysis dialog tests.
     * Provides necessary responses for the dialog to function without a real server.
     */
    static class RecentAnalysesMockApi extends UnimplementedAPI {
        static final int MOCK_ANALYSIS_ID = 99999;
        static final int MOCK_BINARY_ID = 88888;

        @Override
        public List<LegacyAnalysisResult> search(TypedApiInterface.BinaryHash hash) {
            // Return a single recent analysis result
            return List.of(
                new LegacyAnalysisResult(
                    new TypedApiInterface.AnalysisID(MOCK_ANALYSIS_ID),
                    new BinaryID(MOCK_BINARY_ID),
                    "test_binary",
                    "2024-01-15 10:00:00",
                    1,
                    "binnet-0.2-x86-linux",
                    hash,
                    AnalysisStatus.Complete,
                    0x0L,  // Default image base for x64 programs
                    "abc123hash"
                )
            );
        }

        @Override
        public TypedApiInterface.AnalysisID getAnalysisIDfromBinaryID(BinaryID binaryID) {
            assertEquals("Binary ID should match mock data", MOCK_BINARY_ID, binaryID.value());
            return new TypedApiInterface.AnalysisID(MOCK_ANALYSIS_ID);
        }

        @Override
        public AnalysisStatus status(TypedApiInterface.AnalysisID analysisID) {
            assertEquals("Analysis ID should match mock data", MOCK_ANALYSIS_ID, analysisID.id());
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(TypedApiInterface.AnalysisID analysisID) {
            // Return function info covering common test addresses.
            // Note: 0x1200 is deliberately omitted so tests can verify unmatched function behavior.
            return List.of(
                new FunctionInfo(
                    new TypedApiInterface.FunctionID(1001),
                    "main",
                    "main",
                    0x1000L,
                    100
                ),
                new FunctionInfo(
                    new TypedApiInterface.FunctionID(1002),
                    "helper",
                    "helper",
                    0x1100L,
                    50
                )
            );
        }

        @Override
        public FunctionDataTypesList listFunctionDataTypesForAnalysis(TypedApiInterface.AnalysisID analysisID) {
            // Return empty list
            var list = new FunctionDataTypesList();
            list.setItems(List.of());
            return list;
        }
    }

    // ==================== Function Selection Tests ====================

    @Test
    public void testDialogHasFunctionSelectionPanel() throws Exception {
        var tool = env.getTool();

        var mockApi = new RecentAnalysesMockApi();
        addMockedService(tool, mockApi);

        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x1000", 0x1000);
        builder.createEmptyFunction("main", "0x1000", 100, Undefined.getUndefinedDataType(4));
        builder.createEmptyFunction("helper", "0x1100", 50, Undefined.getUndefinedDataType(4));
        var program = builder.getProgram();

        env.showTool(program);
        waitForSwing();

        RecentAnalysisDialog dialog = runSwing(() ->
                new RecentAnalysisDialog(tool, program)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(RecentAnalysisDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        // Verify the function selection panel exists
        FunctionSelectionPanel functionSelectionPanel =
                (FunctionSelectionPanel) getInstanceField("functionSelectionPanel", foundDialog);
        assertNotNull("Function selection panel should exist in RecentAnalysisDialog",
                functionSelectionPanel);

        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testFunctionSelectionPanelLoadsInAttachDialog() throws Exception {
        var tool = env.getTool();

        var mockApi = new RecentAnalysesMockApi();
        addMockedService(tool, mockApi);

        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x1000", 0x1000);
        builder.createEmptyFunction("main", "0x1000", 100, Undefined.getUndefinedDataType(4));
        builder.createEmptyFunction("process", "0x1100", 150, Undefined.getUndefinedDataType(4));
        builder.createEmptyFunction("cleanup", "0x1200", 80, Undefined.getUndefinedDataType(4));
        var program = builder.getProgram();

        env.showTool(program);
        waitForSwing();

        RecentAnalysisDialog dialog = runSwing(() ->
                new RecentAnalysisDialog(tool, program)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(RecentAnalysisDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        FunctionSelectionPanel functionSelectionPanel =
                (FunctionSelectionPanel) getInstanceField("functionSelectionPanel", foundDialog);

        // Wait for functions to load
        waitForCondition(() -> functionSelectionPanel.getTotalFunctionCount() > 0,
                "Function selection panel should load functions");

        // Should have at least our 3 functions
        assertTrue("Should have at least 3 functions",
                functionSelectionPanel.getTotalFunctionCount() >= 3);

        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testSelectAllButtonInAttachDialog() throws Exception {
        var tool = env.getTool();

        var mockApi = new RecentAnalysesMockApi();
        addMockedService(tool, mockApi);

        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x1000", 0x1000);
        builder.createEmptyFunction("func1", "0x1000", 100, Undefined.getUndefinedDataType(4));
        builder.createEmptyFunction("func2", "0x1100", 100, Undefined.getUndefinedDataType(4));
        var program = builder.getProgram();

        env.showTool(program);
        waitForSwing();

        RecentAnalysisDialog dialog = runSwing(() ->
                new RecentAnalysisDialog(tool, program)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(RecentAnalysisDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        FunctionSelectionPanel functionSelectionPanel =
                (FunctionSelectionPanel) getInstanceField("functionSelectionPanel", foundDialog);

        waitForCondition(() -> functionSelectionPanel.getTotalFunctionCount() > 0,
                "Function selection panel should load functions");

        // Find and click Select All button
        JButton selectAllButton = findButtonByText(foundDialog.getComponent(), "Select All");
        assertNotNull("Select All button should exist", selectAllButton);

        pressButton(selectAllButton);
        waitForSwing();

        // All enabled functions should be selected (disabled functions from remote matching remain unselected)
        int enabledCount = functionSelectionPanel.getTableModel().getEnabledCount();
        assertEquals("All enabled functions should be selected",
                enabledCount,
                functionSelectionPanel.getSelectedFunctions().size());
        assertTrue("At least one function should be selected", enabledCount > 0);

        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testDeselectAllButtonInAttachDialog() throws Exception {
        var tool = env.getTool();

        var mockApi = new RecentAnalysesMockApi();
        addMockedService(tool, mockApi);

        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x1000", 0x1000);
        builder.createEmptyFunction("func1", "0x1000", 100, Undefined.getUndefinedDataType(4));
        builder.createEmptyFunction("func2", "0x1100", 100, Undefined.getUndefinedDataType(4));
        var program = builder.getProgram();

        env.showTool(program);
        waitForSwing();

        RecentAnalysisDialog dialog = runSwing(() ->
                new RecentAnalysisDialog(tool, program)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(RecentAnalysisDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        // Wait for analyses table to load so the auto-select triggers the remote function fetch
        var tableModelField = getInstanceField("recentAnalysesTableModel", foundDialog);
        @SuppressWarnings("unchecked")
        var tableModel = (docking.widgets.table.threaded.ThreadedTableModel<LegacyAnalysisResult, ?>) tableModelField;
        waitForTableModel(tableModel);
        waitForSwing();

        FunctionSelectionPanel functionSelectionPanel =
                (FunctionSelectionPanel) getInstanceField("functionSelectionPanel", foundDialog);

        waitForCondition(() -> functionSelectionPanel.getTotalFunctionCount() > 0,
                "Function selection panel should load functions");

        // Wait for remote function matching to complete (async fetch)
        waitForCondition(() -> functionSelectionPanel.getTableModel().getEnabledCount() < functionSelectionPanel.getTotalFunctionCount(),
                "Remote function matching should complete before testing deselect");

        // Find and click Deselect All button
        JButton deselectAllButton = findButtonByText(foundDialog.getComponent(), "Deselect All");
        assertNotNull("Deselect All button should exist", deselectAllButton);

        pressButton(deselectAllButton);
        waitForSwing();

        // No functions should be selected
        assertTrue("No functions should be selected",
                functionSelectionPanel.getSelectedFunctions().isEmpty());

        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testExternalFunctionsExcludedByDefaultInAttachDialog() throws Exception {
        var tool = env.getTool();

        var mockApi = new RecentAnalysesMockApi();
        addMockedService(tool, mockApi);

        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x1000", 0x1000);
        builder.createEmptyFunction("main", "0x1000", 100, Undefined.getUndefinedDataType(4));
        // Create external function (extAddress, libName, functionName)
        builder.createExternalFunction(null, "EXTERNAL", "printf");
        var program = builder.getProgram();

        env.showTool(program);
        waitForSwing();

        RecentAnalysisDialog dialog = runSwing(() ->
                new RecentAnalysisDialog(tool, program)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(RecentAnalysisDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        FunctionSelectionPanel functionSelectionPanel =
                (FunctionSelectionPanel) getInstanceField("functionSelectionPanel", foundDialog);

        waitForCondition(() -> functionSelectionPanel.getTotalFunctionCount() > 0,
                "Function selection panel should load functions");

        // External functions should not be selected by default
        List<Function> selectedFunctions = functionSelectionPanel.getSelectedFunctions();
        for (Function func : selectedFunctions) {
            assertFalse("External function should not be selected by default: " + func.getName(),
                    func.isExternal());
        }

        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testRemoteFunctionMatchingDisablesUnmatchedFunctions() throws Exception {
        var tool = env.getTool();

        var mockApi = new RecentAnalysesMockApi();
        addMockedService(tool, mockApi);

        // Create 3 functions: main (0x1000, 100), helper (0x1100, 50), unmatched (0x1200, 80)
        // The mock API returns info for main and helper but not unmatched
        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x1000", 0x1000);
        builder.createEmptyFunction("main", "0x1000", 100, Undefined.getUndefinedDataType(4));
        builder.createEmptyFunction("helper", "0x1100", 50, Undefined.getUndefinedDataType(4));
        builder.createEmptyFunction("unmatched", "0x1200", 80, Undefined.getUndefinedDataType(4));
        var program = builder.getProgram();

        env.showTool(program);
        waitForSwing();

        RecentAnalysisDialog dialog = runSwing(() ->
                new RecentAnalysisDialog(tool, program)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(RecentAnalysisDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        // Wait for the analyses table to load
        var tableModelField = getInstanceField("recentAnalysesTableModel", foundDialog);
        @SuppressWarnings("unchecked")
        var tableModel = (docking.widgets.table.threaded.ThreadedTableModel<LegacyAnalysisResult, ?>) tableModelField;
        waitForTableModel(tableModel);
        waitForSwing();

        FunctionSelectionPanel functionSelectionPanel =
                (FunctionSelectionPanel) getInstanceField("functionSelectionPanel", foundDialog);

        waitForCondition(() -> functionSelectionPanel.getTotalFunctionCount() > 0,
                "Function selection panel should load functions");

        // Wait for remote function info to be applied (async fetch)
        waitForCondition(() -> functionSelectionPanel.getTableModel().getEnabledCount() < functionSelectionPanel.getTotalFunctionCount(),
                "Remote function matching should disable some functions");

        // Verify enabled/disabled state
        var allRows = functionSelectionPanel.getTableModel().getAllRows();
        for (var row : allRows) {
            if ("unmatched".equals(row.getName())) {
                assertFalse("Unmatched function should be disabled", row.isEnabled());
                assertFalse("Unmatched function should not be selected", row.isSelected());
                assertNull("Unmatched function should have no remote info", row.getRemoteFunctionInfo());
            } else {
                assertTrue("Matched function '" + row.getName() + "' should be enabled", row.isEnabled());
                assertNotNull("Matched function '" + row.getName() + "' should have remote info", row.getRemoteFunctionInfo());
            }
        }

        // Verify that select all only selects enabled functions
        JButton selectAllButton = findButtonByText(foundDialog.getComponent(), "Select All");
        pressButton(selectAllButton);
        waitForSwing();

        for (var row : allRows) {
            if ("unmatched".equals(row.getName())) {
                assertFalse("Disabled function should remain unselected after Select All", row.isSelected());
            } else {
                assertTrue("Enabled function should be selected after Select All", row.isSelected());
            }
        }

        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testPickAnalysisWithFunctionSelection() throws Exception {
        var tool = env.getTool();

        var mockApi = new RecentAnalysesMockApi();
        var service = addMockedService(tool, mockApi);

        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x1000", 0x1000);
        builder.createEmptyFunction("main", "0x1000", 100, Undefined.getUndefinedDataType(4));
        builder.createEmptyFunction("helper", "0x1100", 50, Undefined.getUndefinedDataType(4));
        var program = builder.getProgram();

        env.showTool(program);
        waitForSwing();

        // Set up event listener
        AtomicBoolean eventReceived = new AtomicBoolean(false);
        tool.addEventListener(RevEngAIAnalysisStatusChangedEvent.class, e -> {
            eventReceived.set(true);
        });

        RecentAnalysisDialog dialog = runSwing(() ->
                new RecentAnalysisDialog(tool, program)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(RecentAnalysisDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        // Wait for both table models to load
        var tableModelField = getInstanceField("recentAnalysesTableModel", foundDialog);
        @SuppressWarnings("unchecked")
        var tableModel = (docking.widgets.table.threaded.ThreadedTableModel<LegacyAnalysisResult, ?>) tableModelField;
        waitForTableModel(tableModel);

        FunctionSelectionPanel functionSelectionPanel =
                (FunctionSelectionPanel) getInstanceField("functionSelectionPanel", foundDialog);
        waitForCondition(() -> functionSelectionPanel.getTotalFunctionCount() > 0,
                "Function selection panel should load functions");

        // Select only the main function (deselect helper)
        JButton deselectAllButton = findButtonByText(foundDialog.getComponent(), "Deselect All");
        pressButton(deselectAllButton);
        waitForSwing();

        // With no functions selected, the pick buttons should be disabled
        JButton pickMostRecentButton = findButtonByText(foundDialog.getComponent(), "Pick most recent");
        assertNotNull("Pick most recent button should exist", pickMostRecentButton);
        assertFalse("Pick most recent button should be disabled when no functions are selected",
                pickMostRecentButton.isEnabled());

        JButton pickSelectedButton = findButtonByText(foundDialog.getComponent(), "Pick selected");
        assertNotNull("Pick selected button should exist", pickSelectedButton);
        assertFalse("Pick selected button should be disabled when no functions are selected",
                pickSelectedButton.isEnabled());

        close(foundDialog);
        waitForSwing();
    }

}
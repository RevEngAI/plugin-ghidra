package ai.reveng;

import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching.FunctionLevelFunctionMatchingDialog;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin;
import docking.DockingWindowManager;
import ghidra.program.model.data.Undefined;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import javax.swing.*;
import generic.theme.GColor;
import java.math.BigDecimal;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.FunctionSignatureBatch;

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
        var builder = newX64Program("test_binary");
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

        var builder = newX64Program("test_binary");
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

        var builder = newX64Program("test_binary");
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
    public void testUserSubmittedDebugSymbolsAlwaysVisibleAndEnabledByParent() throws Exception {
        var tool = env.getTool();

        var mockApi = new FunctionMatchingMockApi();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = newX64Program("test_binary");
        var testFunction = builder.createEmptyFunction("test_function", "0x1000", 50, Undefined.getUndefinedDataType(4));

        var analysedProgram = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(analysedProgram.program());
        waitForSwing();

        FunctionLevelFunctionMatchingDialog dialog = runSwing(() ->
            new FunctionLevelFunctionMatchingDialog(tool, analysedProgram, testFunction)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(FunctionLevelFunctionMatchingDialog.class);

        JCheckBox debugSymbols = (JCheckBox) getInstanceField("debugSymbolsCheckBox", foundDialog);
        JCheckBox userSubmitted = (JCheckBox) getInstanceField("userSubmittedDebugSymbolsCheckBox", foundDialog);

        assertTrue(userSubmitted.isVisible());
        assertFalse(userSubmitted.isEnabled());

        setToggleButtonSelected(debugSymbols, true);
        assertTrue(userSubmitted.isVisible());
        assertTrue(userSubmitted.isEnabled());

        setToggleButtonSelected(debugSymbols, false);
        assertTrue(userSubmitted.isVisible());
        assertFalse(userSubmitted.isEnabled());

        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testFunctionMatchingTriggersAPICall() throws Exception {
        var tool = env.getTool();

        var mockApi = new FunctionMatchingMockApi();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = newX64Program("test_binary");
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

        JTable resultsTable = (JTable) getInstanceField("resultsTable", foundDialog);
        waitForCondition(() -> resultsTable.getRowCount() > 0,
                "Results table should populate without pressing Match Functions");
        assertTrue("Function matching API should have been called", mockApi.functionMatchingCalled);
        assertEquals("Should request 5 results per function",
                Long.valueOf(5L), mockApi.lastMatchingRequest.getResultsPerFunction());

        // Close the dialog
        close(foundDialog);
        waitForSwing();
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testPlatformAndArchitectureTogglesAreSentAsMatchFilters() throws Exception {
        var tool = env.getTool();

        var mockApi = new FunctionMatchingMockApi();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = newX64Program("test_binary");
        var testFunction = builder.createEmptyFunction("test_function", "0x1000", 50, Undefined.getUndefinedDataType(4));

        var analysedProgram = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(analysedProgram.program());
        waitForSwing();

        FunctionLevelFunctionMatchingDialog dialog = runSwing(() ->
            new FunctionLevelFunctionMatchingDialog(tool, analysedProgram, testFunction)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(FunctionLevelFunctionMatchingDialog.class);

        // The automatic run on open leaves platform, architecture and user unfiltered, i.e. any
        waitForCondition(() -> mockApi.lastMatchingRequest != null, "Matching should start when the dialog opens");
        MatchFilters initialFilters = mockApi.lastMatchingRequest.getFilters();
        assertNull(initialFilters.getPlatforms());
        assertNull(initialFilters.getArchitectures());
        assertNull(initialFilters.getUserIds());
        waitForTasks();

        var platforms = (java.util.Map<MatchFilters.PlatformsEnum, JCheckBox>) getInstanceField("platformCheckBoxes", foundDialog);
        var architectures = (java.util.Map<MatchFilters.ArchitecturesEnum, JCheckBox>) getInstanceField("architectureCheckBoxes", foundDialog);
        setToggleButtonSelected(platforms.get(MatchFilters.PlatformsEnum.LINUX), true);
        setToggleButtonSelected(architectures.get(MatchFilters.ArchitecturesEnum.ARM_64), true);

        var firstRequest = mockApi.lastMatchingRequest;
        pressButton(findButtonByText(foundDialog.getComponent(), "Match Functions"));
        waitForCondition(() -> mockApi.lastMatchingRequest != firstRequest, "Pressing Match Functions should start a new match");
        waitForTasks();

        MatchFilters filters = mockApi.lastMatchingRequest.getFilters();
        assertEquals(List.of(MatchFilters.PlatformsEnum.LINUX), filters.getPlatforms());
        assertEquals(List.of(MatchFilters.ArchitecturesEnum.ARM_64), filters.getArchitectures());
        assertNull(filters.getUserIds());

        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testClickMatchButtonPopulatesResultsTable() throws Exception {
        var tool = env.getTool();

        var mockApi = new FunctionMatchingMockApi();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = newX64Program("test_binary");
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

        // Once the results are in, the status must say so. Nothing used to write to the label after
        // "Loading type information...", so a completed match looked exactly like a stuck one.
        JLabel statusLabel = (JLabel) getInstanceField("statusLabel", foundDialog);
        waitForCondition(() -> !statusLabel.getText().contains("Loading"),
                "Status label should stop saying it is loading once matching has finished");
        assertTrue("The finished status should report the matches, was: " + statusLabel.getText(),
                statusLabel.getText().contains("Matching complete"));
        JProgressBar progressBar = (JProgressBar) getInstanceField("matchingProgressBar", foundDialog);
        assertFalse("The progress bar should not be left spinning", progressBar.isVisible());

        // Close the dialog
        close(foundDialog);
        waitForSwing();
    }

    /**
     * The results table is sortable, so a selected view row need not be the same row in the list
     * backing the table model. Selecting a row after sorting must still pick the match that is
     * actually displayed on that row, otherwise "Rename Selected" renames an unrelated function.
     */
    @Test
    public void testSelectedMatchFollowsSortOrderNotModelOrder() throws Exception {
        var tool = env.getTool();

        var mockApi = new MultiMatchMockApi();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = newX64Program("test_binary");
        var testFunction = builder.createEmptyFunction("test_function", "0x1000", 50, Undefined.getUndefinedDataType(4));

        var analysedProgram = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(analysedProgram.program());
        waitForSwing();

        FunctionLevelFunctionMatchingDialog dialog = runSwing(() ->
            new FunctionLevelFunctionMatchingDialog(tool, analysedProgram, testFunction)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(FunctionLevelFunctionMatchingDialog.class);
        assertNotNull("Dialog should be shown", foundDialog);

        JTable resultsTable = (JTable) getInstanceField("resultsTable", foundDialog);

        pressButton(findButtonByText(foundDialog.getComponent(), "Match Functions"));
        waitForTasks();
        waitForSwing();
        waitForCondition(() -> resultsTable.getRowCount() == 3,
                "Results table should hold all three mocked matches");

        // The model holds the matches in the order the server returned them
        assertEquals("zeta_match", resultsTable.getModel().getValueAt(0, 0));
        assertEquals("alpha_match", resultsTable.getModel().getValueAt(1, 0));
        assertEquals("mid_match", resultsTable.getModel().getValueAt(2, 0));

        // Sort ascending by matched function name, which reorders the view against the model
        runSwing(() -> resultsTable.getRowSorter().toggleSortOrder(0));
        waitForSwing();
        assertEquals("Sorting should have reordered the view", 1, resultsTable.convertRowIndexToModel(0));

        // Select the first row as displayed, which is no longer the first row of the model
        runSwing(() -> resultsTable.setRowSelectionInterval(0, 0));
        waitForSwing();

        List<?> selected = (List<?>) invokeInstanceMethod("getSelectedMatches", foundDialog);
        assertEquals("Exactly one match should be selected", 1, selected.size());
        assertEquals("The match on the selected view row must be the one that gets renamed",
                "alpha_match",
                ((GhidraFunctionMatchWithSignature) selected.get(0)).functionMatch().name());

        // And the last displayed row maps back to the first row of the model
        runSwing(() -> resultsTable.setRowSelectionInterval(2, 2));
        waitForSwing();
        selected = (List<?>) invokeInstanceMethod("getSelectedMatches", foundDialog);
        assertEquals(1, selected.size());
        assertEquals("zeta_match",
                ((GhidraFunctionMatchWithSignature) selected.get(0)).functionMatch().name());

        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testSortBySimilarityAndConfidence() throws Exception {
        var tool = env.getTool();

        var mockApi = new MultiMatchMockApi() {
            @Override
            public GetMatchesOutputBody getFunctionsMatches(List<Long> functionIds) {
                var response = super.getFunctionsMatches(functionIds);
                var matches = response.getMatches().get(0).getMatchedFunctions();
                matches.get(0).setConfidence(0.0);
                matches.get(2).setConfidence(null);
                return response;
            }
        };
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = newX64Program("test_binary");
        var testFunction = builder.createEmptyFunction("test_function", "0x1000", 50, Undefined.getUndefinedDataType(4));

        var analysedProgram = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(analysedProgram.program());
        waitForSwing();

        FunctionLevelFunctionMatchingDialog dialog = runSwing(() ->
            new FunctionLevelFunctionMatchingDialog(tool, analysedProgram, testFunction)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(FunctionLevelFunctionMatchingDialog.class);

        JTable resultsTable = (JTable) getInstanceField("resultsTable", foundDialog);

        pressButton(findButtonByText(foundDialog.getComponent(), "Match Functions"));
        waitForTasks();
        waitForSwing();
        waitForCondition(() -> resultsTable.getRowCount() == 3,
                "Results table should hold all three mocked matches");

        // Similarity: zeta 0.50, alpha 0.95, mid 0.72
        runSwing(() -> resultsTable.getRowSorter().toggleSortOrder(1));
        waitForSwing();
        assertEquals("zeta_match", resultsTable.getValueAt(0, 0));
        assertEquals("mid_match", resultsTable.getValueAt(1, 0));
        assertEquals("alpha_match", resultsTable.getValueAt(2, 0));

        // Confidence: zeta 0, alpha 0.95, mid null
        runSwing(() -> resultsTable.getRowSorter().toggleSortOrder(2));
        waitForSwing();
        assertEquals("mid_match", resultsTable.getValueAt(0, 0));
        assertEquals("zeta_match", resultsTable.getValueAt(1, 0));
        assertEquals("alpha_match", resultsTable.getValueAt(2, 0));

        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testSimilarityAndConfidenceCellsAreColorCoded() throws Exception {
        var tool = env.getTool();

        var mockApi = new FunctionMatchingMockApi();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = newX64Program("test_binary");
        var testFunction = builder.createEmptyFunction("test_function", "0x1000", 50, Undefined.getUndefinedDataType(4));

        var analysedProgram = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(analysedProgram.program());
        waitForSwing();

        FunctionLevelFunctionMatchingDialog dialog = runSwing(() ->
            new FunctionLevelFunctionMatchingDialog(tool, analysedProgram, testFunction)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(FunctionLevelFunctionMatchingDialog.class);

        JTable resultsTable = (JTable) getInstanceField("resultsTable", foundDialog);

        pressButton(findButtonByText(foundDialog.getComponent(), "Match Functions"));
        waitForTasks();
        waitForSwing();
        waitForCondition(() -> resultsTable.getRowCount() > 0, "Results table should have rows");

        // Similarity (1) and Confidence (2) hold BigDecimal values on a 0-100 scale
        for (int column : new int[]{1, 2}) {
            var renderer = runSwing(() -> resultsTable.getCellRenderer(0, column));
            var high = runSwing(() -> renderer.getTableCellRendererComponent(
                    resultsTable, new BigDecimal("99.93"), false, false, 0, column).getForeground());
            assertEquals(new GColor("color.fg.reveng.similarity.low"), high);
            var low = runSwing(() -> renderer.getTableCellRendererComponent(
                    resultsTable, BigDecimal.ZERO, false, false, 0, column).getForeground());
            assertEquals(new GColor("color.fg.reveng.similarity.critical"), low);
        }

        close(foundDialog);
        waitForSwing();
    }

    @Test
    public void testRightClickOffersMatchedBinaryInPortal() throws Exception {
        var tool = env.getTool();

        var mockApi = new MultiMatchMockApi();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = newX64Program("test_binary");
        var testFunction = builder.createEmptyFunction("test_function", "0x1000", 50, Undefined.getUndefinedDataType(4));

        var analysedProgram = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(analysedProgram.program());
        waitForSwing();

        FunctionLevelFunctionMatchingDialog dialog = runSwing(() ->
            new FunctionLevelFunctionMatchingDialog(tool, analysedProgram, testFunction)
        );

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(FunctionLevelFunctionMatchingDialog.class);

        JTable resultsTable = (JTable) getInstanceField("resultsTable", foundDialog);
        assertNull(invokeInstanceMethod("getSelectedMatchedAnalysisID", foundDialog));

        pressButton(findButtonByText(foundDialog.getComponent(), "Match Functions"));
        waitForTasks();
        waitForSwing();
        waitForCondition(() -> resultsTable.getRowCount() == 3,
                "Results table should hold all three mocked matches");

        var cell = runSwing(() -> resultsTable.getCellRect(1, 0, true));
        var rightClick = new java.awt.event.MouseEvent(resultsTable, java.awt.event.MouseEvent.MOUSE_PRESSED,
                System.currentTimeMillis(), java.awt.event.InputEvent.BUTTON3_DOWN_MASK,
                cell.x + 1, cell.y + 1, 1, true, java.awt.event.MouseEvent.BUTTON3);
        runSwing(() -> resultsTable.dispatchEvent(rightClick));
        var popup = (JPopupMenu) getInstanceField("portalPopup", foundDialog);
        assertTrue("Right click should show the portal popup", runSwing(popup::isVisible));
        assertTrue("Right click should not reach the docking popup", rightClick.isConsumed());
        assertEquals("Right click should select the row under the cursor", 1, resultsTable.getSelectedRow());
        var item = (JMenuItem) popup.getComponent(0);
        assertEquals("Open in Portal", item.getText());
        assertTrue(item.isEnabled());
        assertEquals(new TypedApiInterface.AnalysisID(12345),
                invokeInstanceMethod("getSelectedMatchedAnalysisID", foundDialog));
        runSwing(() -> popup.setVisible(false));

        close(foundDialog);
        waitForSwing();
    }

    /**
     * Returns several matches whose server order differs from their alphabetical order, so that
     * sorting the results table genuinely separates view indices from model indices.
     */
    static class MultiMatchMockApi extends FunctionMatchingMockApi {
        @Override
        public GetMatchesOutputBody getFunctionsMatches(List<Long> functionIds) {
            var response = new GetMatchesOutputBody();
            response.setStatus(GetMatchesOutputBody.StatusEnum.COMPLETED);

            var functionMatch = new ai.reveng.model.FunctionMatch();
            functionMatch.setFunctionId(100L);
            functionMatch.setMatchedFunctions(List.of(
                    matchedFunction(200L, "zeta_match", 0.50),
                    matchedFunction(201L, "alpha_match", 0.95),
                    matchedFunction(202L, "mid_match", 0.72)
            ));
            response.setMatches(List.of(functionMatch));

            return response;
        }

        private static MatchedFunction matchedFunction(long id, String name, double similarity) {
            var matchedFunc = new MatchedFunction();
            matchedFunc.setFunctionId(id);
            matchedFunc.setFunctionName(name);
            matchedFunc.setMangledName(name);
            matchedFunc.setSha256Hash(Long.toString(id).repeat(64).substring(0, 64));
            matchedFunc.setBinaryName("libc.so");
            matchedFunc.setBinaryId(1L);
            matchedFunc.setFunctionVaddr(0x2000L + id);
            matchedFunc.setAnalysisId(12345L);
            matchedFunc.setDebug(false);
            matchedFunc.setSimilarity(similarity);
            matchedFunc.setConfidence(similarity);
            return matchedFunc;
        }

        @Override
        public List<String> getAssembly(TypedApiInterface.FunctionID functionID) {
            return List.of("push rbp", "mov rbp, rsp", "ret");
        }
    }

    /// A run that is cancelled and replaced must not reach the UI. Its thread, once its request came back,
    /// used to hide the progress bar of the run that replaced it on the way out.
    @Test
    public void testCancelledRunDoesNotHideTheNextRunsProgress() throws Exception {
        var tool = env.getTool();

        var mockApi = new StillRunningMockApi();
        var service = addMockedService(tool, mockApi);

        env.addPlugin(BinarySimilarityPlugin.class);

        var builder = newX64Program("test_binary");
        var testFunction = builder.createEmptyFunction("test_function", "0x1000", 50, Undefined.getUndefinedDataType(4));

        var analysedProgram = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(analysedProgram.program());
        waitForSwing();

        FunctionLevelFunctionMatchingDialog dialog = runSwing(() ->
            new FunctionLevelFunctionMatchingDialog(tool, analysedProgram, testFunction)
        );
        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(FunctionLevelFunctionMatchingDialog.class);

        JProgressBar progressBar = (JProgressBar) getInstanceField("matchingProgressBar", foundDialog);
        JLabel statusLabel = (JLabel) getInstanceField("statusLabel", foundDialog);
        // The first run's request is held by the mock, as a slow server would; while running, the Match button cancels
        waitForCondition(() -> mockApi.lastMatchingRequest != null, "Matching should start when the dialog opens");
        pressButton(findButtonByText(foundDialog.getComponent(), "Cancel"));
        waitForSwing();
        assertFalse("Cancelling should hide the progress bar", progressBar.isVisible());

        var firstRequest = mockApi.lastMatchingRequest;
        pressButton(findButtonByText(foundDialog.getComponent(), "Match Functions"));
        waitForCondition(() -> mockApi.lastMatchingRequest != firstRequest, "Pressing Match Functions should start a new run");
        waitForCondition(() -> statusLabel.getText().contains("step 2 of 4"),
                "The step reported by the server should be shown");

        // Only now does the cancelled run's request come back
        mockApi.firstStartGate.countDown();
        waitForCondition(() -> mockApi.firstStartReturned, "The cancelled run's request should return");
        Thread.sleep(200);
        waitForSwing();
        assertTrue("The cancelled run must not hide the new run's progress bar", progressBar.isVisible());

        close(foundDialog);
        waitForSwing();
    }

    /// Reports matching as still running, on the second of four steps, so a run never finishes on its own.
    /// The first request to start matching is held until {@link #firstStartGate} opens.
    static class StillRunningMockApi extends FunctionMatchingMockApi {
        final CountDownLatch firstStartGate = new CountDownLatch(1);
        volatile boolean firstStartReturned = false;
        private final AtomicInteger starts = new AtomicInteger();

        @Override
        public StartMatchingOutputBody startFunctionsMatching(StartMatchingForFunctionsInputBody request) {
            boolean first = starts.getAndIncrement() == 0;
            super.startFunctionsMatching(request);
            if (first) {
                // Like a blocking HTTP call, cancelling (an interrupt) doesn't cut this short
                boolean interrupted = false;
                while (true) {
                    try {
                        firstStartGate.await();
                        break;
                    } catch (InterruptedException e) {
                        interrupted = true;
                    }
                }
                if (interrupted) {
                    Thread.currentThread().interrupt();
                }
                firstStartReturned = true;
            }
            var response = new StartMatchingOutputBody();
            response.setStatus(StartMatchingOutputBody.StatusEnum.RUNNING);
            response.setStep("Searching for similar functions");
            response.setStepIndex(1L);
            response.setStepsTotal(4L);
            return response;
        }

        @Override
        public GetMatchesStatusOutputBody getFunctionsMatchingStatus(List<Long> functionIds) {
            var response = new GetMatchesStatusOutputBody();
            response.setStatus(GetMatchesStatusOutputBody.StatusEnum.RUNNING);
            response.setStep("Searching for similar functions");
            response.setStepIndex(1L);
            response.setStepsTotal(4L);
            return response;
        }
    }

    /**
     * Mock API implementation for function matching dialog tests.
     * Provides necessary responses for the dialog to function without a real server.
     */
    static class FunctionMatchingMockApi extends UnimplementedAPI {
        private final AnalysisStatus currentStatus = AnalysisStatus.Complete;
        boolean functionMatchingCalled = false;
        volatile StartMatchingForFunctionsInputBody lastMatchingRequest;

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
        public AnalysisBasicInfoOutputBody getAnalysisBasicInfo(TypedApiInterface.AnalysisID analysisID) {
            var basic = new AnalysisBasicInfoOutputBody();
            basic.setModelId(1L);
            basic.setModelName("test-model");
            basic.setBinaryName("test_binary");
            basic.setSha256Hash("0".repeat(64));
            return basic;
        }

        @Override
        public StartMatchingOutputBody startFunctionsMatching(StartMatchingForFunctionsInputBody request) {
            functionMatchingCalled = true;
            lastMatchingRequest = request;
            var response = new StartMatchingOutputBody();
            response.setStatus(StartMatchingOutputBody.StatusEnum.COMPLETED);
            return response;
        }

        @Override
        public GetMatchesStatusOutputBody getFunctionsMatchingStatus(List<Long> functionIds) {
            var response = new GetMatchesStatusOutputBody();
            response.setStatus(GetMatchesStatusOutputBody.StatusEnum.COMPLETED);
            return response;
        }

        @Override
        public GetMatchesOutputBody getFunctionsMatches(List<Long> functionIds) {
            var response = new GetMatchesOutputBody();
            response.setStatus(GetMatchesOutputBody.StatusEnum.COMPLETED);

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
            matchedFunc.setBinaryId(1L);
            matchedFunc.setFunctionVaddr(0x2000L);
            matchedFunc.setAnalysisId(12345L);
            matchedFunc.setDebug(false);
            matchedFunc.setSimilarity(0.95);
            matchedFunc.setConfidence(0.87);

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
        public FunctionSignatureBatch listFunctionSignatures(List<TypedApiInterface.FunctionID> functionIDs,
                                                             boolean includeDataTypes) {
            // No type info available
            return FunctionSignatureBatch.empty();
        }
    }
}
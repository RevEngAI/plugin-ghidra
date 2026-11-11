package ai.reveng;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses.RecentAnalysisDialog;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.model.AnalysisRecordBody;
import docking.DockingWindowManager;
import ghidra.framework.Log4jErrorLogger;
import ghidra.util.DefaultErrorLogger;
import ghidra.util.Msg;
import org.junit.Test;

import javax.swing.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
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

        // Create a test program with matching hash
        var builder = newX64Program("test_binary");
        builder.createMemory("test", "0x1000", 100);
        var program = builder.getProgram();

        // Show the tool with the program
        env.showTool(program);
        waitForSwing();

        // Set up event listener to capture the analysis status changed event
        AtomicBoolean eventReceived = new AtomicBoolean(false);
        AtomicReference<RevEngAIAnalysisStatusChangedEvent> receivedEvent = new AtomicReference<>();
        tool.addEventListener(RevEngAIAnalysisStatusChangedEvent.class, e -> {
            eventReceived.set(true);
            receivedEvent.set((RevEngAIAnalysisStatusChangedEvent) e);
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
        var tableModel = (docking.widgets.table.threaded.ThreadedTableModel<AnalysisRecordBody, ?>) tableModelField;

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
        assertEquals("Event status should match the analysis status",
                AnalysisStatus.Complete, receivedEvent.get().getStatus());

        GhidraRevengService.ProgramWithID eventProgramWithID = receivedEvent.get().getProgramWithBinaryID();
        assertNotNull("Event should contain ProgramWithID", eventProgramWithID);
        assertSame("Event program should be the same as our test program",
                program, eventProgramWithID.program());
        assertEquals("Event analysis ID should match mock data",
                RecentAnalysesMockApi.MOCK_ANALYSIS_ID, eventProgramWithID.analysisID().id());

        // Verify getKnownProgram returns the same program with the correct analysis ID
        var knownProgram = service.getKnownProgram(program);
        assertTrue("Program should be known after selection", knownProgram.isPresent());
        assertEquals("Known program analysis ID should match event analysis ID",
                eventProgramWithID.analysisID(), knownProgram.get().analysisID());
        assertSame("Known program should be the same instance as event program",
                eventProgramWithID.program(), knownProgram.get().program());
    }

    @Test
    public void testDoubleClickPicksAnalysisAndRightClickOffersPortal() throws Exception {
        var tool = env.getTool();
        var service = addMockedService(tool, new RecentAnalysesMockApi());

        var builder = newX64Program("test_binary");
        builder.createMemory("test", "0x1000", 100);
        var program = builder.getProgram();
        env.showTool(program);
        waitForSwing();

        AtomicBoolean eventReceived = new AtomicBoolean(false);
        tool.addEventListener(RevEngAIAnalysisStatusChangedEvent.class, e -> eventReceived.set(true));

        RecentAnalysisDialog dialog = runSwing(() -> new RecentAnalysisDialog(tool, program));
        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        var foundDialog = waitForDialogComponent(RecentAnalysisDialog.class);

        @SuppressWarnings("unchecked")
        var tableModel = (docking.widgets.table.threaded.ThreadedTableModel<AnalysisRecordBody, ?>)
                getInstanceField("recentAnalysesTableModel", foundDialog);
        waitForTableModel(tableModel);
        @SuppressWarnings("unchecked")
        var table = ((ghidra.util.table.GhidraFilterTable<AnalysisRecordBody>)
                getInstanceField("recentAnalysesTable", foundDialog)).getTable();

        clickTableCell(table, 0, 0, 1);
        assertFalse("Single click should only select", eventReceived.get());

        var cell = runSwing(() -> table.getCellRect(0, 0, true));
        var rightClick = new java.awt.event.MouseEvent(table, java.awt.event.MouseEvent.MOUSE_PRESSED,
                System.currentTimeMillis(), java.awt.event.InputEvent.BUTTON3_DOWN_MASK,
                cell.x + 1, cell.y + 1, 1, true, java.awt.event.MouseEvent.BUTTON3);
        runSwing(() -> table.dispatchEvent(rightClick));
        var popup = (JPopupMenu) getInstanceField("portalPopup", foundDialog);
        assertTrue("Right click should show the portal popup", runSwing(popup::isVisible));
        assertTrue("Right click should not reach the docking popup", rightClick.isConsumed());
        assertEquals(1, popup.getComponentCount());
        assertEquals("Open in Portal", ((JMenuItem) popup.getComponent(0)).getText());
        runSwing(() -> popup.setVisible(false));

        clickTableCell(table, 0, 0, 2);
        waitForCondition(eventReceived::get, "Double click should pick the analysis");
        assertEquals(RecentAnalysesMockApi.MOCK_ANALYSIS_ID,
                service.getKnownProgram(program).orElseThrow().analysisID().id());
    }

    @Test
    public void testDialogShowsRecentAnalyses() throws Exception {
        var tool = env.getTool();

        var mockApi = new RecentAnalysesMockApi();
        addMockedService(tool, mockApi);

        var builder = newX64Program("test_binary");
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

    @Test
    public void testPickSelectedWithoutSelectionDoesNothing() throws Exception {
        var tool = env.getTool();
        addMockedService(tool, new RecentAnalysesMockApi());

        var builder = newX64Program("test_binary");
        builder.createMemory("test", "0x1000", 100);
        var program = builder.getProgram();
        env.showTool(program);
        waitForSwing();

        List<Object> errors = new CopyOnWriteArrayList<>();
        Msg.setErrorLogger(new DefaultErrorLogger() {
            @Override
            public void error(Object originator, Object message, Throwable throwable) {
                errors.add(message);
            }
        });
        try {
            RecentAnalysisDialog dialog = runSwing(() -> new RecentAnalysisDialog(tool, program));
            runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
            var foundDialog = waitForDialogComponent(RecentAnalysisDialog.class);

            pressButton(findButtonByText(foundDialog.getComponent(), "Pick selected"));
            waitForTasks();
            waitForSwing();

            assertEquals(List.of(), errors);
            close(foundDialog);
        } finally {
            Msg.setErrorLogger(new Log4jErrorLogger());
        }
    }

    /**
     * Mock API implementation for recent analysis dialog tests.
     * Provides necessary responses for the dialog to function without a real server.
     */
    static class RecentAnalysesMockApi extends UnimplementedAPI {
        static final int MOCK_ANALYSIS_ID = 99999;
        static final int MOCK_BINARY_ID = 88888;

        @Override
        public List<AnalysisRecordBody> search(TypedApiInterface.BinaryHash hash) {
            // Return a single recent analysis result
            return List.of(
                new AnalysisRecordBody()
                    .analysisId((long) MOCK_ANALYSIS_ID)
                    .binaryId((long) MOCK_BINARY_ID)
                    .binaryName("test_binary")
                    .creation(java.time.OffsetDateTime.parse("2024-01-15T10:00:00Z"))
                    .modelId(1L)
                    .modelName("binnet-0.2-x86-linux")
                    .sha256Hash(hash.sha256())
                    .status(AnalysisStatus.Complete.name())
                    .baseAddress(0x0L)  // Default image base for x64 programs
                    .functionBoundariesHash("abc123hash")
            );
        }

        @Override
        public AnalysisStatus status(TypedApiInterface.AnalysisID analysisID) {
            assertEquals("Analysis ID should match mock data", MOCK_ANALYSIS_ID, analysisID.id());
            return AnalysisStatus.Complete;
        }
    }
}
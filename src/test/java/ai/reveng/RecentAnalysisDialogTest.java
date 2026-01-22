package ai.reveng;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses.RecentAnalysisDialog;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryID;
import ai.reveng.toolkit.ghidra.core.services.api.types.LegacyAnalysisResult;
import docking.DockingWindowManager;
import ghidra.program.database.ProgramBuilder;
import org.junit.Test;

import javax.swing.*;
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

        // Create a test program with matching hash
        var builder = new ProgramBuilder("test_binary", ProgramBuilder._X64, this);
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
    }
}
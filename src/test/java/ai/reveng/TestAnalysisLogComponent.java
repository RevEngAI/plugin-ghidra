package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc.AnalysisLogComponent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.StatusPoller;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.plugins.AnalysisManagementPlugin;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import docking.DefaultActionContext;
import docking.widgets.OptionDialog;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitorComponent;
import org.junit.Test;

import javax.swing.JTextArea;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class TestAnalysisLogComponent extends RevEngMockableHeadedIntegrationTest {

    private GhidraRevengService.ProgramWithID getPlaceHolderID() throws Exception{
        var builder = newX64Program();
        // Add an example function
        var program = builder.getProgram();
        return new GhidraRevengService.ProgramWithID(
                program,
                new TypedApiInterface.AnalysisID(1)
        );
    }

    /// If a user starts Ghidra for a program with an associated analysis that is still processing on the server,
    /// then the analysis log component should show that the analysis is still processing, and automatically
    /// fetch the logs and fire
    ///
    @Test
    public void testResumeWaitingForProcessingAnalysis() throws Exception{
        var defaultTool = env.showTool();

        addMockedService(defaultTool, new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return AnalysisStatus.Processing;
            }
        });

//        defaultTool.getService(GhidraRevengService.class);
        env.addPlugin(AnalysisManagementPlugin.class);
        var programWithID = getPlaceHolderID();
        defaultTool.firePluginEvent(
                new RevEngAIAnalysisStatusChangedEvent(
                        "Test",
                        programWithID,
                        AnalysisStatus.Processing
                )
        );
        waitForSwing();
        // The analysis log component should now be visible, and have a task
        var logComponent = defaultTool.getComponentProvider(AnalysisLogComponent.NAME);
        assertNotNull(logComponent);
        Map<Program, Task> trackedPrograms = (Map<Program, Task>) getInstanceField("trackedPrograms", logComponent);
        assertNotNull(trackedPrograms);
        assertTrue(trackedPrograms.containsKey(programWithID.program()));
    }


    @Test
    public void testFullAnalysisFlow() throws Exception {
        var defaultTool = env.showTool();
        var programWithID = getPlaceHolderID();

        addMockedService(defaultTool, new UnimplementedAPI() {
                    private final Map<AnalysisID, AnalysisStatus> statusMap = new HashMap<>();

                    {
                        statusMap.put(programWithID.analysisID(), AnalysisStatus.Queued);
                    }

                    @Override
                    public AnalysisStatus status(AnalysisID analysisID) {
                        var nextStatus = getNextStatus(statusMap.get(analysisID));
                        statusMap.put(analysisID, nextStatus);
                        return nextStatus;
                    }

                    @Override
                    public String getAnalysisLogs(AnalysisID analysisID) {
                        var status = statusMap.get(analysisID);
                        return "PLACEHOLDER_LOGS";
                    }

                    @Override
                    public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
                        return List.of();
                    }
                }
        );
        env.addPlugin(AnalysisManagementPlugin.class);
        // Start a new analysis that is queued
        defaultTool.firePluginEvent(
                new RevEngAIAnalysisStatusChangedEvent(
                        "Test",
                        programWithID,
                        AnalysisStatus.Queued
                )
        );

        AnalysisLogComponent logComponent = (AnalysisLogComponent) defaultTool.getComponentProvider(AnalysisLogComponent.NAME);
        var trackedPrograms =  (Map<Program, Task>) getInstanceField("trackedPrograms", logComponent);
        assertNotNull(trackedPrograms);
        assertTrue(trackedPrograms.containsKey(programWithID.program()));
        waitForTasks();

        // Check that it is cleared out again after the task finished
        assertFalse(trackedPrograms.containsKey(programWithID.program()));
        // Check that the taskmonitor is hidden again and isn't sitting there forever
        TaskMonitorComponent taskMonitorComponent = (TaskMonitorComponent) getInstanceField("taskMonitorComponent", logComponent);
        assertFalse(taskMonitorComponent.isVisible());
    }

    @Test
    public void testTransientServerErrorsDoNotStopMonitoring() throws Exception {
        var defaultTool = env.showTool();
        var programWithID = getPlaceHolderID();
        var statusCalls = new AtomicInteger();
        var logCalls = new AtomicInteger();

        addMockedService(defaultTool, new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) throws ApiException {
                return switch (statusCalls.incrementAndGet()) {
                    case 1 -> throw new ApiException(503, "Service Unavailable");
                    case 2 -> AnalysisStatus.Processing;
                    default -> AnalysisStatus.Complete;
                };
            }

            @Override
            public String getAnalysisLogs(AnalysisID analysisID) {
                if (logCalls.incrementAndGet() == 1) {
                    throw new RuntimeException(new ApiException(500, "Internal Server Error"));
                }
                return "PLACEHOLDER_LOGS";
            }

            @Override
            public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
                return List.of();
            }
        });
        env.addPlugin(AnalysisManagementPlugin.class);
        defaultTool.firePluginEvent(
                new RevEngAIAnalysisStatusChangedEvent("Test", programWithID, AnalysisStatus.Queued)
        );

        AnalysisLogComponent logComponent = (AnalysisLogComponent) defaultTool.getComponentProvider(AnalysisLogComponent.NAME);
        var trackedPrograms = (Map<Program, Task>) getInstanceField("trackedPrograms", logComponent);
        waitForTasks();

        assertTrue(statusCalls.get() >= 3);
        assertFalse(trackedPrograms.containsKey(programWithID.program()));
    }

    @Test
    public void testCancelledMonitoringUntracksProgram() throws Exception {
        var defaultTool = env.showTool();
        var programWithID = getPlaceHolderID();

        addMockedService(defaultTool, new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return AnalysisStatus.Queued;
            }
        });
        env.addPlugin(AnalysisManagementPlugin.class);
        defaultTool.firePluginEvent(
                new RevEngAIAnalysisStatusChangedEvent("Test", programWithID, AnalysisStatus.Queued)
        );

        AnalysisLogComponent logComponent = (AnalysisLogComponent) defaultTool.getComponentProvider(AnalysisLogComponent.NAME);
        var trackedPrograms = (Map<Program, Task>) getInstanceField("trackedPrograms", logComponent);
        TaskMonitorComponent taskMonitor = (TaskMonitorComponent) getInstanceField("taskMonitorComponent", logComponent);
        taskMonitor.cancel();
        waitForTasks();

        assertFalse(trackedPrograms.containsKey(programWithID.program()));
        TaskMonitorComponent taskMonitorComponent = (TaskMonitorComponent) getInstanceField("taskMonitorComponent", logComponent);
        assertFalse(taskMonitorComponent.isVisible());
    }

    /// An analysis that was still Uploaded when Ghidra closed is waited on again when the program is reopened
    @Test
    public void testReopenedUploadedAnalysisIsWaitedOn() throws Exception {
        var defaultTool = env.getTool();
        var statusCalls = new AtomicInteger();
        var service = addMockedService(defaultTool, new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                // Error ends the wait without loading results, which this mock does not provide
                return statusCalls.incrementAndGet() <= 2 ? AnalysisStatus.Uploaded : AnalysisStatus.Error;
            }
        });
        env.addPlugin(AnalysisManagementPlugin.class);
        var program = newX64Program().getProgram();
        service.registerAnalysisForProgram(program, new TypedApiInterface.AnalysisID(1));

        // Waits for the tool to be idle, so also for the monitoring task the reopen starts
        env.showTool(program);
        waitForTasks();

        // The check on reopen, then the monitoring task polling until the analysis ends
        assertEquals(3, statusCalls.get());
        AnalysisLogComponent logComponent = (AnalysisLogComponent) defaultTool.getComponentProvider(AnalysisLogComponent.NAME);
        var trackedPrograms = (Map<Program, Task>) getInstanceField("trackedPrograms", logComponent);
        assertFalse(trackedPrograms.containsKey(program));
        // The wait ended in Error, which is reported
        pressButtonByText(waitForDialogComponent(null, OptionDialog.class, 30_000), "Keep attached");
    }

    private static final String FAILED_ANALYSIS_LOGS = "Unpacking binary\nDisassembling\nFATAL: worker ran out of memory\n";

    /// An analysis that always reports Error, with a log whose last line says why
    private static class FailedAnalysisAPI extends UnimplementedAPI {
        final AtomicInteger logCalls = new AtomicInteger();

        @Override
        public AnalysisStatus status(AnalysisID analysisID) {
            return AnalysisStatus.Error;
        }

        @Override
        public String getAnalysisLogs(AnalysisID analysisID) {
            logCalls.incrementAndGet();
            return FAILED_ANALYSIS_LOGS;
        }
    }

    /// The error dialog, once the work that leads to it has run: the Queued event starts the wait (a task), the wait
    /// fires the Error event (Swing), which starts the log fetch (a task), which shows the dialog (Swing). How many
    /// rounds that takes varies between machines, so poll for the dialog; the limit only bounds a broken run.
    private OptionDialog awaitErrorDialog() {
        var dialog = waitForDialogComponent(null, OptionDialog.class, 30_000);
        assertNotNull("the failed analysis should be reported", dialog);
        return dialog;
    }

    private String logText(AnalysisLogComponent logComponent) {
        return runSwing(() -> ((JTextArea) getInstanceField("textArea", logComponent)).getText());
    }

    /// An analysis started in the session that fails on the server is reported with the end of its log, and
    /// Detach in that report frees the program for a new analysis, like the Detach action does
    @Test
    public void testErrorDuringSessionOffersDetach() throws Exception {
        var tool = env.getTool();
        var service = addMockedService(tool, new FailedAnalysisAPI());
        env.addPlugin(AnalysisManagementPlugin.class);
        var program = newX64Program().getProgram();
        env.showTool(program);
        // As StartAnalysisTask does: associate the program, then report the analysis as queued
        var programWithID = service.registerAnalysisForProgram(program, new TypedApiInterface.AnalysisID(7));
        tool.firePluginEvent(new RevEngAIAnalysisStatusChangedEvent("StartAnalysisTask", programWithID, AnalysisStatus.Queued));

        var dialog = awaitErrorDialog();
        assertTrue(dialog.getMessage(), dialog.getMessage().contains("analysis 7 of " + program.getName() + " failed"));
        assertTrue(dialog.getMessage(), dialog.getMessage().contains("FATAL: worker ran out of memory"));
        var context = new DefaultActionContext();
        assertFalse(getAction(tool, "Create new").isEnabledForContext(context));

        pressButtonByText(dialog, "Detach");
        waitForSwing();

        assertTrue(service.getKnownProgram(program).isEmpty());
        assertTrue(getAction(tool, "Create new").isEnabledForContext(context));
        assertTrue(getAction(tool, "Attach to existing").isEnabledForContext(context));
        assertFalse(getAction(tool, "Detach").isEnabledForContext(context));

        // The log panel says how the analysis ended instead of stopping at the last log line
        AnalysisLogComponent logComponent = (AnalysisLogComponent) tool.getComponentProvider(AnalysisLogComponent.NAME);
        var text = logText(logComponent);
        assertTrue(text, text.contains("FATAL: worker ran out of memory"));
        assertTrue(text, text.endsWith(AnalysisLogComponent.terminalStatusLine(AnalysisStatus.Error, 7)));
    }

    /// Keeping the failed analysis attached leaves the association alone, and the same failure is not reported again
    @Test
    public void testKeepAttachedReportsFailureOnce() throws Exception {
        var tool = env.getTool();
        var service = addMockedService(tool, new FailedAnalysisAPI());
        env.addPlugin(AnalysisManagementPlugin.class);
        var program = newX64Program().getProgram();
        env.showTool(program);
        var programWithID = service.registerAnalysisForProgram(program, new TypedApiInterface.AnalysisID(7));
        tool.firePluginEvent(new RevEngAIAnalysisStatusChangedEvent("StartAnalysisTask", programWithID, AnalysisStatus.Queued));

        pressButtonByText(awaitErrorDialog(), "Keep attached");
        waitForSwing();
        assertEquals(Optional.of(programWithID), service.getKnownProgram(program));

        // The same failure reported again, e.g. by Check status or a repeated event
        tool.firePluginEvent(new RevEngAIAnalysisStatusChangedEvent("Test", programWithID, AnalysisStatus.Error));
        waitForSwing();
        waitForTasks();
        waitForSwing();
        assertNull(getDialogComponent(OptionDialog.class));
    }

    /// A program reopened with an analysis that failed while Ghidra was closed gets the same single report
    @Test
    public void testReopenedFailedAnalysisIsReportedOnce() throws Exception {
        var tool = env.getTool();
        var api = new FailedAnalysisAPI();
        var service = addMockedService(tool, api);
        env.addPlugin(AnalysisManagementPlugin.class);
        var program = newX64Program().getProgram();
        service.registerAnalysisForProgram(program, new TypedApiInterface.AnalysisID(7));

        env.showTool(program);
        var dialog = waitForDialogComponent(null, OptionDialog.class, 30_000);
        assertTrue(dialog.getMessage(), dialog.getMessage().contains("FATAL: worker ran out of memory"));
        pressButtonByText(dialog, "Detach");
        waitForSwing();
        waitForTasks();

        assertTrue(service.getKnownProgram(program).isEmpty());
        assertNull(getDialogComponent(OptionDialog.class));
        // Only the report fetched the log: nothing waits on an analysis that has already ended
        assertEquals(1, api.logCalls.get());
    }

    @Test
    public void testTerminalStatusText() {
        assertEquals("RevEng.AI: analysis 3 completed.", AnalysisLogComponent.terminalStatusLine(AnalysisStatus.Complete, 3));
        var error = AnalysisLogComponent.terminalStatusLine(AnalysisStatus.Error, 3);
        assertTrue(error, error.contains("analysis 3 failed on the server"));
        assertTrue(error, error.contains("Detach"));
        assertNull(AnalysisLogComponent.terminalStatusLine(AnalysisStatus.Processing, 3));

        assertEquals(AnalysisLogComponent.NO_LOGS, AnalysisLogComponent.withTerminalStatus(null, null));
        assertEquals("a\nb", AnalysisLogComponent.withTerminalStatus("a\nb", null));
        assertEquals("done", AnalysisLogComponent.withTerminalStatus("  ", "done"));
        assertEquals("a\nb\n\ndone", AnalysisLogComponent.withTerminalStatus("a\nb\n", "done"));
    }

    /// A new analysis for the program clears how the previous one ended
    @Test
    public void testNewAnalysisClearsTerminalStatus() throws Exception {
        var tool = env.getTool();
        addMockedService(tool, new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return AnalysisStatus.Queued;
            }
        });
        env.addPlugin(AnalysisManagementPlugin.class);
        var program = newX64Program().getProgram();
        env.showTool(program);
        AnalysisLogComponent logComponent = (AnalysisLogComponent) tool.getComponentProvider(AnalysisLogComponent.NAME);
        var finished = new GhidraRevengService.ProgramWithID(program, new TypedApiInterface.AnalysisID(3));
        // Delivered to the log component directly: the plugin would load results for a Complete event
        runSwing(() -> logComponent.processEvent(
                new RevEngAIAnalysisStatusChangedEvent("Test", finished, AnalysisStatus.Complete)));
        assertEquals(AnalysisLogComponent.terminalStatusLine(AnalysisStatus.Complete, 3), logText(logComponent));

        var next = new GhidraRevengService.ProgramWithID(program, new TypedApiInterface.AnalysisID(4));
        runSwing(() -> logComponent.processEvent(
                new RevEngAIAnalysisStatusChangedEvent("Test", next, AnalysisStatus.Queued)));
        assertEquals(AnalysisLogComponent.NO_LOGS, logText(logComponent));
        TaskMonitorComponent taskMonitor = (TaskMonitorComponent) getInstanceField("taskMonitorComponent", logComponent);
        taskMonitor.cancel();
        waitForTasks();
    }

    /// An analysis reporting an unrecognised status on reopen is reported, not waited on
    @Test
    public void testReopenedUnknownAnalysisIsNotWaitedOn() throws Exception {
        var defaultTool = env.getTool();
        var statusCalls = new AtomicInteger();
        var service = addMockedService(defaultTool, new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                statusCalls.incrementAndGet();
                return AnalysisStatus.Unknown;
            }
        });
        env.addPlugin(AnalysisManagementPlugin.class);
        var program = newX64Program().getProgram();
        service.registerAnalysisForProgram(program, new TypedApiInterface.AnalysisID(1));

        env.showTool(program);
        waitForCondition(() -> statusCalls.get() > 0, "the status should be checked on reopen");
        waitForTasks();
        waitForSwing();

        AnalysisLogComponent logComponent = (AnalysisLogComponent) defaultTool.getComponentProvider(AnalysisLogComponent.NAME);
        var trackedPrograms = (Map<Program, Task>) getInstanceField("trackedPrograms", logComponent);
        assertFalse(trackedPrograms.containsKey(program));
        assertEquals(1, statusCalls.get());
    }

    /// An Unknown status neither starts a wait (it would end at once) nor restarts one when its event arrives late
    @Test
    public void testUnknownStatusIsNotMonitored() throws Exception {
        var defaultTool = env.showTool();
        var programWithID = getPlaceHolderID();
        var statusCalls = new AtomicInteger();

        addMockedService(defaultTool, new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                statusCalls.incrementAndGet();
                return AnalysisStatus.Unknown;
            }
        });
        env.addPlugin(AnalysisManagementPlugin.class);
        defaultTool.firePluginEvent(
                new RevEngAIAnalysisStatusChangedEvent("Test", programWithID, AnalysisStatus.Unknown)
        );
        waitForSwing();
        waitForTasks();

        AnalysisLogComponent logComponent = (AnalysisLogComponent) defaultTool.getComponentProvider(AnalysisLogComponent.NAME);
        var trackedPrograms = (Map<Program, Task>) getInstanceField("trackedPrograms", logComponent);
        assertFalse(trackedPrograms.containsKey(programWithID.program()));
        assertEquals(0, statusCalls.get());
    }

    /// A wait that ends on an Unknown status is reported once and is not restarted by its own status event
    @Test
    public void testWaitEndingOnUnknownStatusStops() throws Exception {
        var defaultTool = env.showTool();
        var programWithID = getPlaceHolderID();
        var statusCalls = new AtomicInteger();

        addMockedService(defaultTool, new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return statusCalls.incrementAndGet() == 1 ? AnalysisStatus.Processing : AnalysisStatus.Unknown;
            }
        });
        env.addPlugin(AnalysisManagementPlugin.class);
        defaultTool.firePluginEvent(
                new RevEngAIAnalysisStatusChangedEvent("Test", programWithID, AnalysisStatus.Queued)
        );
        waitForTasks();
        waitForSwing();
        waitForTasks();

        AnalysisLogComponent logComponent = (AnalysisLogComponent) defaultTool.getComponentProvider(AnalysisLogComponent.NAME);
        var trackedPrograms = (Map<Program, Task>) getInstanceField("trackedPrograms", logComponent);
        assertFalse(trackedPrograms.containsKey(programWithID.program()));
        assertEquals(2, statusCalls.get());
        TaskMonitorComponent taskMonitorComponent = (TaskMonitorComponent) getInstanceField("taskMonitorComponent", logComponent);
        assertFalse(taskMonitorComponent.isVisible());
    }

    @Test
    public void testUnfinishedWaitMessages() throws Exception {
        var programWithID = getPlaceHolderID();
        var name = programWithID.program().getName();

        var unrecognised = AnalysisLogComponent.unfinishedWaitMessage(
                new StatusPoller.Result<>(StatusPoller.Ending.UNRECOGNISED, AnalysisStatus.Unknown, Duration.ofSeconds(3)),
                programWithID);
        assertTrue(unrecognised, unrecognised.contains("analysis 1 of " + name));
        assertTrue(unrecognised, unrecognised.contains("does not recognise"));

        var timedOut = AnalysisLogComponent.unfinishedWaitMessage(
                new StatusPoller.Result<>(StatusPoller.Ending.TIMED_OUT, AnalysisStatus.Processing, Duration.ofHours(3).minusSeconds(2)),
                programWithID);
        assertTrue(timedOut, timedOut.contains("has not finished after 3 hours (status: Processing)"));
        assertTrue(timedOut, timedOut.contains("reopen the program"));

        assertNull(AnalysisLogComponent.unfinishedWaitMessage(
                new StatusPoller.Result<>(StatusPoller.Ending.DONE, AnalysisStatus.Complete, Duration.ZERO), programWithID));
        assertNull(AnalysisLogComponent.unfinishedWaitMessage(
                new StatusPoller.Result<>(StatusPoller.Ending.CANCELLED, AnalysisStatus.Queued, Duration.ZERO), programWithID));
    }
}

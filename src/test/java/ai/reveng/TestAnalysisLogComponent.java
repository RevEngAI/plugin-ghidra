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
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitorComponent;
import org.junit.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

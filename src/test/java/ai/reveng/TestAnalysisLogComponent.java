package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc.AnalysisLogComponent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.plugins.AnalysisManagementPlugin;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitorComponent;
import org.junit.Test;

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
}

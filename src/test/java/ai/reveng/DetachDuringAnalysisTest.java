package ai.reveng;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc.AnalysisLogComponent;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisResultsLoaded;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.plugins.AnalysisManagementPlugin;
import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitorComponent;
import org.junit.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

/// Detaching or closing a program while its analysis is still being waited on (ENG-4590)
public class DetachDuringAnalysisTest extends RevEngMockableHeadedIntegrationTest {

    private static final TypedApiInterface.AnalysisID OLD = new TypedApiInterface.AnalysisID(1);
    private static final TypedApiInterface.AnalysisID NEW = new TypedApiInterface.AnalysisID(2);

    /// Analyses stay Processing until marked finished; function info requests are recorded
    private static class RunningAnalysesAPI extends UnimplementedAPI {
        final Set<AnalysisID> finished = ConcurrentHashMap.newKeySet();
        final Map<AnalysisID, AtomicInteger> statusCalls = new ConcurrentHashMap<>();
        final AtomicInteger functionInfoCalls = new AtomicInteger();

        int statusCalls(AnalysisID id) {
            return statusCalls.computeIfAbsent(id, k -> new AtomicInteger()).get();
        }

        @Override
        public AnalysisStatus status(AnalysisID analysisID) {
            statusCalls.computeIfAbsent(analysisID, k -> new AtomicInteger()).incrementAndGet();
            return finished.contains(analysisID) ? AnalysisStatus.Complete : AnalysisStatus.Processing;
        }

        @Override
        public String getAnalysisLogs(AnalysisID analysisID) {
            return "logs of analysis " + analysisID.id();
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
            functionInfoCalls.incrementAndGet();
            return List.of();
        }
    }

    private record Fixture(PluginTool tool, GhidraRevengService service, RunningAnalysesAPI api, Program program,
                           AnalysisLogComponent logComponent) {

        @SuppressWarnings("unchecked")
        Map<Program, Task> trackedPrograms() {
            return (Map<Program, Task>) getInstanceField("trackedPrograms", logComponent);
        }

        /// The analysis the program's wait is for, or empty when nothing waits for it
        Optional<GhidraRevengService.ProgramWithID> monitoredAnalysis() {
            return Optional.ofNullable(trackedPrograms().get(program))
                    .map(task -> (GhidraRevengService.ProgramWithID) getInstanceField("program", task));
        }

        /// As StartAnalysisTask does: attach the program, then report the analysis as queued
        GhidraRevengService.ProgramWithID startAnalysis(TypedApiInterface.AnalysisID id) {
            var programWithID = service.registerAnalysisForProgram(program, id);
            runSwing(() -> tool.firePluginEvent(
                    new RevEngAIAnalysisStatusChangedEvent("StartAnalysisTask", programWithID, AnalysisStatus.Queued)));
            return programWithID;
        }

        void stopAllWaits() {
            ((TaskMonitorComponent) getInstanceField("taskMonitorComponent", logComponent)).cancel();
            waitForTasks();
        }
    }

    private Fixture fixture() throws Exception {
        var tool = env.getTool();
        var api = new RunningAnalysesAPI();
        var service = addMockedService(tool, api);
        env.addPlugin(AnalysisManagementPlugin.class);
        var program = newX64Program().getProgram();
        env.showTool(program);
        var logComponent = (AnalysisLogComponent) tool.getComponentProvider(AnalysisLogComponent.NAME);
        return new Fixture(tool, service, api, program, logComponent);
    }

    /// Detach through the menu action and its confirmation, as the analyst does
    private void detach(Fixture fixture) {
        performAction(getAction(fixture.tool(), "Detach"), false);
        pressButtonByText(awaitDialog(OptionDialog.class), "Detach");
        waitForSwing();
        assertTrue(fixture.service().getKnownProgram(fixture.program()).isEmpty());
    }

    /// Polls for a dialog against this test's own deadline: the timeout that waitForDialogComponent takes is
    /// ignored in favour of Ghidra's 2s default
    private static <T extends DialogComponentProvider> T awaitDialog(Class<T> type) {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        T dialog;
        while ((dialog = getDialogComponent(type)) == null && System.nanoTime() < deadline) {
            sleep(DEFAULT_WAIT_DELAY);
        }
        assertNotNull("timed out waiting for " + type.getSimpleName(), dialog);
        return dialog;
    }

    private static boolean hasFunctionIds(Program program) {
        return program.getUsrPropertyManager().getLongPropertyMap("RevEngAI_FunctionID_Map") != null;
    }

    /// Detach stops the wait for the old analysis, and its Complete arriving late loads nothing into the
    /// program, which is now attached to another analysis
    @Test
    public void testLateCompleteAfterDetachIsIgnored() throws Exception {
        var fixture = fixture();
        var old = fixture.startAnalysis(OLD);
        waitForCondition(() -> fixture.api().statusCalls(OLD) > 0, "the old analysis should be waited on");
        var resultsLoaded = new AtomicBoolean();
        fixture.tool().addEventListener(RevEngAIAnalysisResultsLoaded.class, e -> resultsLoaded.set(true));

        detach(fixture);
        waitForCondition(() -> fixture.monitoredAnalysis().isEmpty(), "detaching should stop the wait");
        // Attached to another analysis, e.g. through Attach to existing
        var current = fixture.service().registerAnalysisForProgram(fixture.program(), NEW);

        // The old analysis now finishes, and its Complete arrives from a wait that had not noticed the detach yet
        fixture.api().finished.add(OLD);
        runSwing(() -> fixture.tool().firePluginEvent(
                new RevEngAIAnalysisStatusChangedEvent(null, old, AnalysisStatus.Complete)));
        waitForTasks();
        waitForSwing();

        assertEquals("the old analysis' results should not be fetched", 0, fixture.api().functionInfoCalls.get());
        assertFalse("no function ids should be written", hasFunctionIds(fixture.program()));
        assertFalse(resultsLoaded.get());
        assertEquals(Optional.of(current), fixture.service().getKnownProgram(fixture.program()));
    }

    /// After Detach, a new analysis of the same program is waited on
    @Test
    public void testNewAnalysisAfterDetachIsMonitored() throws Exception {
        var fixture = fixture();
        fixture.startAnalysis(OLD);
        waitForCondition(() -> fixture.monitoredAnalysis().isPresent(), "the old analysis should be waited on");

        detach(fixture);
        var oldCalls = fixture.api().statusCalls(OLD);
        var next = fixture.startAnalysis(NEW);

        assertEquals(Optional.of(next), fixture.monitoredAnalysis());
        waitForCondition(() -> fixture.api().statusCalls(NEW) > 0, "the new analysis should be polled");
        // Polling continues for the new analysis only
        waitForCondition(() -> fixture.api().statusCalls(NEW) > 1, "the new analysis should keep being polled");
        assertTrue(fixture.api().statusCalls(OLD) <= oldCalls + 1);

        fixture.stopAllWaits();
        assertTrue(fixture.monitoredAnalysis().isEmpty());
    }

    /// Closing the program stops the wait, and forgets the program's logs
    @Test
    public void testClosingProgramStopsMonitoring() throws Exception {
        var fixture = fixture();
        fixture.startAnalysis(OLD);
        waitForCondition(() -> fixture.logComponent().getStoredLogs(fixture.program()) != null,
                "the analysis logs should arrive");

        runSwing(() -> fixture.tool().getService(ProgramManager.class).closeProgram(fixture.program(), true));
        waitForTasks();

        assertTrue(fixture.trackedPrograms().isEmpty());
        assertNull(fixture.logComponent().getStoredLogs(fixture.program()));
        var calls = fixture.api().statusCalls(OLD);
        sleep(1_500);
        assertEquals("the closed program's analysis should no longer be polled", calls, fixture.api().statusCalls(OLD));
    }
}

package ai.reveng;

import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import org.junit.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;

import static org.junit.Assert.assertEquals;

/// Ghidra drops an event fired while another of the same type is being delivered, taking it for an event loop. A wait
/// reports its first status from a background thread, which on a slow machine can be while the Queued event that
/// started it is still being delivered; the Error or Complete it reported was then lost.
public class StatusEventDeliveryTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void aStatusFiredLaterDuringAnotherStatusDeliveryArrives() throws Exception {
        var received = deliverQueuedThenFireFromBackground(RevEngAIAnalysisStatusChangedEvent::fireLater);

        assertEquals(List.of(AnalysisStatus.Queued, AnalysisStatus.Error), received);
    }

    /// Documents the Ghidra behaviour fireLater works around, so a Ghidra version that stops dropping these is noticed
    @Test
    public void aStatusFiredDirectlyDuringAnotherStatusDeliveryIsDropped() throws Exception {
        var received = deliverQueuedThenFireFromBackground((event, tool) -> tool.firePluginEvent(event));

        assertEquals(List.of(AnalysisStatus.Queued), received);
    }

    /// Fires Queued; while it is being delivered, a background thread fires Error with {@code fire} and is waited for
    private List<AnalysisStatus> deliverQueuedThenFireFromBackground(
            BiConsumer<RevEngAIAnalysisStatusChangedEvent, PluginTool> fire) throws Exception {
        var tool = env.getTool();
        var program = newX64Program().getProgram();
        var programWithID = new GhidraRevengService.ProgramWithID(program, new TypedApiInterface.AnalysisID(7));
        List<AnalysisStatus> received = new CopyOnWriteArrayList<>();

        tool.addListenerForAllPluginEvents((PluginEvent event) -> {
            if (!(event instanceof RevEngAIAnalysisStatusChangedEvent status)) {
                return;
            }
            received.add(status.getStatus());
            if (status.getStatus() == AnalysisStatus.Queued) {
                var waitThread = new Thread(() -> fire.accept(
                        new RevEngAIAnalysisStatusChangedEvent(null, programWithID, AnalysisStatus.Error), tool));
                waitThread.start();
                try {
                    waitThread.join();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        });

        runSwing(() -> tool.firePluginEvent(
                new RevEngAIAnalysisStatusChangedEvent("StartAnalysisTask", programWithID, AnalysisStatus.Queued)));
        waitForSwing();
        return List.copyOf(received);
    }
}

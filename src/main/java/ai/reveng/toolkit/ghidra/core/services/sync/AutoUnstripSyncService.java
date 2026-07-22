package ai.reveng.toolkit.ghidra.core.services.sync;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService.AnalysedProgram;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AutoUnstripStatus;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

/**
 * Polls the server-side auto-unstrip status after an analysis completes and, once it finishes,
 * syncs the recovered function names and data types back into Ghidra (PLU-300). Auto-unstrip runs
 * after the analysis is marked complete (PRO-2976), so its results are not present in the initial
 * pull and would otherwise only appear after a manual refresh.
 *
 * <p>Mirrors the IDA plugin's {@code AutoUnstripStatusService} + {@code AutoUnstripStatusCoordinator}:
 * a background thread polls the status endpoint every {@link #POLL_INTERVAL_SECONDS} seconds and, on
 * completion, runs the same reconciliation the "Sync With Portal" action uses.
 */
public class AutoUnstripSyncService {

    private static final long POLL_INTERVAL_SECONDS = 5;

    private final GhidraRevengService revengService;
    private final ReaiLoggingService loggingService;
    /// Surfaces a progress message to the user (text, isWarning); wired to the tool status bar in the plugin.
    private final BiConsumer<String, Boolean> statusNotifier;
    private final ScheduledExecutorService scheduler;
    private final Map<AnalysisID, ScheduledFuture<?>> pollers = new ConcurrentHashMap<>();

    public AutoUnstripSyncService(GhidraRevengService revengService, ReaiLoggingService loggingService,
                                  BiConsumer<String, Boolean> statusNotifier) {
        this.revengService = revengService;
        this.loggingService = loggingService;
        this.statusNotifier = statusNotifier;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            var thread = new Thread(runnable, "RevEng.AI-AutoUnstripSync");
            thread.setDaemon(true);
            return thread;
        });
    }

    /**
     * Start polling the auto-unstrip status for the given analysis; when it completes, sync the
     * recovered names and data types into Ghidra. Any in-flight poll for the same analysis is cancelled.
     *
     * @param resyncIfAlreadyComplete when {@code true}, sync even if the very first poll already reports
     *     completion (auto-unstrip may have finished between analysis completion and the first poll);
     *     when {@code false}, an already-complete unstrip is assumed to be reflected in the initial pull
     *     and is not re-synced.
     */
    public void pollAndSync(AnalysedProgram analysedProgram, boolean resyncIfAlreadyComplete) {
        stopPolling(analysedProgram.analysisID());
        schedule(analysedProgram, resyncIfAlreadyComplete, true, 0);
    }

    public void stopPolling(AnalysisID analysisID) {
        var existing = pollers.remove(analysisID);
        if (existing != null) {
            existing.cancel(false);
        }
    }

    public void dispose() {
        pollers.values().forEach(future -> future.cancel(false));
        pollers.clear();
        scheduler.shutdownNow();
    }

    private void schedule(AnalysedProgram analysedProgram, boolean resyncIfAlreadyComplete,
                          boolean firstPoll, long delaySeconds) {
        var future = scheduler.schedule(
                () -> poll(analysedProgram, resyncIfAlreadyComplete, firstPoll),
                delaySeconds, TimeUnit.SECONDS);
        pollers.put(analysedProgram.analysisID(), future);
    }

    private void poll(AnalysedProgram analysedProgram, boolean resyncIfAlreadyComplete, boolean firstPoll) {
        AutoUnstripStatus status;
        try {
            status = revengService.getAutoUnstripStatus(analysedProgram.analysisID());
        } catch (ApiException e) {
            pollers.remove(analysedProgram.analysisID());
            loggingService.warn("Failed to poll auto-unstrip status: " + e.getMessage());
            return;
        }

        switch (status) {
            case COMPLETED -> {
                pollers.remove(analysedProgram.analysisID());
                if (firstPoll && !resyncIfAlreadyComplete) {
                    return;
                }
                runSync(analysedProgram);
            }
            case FAILED -> {
                pollers.remove(analysedProgram.analysisID());
                announce("RevEng.AI auto-unstrip failed; recovered names were not synced.", true);
            }
            default -> {
                if (firstPoll) {
                    announce("RevEng.AI: waiting for auto-unstrip to finish before syncing recovered "
                            + "function names and data types…", false);
                }
                schedule(analysedProgram, resyncIfAlreadyComplete, false, POLL_INTERVAL_SECONDS);
            }
        }
    }

    private void runSync(AnalysedProgram analysedProgram) {
        announce("RevEng.AI: auto-unstrip finished; syncing recovered function names and data types…", false);
        try {
            var summary = revengService.syncAnalysisUpdates(analysedProgram, TaskMonitor.DUMMY, loggingService);
            announce("RevEng.AI: auto-unstrip sync applied %d recovered names and pushed %d local type sets."
                    .formatted(summary.namesModifiedRemotely(), summary.pushedTypeSets()), false);
        } catch (Exception e) {
            Msg.warn(this, "Failed to sync analysis after auto-unstrip", e);
            announce("RevEng.AI: failed to sync analysis after auto-unstrip: " + e.getMessage(), true);
        }
    }

    /// Record a message in the plugin log and surface it to the user (status bar).
    private void announce(String message, boolean warning) {
        if (warning) {
            loggingService.warn(message);
        } else {
            loggingService.info(message);
        }
        statusNotifier.accept(message, warning);
    }
}

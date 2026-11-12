package ai.reveng.toolkit.ghidra.core.services.sync;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService.AnalysedProgram;
import ai.reveng.toolkit.ghidra.core.services.api.PushFailure;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AutoUnstripStatus;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.time.Duration;
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
 * a background thread polls the status endpoint every {@link #DEFAULT_POLL_INTERVAL} and, on
 * completion, runs the same reconciliation the "Sync With Portal" action uses.
 *
 * <p>Polling stops when auto-unstrip completes or fails, when {@link #stopPolling} is called (even
 * if a poll is running at that moment), after {@link #DEFAULT_MAX_POLL_DURATION}, or on an error a
 * retry cannot fix. A transient error (no connection, timeout, 5xx) backs off and retries within
 * that time limit. Every way of giving up is reported in the log and the status bar.
 */
public class AutoUnstripSyncService {

    public static final Duration DEFAULT_POLL_INTERVAL = Duration.ofSeconds(5);
    public static final Duration DEFAULT_MAX_POLL_DURATION = Duration.ofMinutes(30);
    /// Longest wait between polls while the status endpoint keeps failing transiently.
    private static final Duration MAX_BACKOFF = Duration.ofSeconds(60);

    private final GhidraRevengService revengService;
    private final ReaiLoggingService loggingService;
    /// Surfaces a progress message to the user (text, isWarning); wired to the tool status bar in the plugin.
    private final BiConsumer<String, Boolean> statusNotifier;
    private final long pollIntervalMillis;
    private final Duration maxPollDuration;
    private final ScheduledExecutorService scheduler;
    private final Map<AnalysisID, Poller> pollers = new ConcurrentHashMap<>();

    public AutoUnstripSyncService(GhidraRevengService revengService, ReaiLoggingService loggingService,
                                  BiConsumer<String, Boolean> statusNotifier) {
        this(revengService, loggingService, statusNotifier, DEFAULT_POLL_INTERVAL, DEFAULT_MAX_POLL_DURATION);
    }

    public AutoUnstripSyncService(GhidraRevengService revengService, ReaiLoggingService loggingService,
                                  BiConsumer<String, Boolean> statusNotifier,
                                  Duration pollInterval, Duration maxPollDuration) {
        this.revengService = revengService;
        this.loggingService = loggingService;
        this.statusNotifier = statusNotifier;
        this.pollIntervalMillis = pollInterval.toMillis();
        this.maxPollDuration = maxPollDuration;
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
        var poller = new Poller(analysedProgram, resyncIfAlreadyComplete);
        var previous = pollers.put(analysedProgram.analysisID(), poller);
        if (previous != null) {
            previous.cancel();
        }
        poller.schedule(0);
    }

    /// Stop polling for the given analysis. A poll that is running right now neither reschedules
    /// nor starts a sync afterwards.
    ///
    /// @return whether polling was still active for the analysis
    public boolean stopPolling(AnalysisID analysisID) {
        var existing = pollers.remove(analysisID);
        if (existing != null) {
            existing.cancel();
            return true;
        }
        return false;
    }

    public void dispose() {
        pollers.values().forEach(Poller::cancel);
        pollers.clear();
        scheduler.shutdownNow();
    }

    /// One polling run for one analysis. Cancelling it is final, so a replaced or stopped run can
    /// never put itself back on the schedule.
    private final class Poller {
        private final AnalysedProgram analysedProgram;
        private final boolean resyncIfAlreadyComplete;
        private final long startNanos = System.nanoTime();
        private boolean firstPoll = true;
        private int consecutiveFailures = 0;
        /// Guarded by {@code this}
        private boolean cancelled = false;
        /// Guarded by {@code this}
        private ScheduledFuture<?> future;

        Poller(AnalysedProgram analysedProgram, boolean resyncIfAlreadyComplete) {
            this.analysedProgram = analysedProgram;
            this.resyncIfAlreadyComplete = resyncIfAlreadyComplete;
        }

        synchronized void cancel() {
            cancelled = true;
            if (future != null) {
                future.cancel(false);
            }
        }

        synchronized boolean isCancelled() {
            return cancelled;
        }

        synchronized void schedule(long delayMillis) {
            if (!cancelled) {
                future = scheduler.schedule(this::pollSafely, delayMillis, TimeUnit.MILLISECONDS);
            }
        }

        /// Leave the map, unless a newer run for the same analysis has already replaced this one.
        void finish() {
            pollers.remove(analysedProgram.analysisID(), this);
        }

        private void pollSafely() {
            try {
                poll();
            } catch (RuntimeException e) {
                finish();
                Msg.warn(AutoUnstripSyncService.this, "Auto-unstrip polling failed", e);
                if (!isCancelled()) {
                    announce("RevEng.AI: stopped waiting for auto-unstrip after an unexpected error (%s). "
                            .formatted(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName())
                            + "Use Sync With Portal to pull the recovered names later.", true);
                }
            }
        }

        private void poll() {
            if (isCancelled()) {
                return;
            }
            AutoUnstripStatus status;
            try {
                status = revengService.getAutoUnstripStatus(analysedProgram.analysisID());
            } catch (ApiException e) {
                if (isCancelled()) {
                    return;
                }
                if (PushFailure.of(e) != PushFailure.TRANSIENT) {
                    finish();
                    announce("RevEng.AI: stopped waiting for auto-unstrip, the status check failed (%s). "
                            .formatted(describe(e)) + "Use Sync With Portal to pull the recovered names later.", true);
                    return;
                }
                consecutiveFailures++;
                if (consecutiveFailures == 1) {
                    // Logged once per outage, so a portal that is down for a while does not flood the log.
                    loggingService.warn("Checking the auto-unstrip status failed (%s); retrying with back-off."
                            .formatted(describe(e)));
                }
                rescheduleOrGiveUp(backoffMillis());
                return;
            }
            if (isCancelled()) {
                return;
            }
            if (consecutiveFailures > 0) {
                loggingService.info("Checking the auto-unstrip status works again.");
                consecutiveFailures = 0;
            }

            switch (status) {
                case COMPLETED -> {
                    finish();
                    if (firstPoll && !resyncIfAlreadyComplete) {
                        return;
                    }
                    runSync();
                }
                case FAILED -> {
                    finish();
                    if (!isCancelled()) {
                        announce("RevEng.AI auto-unstrip failed; recovered names were not synced.", true);
                    }
                }
                default -> {
                    if (firstPoll) {
                        announce("RevEng.AI: waiting for auto-unstrip to finish before syncing recovered "
                                + "function names and data types…", false);
                    }
                    firstPoll = false;
                    rescheduleOrGiveUp(pollIntervalMillis);
                }
            }
        }

        private long backoffMillis() {
            int doublings = Math.min(consecutiveFailures, 16);
            return Math.min(pollIntervalMillis << doublings, Math.max(MAX_BACKOFF.toMillis(), pollIntervalMillis));
        }

        private void rescheduleOrGiveUp(long delayMillis) {
            var elapsed = Duration.ofNanos(System.nanoTime() - startNanos);
            if (elapsed.plusMillis(delayMillis).compareTo(maxPollDuration) > 0) {
                finish();
                if (!isCancelled()) {
                    announce(("RevEng.AI: auto-unstrip has not finished after %s; stopped waiting. "
                            + "Use Sync With Portal to pull the recovered names later.")
                            .formatted(describe(maxPollDuration)), true);
                }
                return;
            }
            schedule(delayMillis);
        }

        private void runSync() {
            // The program may have been detached, or attached to another analysis, since polling began.
            var current = revengService.getAnalysedProgram(analysedProgram.program());
            if (isCancelled() || current.isEmpty()
                    || !current.get().analysisID().equals(analysedProgram.analysisID())) {
                loggingService.info("Auto-unstrip finished for analysis %d, but the program is no longer attached to it; not syncing."
                        .formatted(analysedProgram.analysisID().id()));
                return;
            }
            announce("RevEng.AI: auto-unstrip finished; syncing recovered function names and data types…", false);
            try {
                var summary = revengService.syncAnalysisUpdates(current.get(), TaskMonitor.DUMMY, loggingService);
                announce(("RevEng.AI: auto-unstrip sync applied %d recovered name(s) and %d signature(s), "
                        + "and pushed %d local type set(s).")
                        .formatted(summary.namesModifiedRemotely(), summary.appliedSignatures(),
                                summary.pushedTypeSets()), false);
            } catch (Exception e) {
                Msg.warn(AutoUnstripSyncService.this, "Failed to sync analysis after auto-unstrip", e);
                if (isCancelled()) {
                    // Detached mid-sync; the failure is a consequence of that, not something to report.
                    return;
                }
                announce("RevEng.AI: failed to sync analysis after auto-unstrip: " + e.getMessage(), true);
            }
        }
    }

    private static String describe(ApiException e) {
        return e.getCode() > 0 ? "HTTP " + e.getCode() : String.valueOf(e.getMessage());
    }

    private static String describe(Duration duration) {
        return duration.toMinutes() >= 1 ? duration.toMinutes() + " minute(s)" : duration.toSeconds() + " second(s)";
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

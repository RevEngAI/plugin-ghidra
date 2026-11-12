package ai.reveng.toolkit.ghidra.core.services.sync;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraDataTypeEncoder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService.AnalysedProgram;
import ai.reveng.toolkit.ghidra.core.services.api.PushFailure;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.DomainObjectListenerBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.FunctionChangeRecord;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import ghidra.util.Msg;

import javax.annotation.Nullable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

/**
 * Reactive push-back of local edits to the portal (PLU-322). Registers a {@link DomainObjectListener}
 * on analysed programs and, when the user renames a function or edits its signature (return type,
 * parameters, calling convention, or a data type those use), pushes that change back to the portal
 * in the background. Local variables are not pushed: the portal's signature holds only the
 * parameters and return type, so an edit to a local has nothing to send.
 *
 * <p>Mirrors the IDA plugin's {@code hooks/reactive.py} + {@code hooks/artifacts.py}: edits are
 * debounced, renames per program and sent as one batch (a script renaming hundreds of functions makes
 * one request, not hundreds), signature edits per function. Type edits are ignored while the plugin is writing
 * server-sourced changes into that program (see {@link GhidraRevengService#isApplyingServerChanges}),
 * so sync-applied changes are not echoed straight back. Renames need no such guard: the plugin only
 * ever writes {@link SourceType#ANALYSIS} names, and only {@link SourceType#USER_DEFINED} ones are
 * pushed, so an analyst's rename is pushed even when it lands in the middle of a sync.
 *
 * <p>A push that fails leaves the edit marked in {@link UnpushedEdits} until a push succeeds, and
 * "Sync with portal" sends whatever is marked. What happens in between depends on the failure — see
 * {@link PushFailure}:
 * <ul>
 * <li>When the portal could not be reached, the program's marked edits are retried in the background,
 * backing off through {@link #RETRY_DELAYS}. The outage is reported once, in the plugin log and the
 * status bar, however many pushes fail, and once more when the edits have gone up.</li>
 * <li>When the portal turned an edit down, the marked edits are sent again at once, one at a time
 * where a batch was refused, so the ones it does take go up. Each edit it will not take is reported
 * once and not retried automatically.</li>
 * <li>When the portal refused the API key, that is reported once and nothing is retried until a
 * push succeeds again.</li>
 * </ul>
 * Each failure is also logged to Ghidra's console.
 */
public class LocalEditSyncService {

    /// Coalesce rapid successive edits to the same function before pushing, matching IDA's debounce.
    private static final long DEBOUNCE_MS = 400;

    /// The waits before each automatic retry of a program's unpushed edits; the last one repeats.
    public static final List<Duration> RETRY_DELAYS = List.of(
            Duration.ofSeconds(30), Duration.ofMinutes(1), Duration.ofMinutes(2), Duration.ofMinutes(5));

    private final GhidraRevengService revengService;
    private final ReaiLoggingService loggingService;
    /// Shows a message in the status bar; the flag marks it as a warning.
    private final BiConsumer<String, Boolean> statusNotifier;
    private final ScheduledExecutorService scheduler;
    private final Map<Program, DomainObjectListener> listeners = new ConcurrentHashMap<>();
    private final Map<Program, ScheduledFuture<?>> pendingRenames = new ConcurrentHashMap<>();
    /// The functions renamed in each program since its last rename push. Guarded by itself.
    private final Map<Program, Set<Address>> dueRenames = new HashMap<>();
    private final Map<InProgram<Address>, ScheduledFuture<?>> pendingTypes = new ConcurrentHashMap<>();
    private final Map<InProgram<String>, ScheduledFuture<?>> pendingDataTypeScans = new ConcurrentHashMap<>();
    private final List<Duration> retryDelays;
    /// The programs whose unpushed edits wait for an automatic retry.
    private final Map<Program, ScheduledFuture<?>> pendingRetries = new ConcurrentHashMap<>();
    /// How many retries have failed in a row, per program, which picks the next wait.
    private final Map<Program, Integer> failedRetries = new ConcurrentHashMap<>();
    // The outage state below is only touched on the scheduler thread.
    /// Whether the analyst has been told that pushes are failing.
    private boolean outageReported;
    /// Edits the retries have pushed since the outage was reported.
    private int pushedSinceOutage;
    /// Whether the analyst has been told the API key was refused; cleared when a push succeeds.
    private boolean authReported;
    /// The programs whose retries stopped on a refused API key, to resume when a push succeeds.
    private final Set<Program> stoppedOnAuth = ConcurrentHashMap.newKeySet();
    /// The rejected edits already reported, per program, so each is reported once.
    private final Map<Program, Set<String>> reportedRejections = new ConcurrentHashMap<>();

    /// A debounce key. One service handles every open program, and two programs can have functions at
    /// the same address (two versions of one binary, or any two PEs with code at `0x140001000`), so an
    /// address or type path alone would let an edit in one program cancel the other's pending push.
    private record InProgram<K>(Program program, K key) {}

    public LocalEditSyncService(GhidraRevengService revengService, ReaiLoggingService loggingService,
                                BiConsumer<String, Boolean> statusNotifier) {
        this(revengService, loggingService, statusNotifier, RETRY_DELAYS);
    }

    /// @param retryDelays the waits before each automatic retry; the last one repeats
    public LocalEditSyncService(GhidraRevengService revengService, ReaiLoggingService loggingService,
                                BiConsumer<String, Boolean> statusNotifier, List<Duration> retryDelays) {
        this.revengService = revengService;
        this.loggingService = loggingService;
        this.statusNotifier = statusNotifier;
        this.retryDelays = List.copyOf(retryDelays);
        this.scheduler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            var thread = new Thread(runnable, "RevEng.AI-LocalEditSync");
            thread.setDaemon(true);
            return thread;
        });
    }

    /// Start listening for local edits on the given analysed program. Idempotent.
    public void attach(Program program) {
        listeners.computeIfAbsent(program, p -> {
            var listener = buildListener(p);
            p.addListener(listener);
            return listener;
        });
    }

    /// Stop listening for local edits on the given program.
    public void detach(Program program) {
        var listener = listeners.remove(program);
        if (listener != null) {
            program.removeListener(listener);
        }
        // Its edits stay marked, so the next sync of it still sends them.
        var retry = pendingRetries.remove(program);
        if (retry != null) {
            retry.cancel(false);
        }
        failedRetries.remove(program);
        stoppedOnAuth.remove(program);
        reportedRejections.remove(program);
        scheduler.execute(() -> {
            if (pendingRetries.isEmpty()) {
                outageReported = false;
                pushedSinceOutage = 0;
            }
        });
    }

    public void dispose() {
        listeners.forEach(Program::removeListener);
        listeners.clear();
        scheduler.shutdownNow();
    }

    private DomainObjectListener buildListener(Program program) {
        return new DomainObjectListenerBuilder(this)
                .each(ProgramEvent.SYMBOL_RENAMED).call(record -> onSymbolRenamed(program, record))
                // Renaming a decompiler-inferred variable commits it to the database as a new symbol,
                // which fires SYMBOL_ADDED rather than SYMBOL_RENAMED, so we react to both.
                .each(ProgramEvent.SYMBOL_ADDED).call(record -> onVariableSymbolChanged(program, record))
                .each(ProgramEvent.FUNCTION_CHANGED).call(record -> onFunctionChanged(program, record))
                .each(ProgramEvent.FUNCTION_ADDED).call(record -> onFunctionAdded(program, record))
                // Editing a data type definition (rename a struct, change its fields, ...) does not
                // fire a function event, so we react to the data-type events and push every server-known
                // function that references the edited type — the portal stores types per function.
                .each(ProgramEvent.DATA_TYPE_CHANGED, ProgramEvent.DATA_TYPE_RENAMED, ProgramEvent.DATA_TYPE_REPLACED)
                .call(record -> onDataTypeChanged(program, record))
                .build();
    }

    private void onSymbolRenamed(Program program, DomainObjectChangeRecord record) {
        var symbol = symbolOf(record);
        if (symbol == null || symbol.getSource() != SourceType.USER_DEFINED) {
            return;
        }
        if (symbol.getSymbolType() == SymbolType.FUNCTION) {
            var function = program.getFunctionManager().getFunctionAt(symbol.getAddress());
            if (isSyncable(function)) {
                scheduleRename(program, function.getEntryPoint());
            }
        } else {
            scheduleTypesForVariable(program, symbol);
        }
    }

    private void onVariableSymbolChanged(Program program, DomainObjectChangeRecord record) {
        // Applying a portal signature adds parameter symbols.
        if (revengService.isApplyingServerChanges(program)) {
            return;
        }
        var symbol = symbolOf(record);
        if (symbol != null) {
            scheduleTypesForVariable(program, symbol);
        }
    }

    /// Push the containing function's signature when one of its parameter symbols changed.
    private void scheduleTypesForVariable(Program program, Symbol symbol) {
        if (symbol.getSymbolType() != SymbolType.PARAMETER) {
            return;
        }
        if (symbol.getParentNamespace() instanceof Function function && isSyncable(function)) {
            scheduleTypes(program, function.getEntryPoint());
        }
    }

    private static Symbol symbolOf(DomainObjectChangeRecord record) {
        if (record instanceof ProgramChangeRecord programChange
                && programChange.getObject() instanceof Symbol symbol) {
            return symbol;
        }
        return null;
    }

    private void onFunctionChanged(Program program, DomainObjectChangeRecord record) {
        if (!(record instanceof FunctionChangeRecord functionChange)) {
            return;
        }
        var function = functionChange.getFunction();
        if (!isSyncable(function) || revengService.isApplyingServerChanges(program)) {
            return;
        }
        // Only the return type and parameters reach the portal. Ghidra reports any other change —
        // a local variable added, removed or retyped, the stack frame, an inline or no-return flag —
        // without one of these two types, and pushing for it would resend an unchanged signature.
        if (!functionChange.isFunctionSignatureChange()) {
            return;
        }
        scheduleTypes(program, function.getEntryPoint());
    }

    /// A function deleted and created again keeps its server id, because the id map is keyed by
    /// address, but not its tag; put the tag back so it still shows as synced.
    private void onFunctionAdded(Program program, DomainObjectChangeRecord record) {
        if (record instanceof ProgramChangeRecord programChange) {
            var function = program.getFunctionManager().getFunctionAt(programChange.getStart());
            if (isSyncable(function)) {
                revengService.restoreSyncedTag(function);
            }
        }
    }

    private void onDataTypeChanged(Program program, DomainObjectChangeRecord record) {
        // Applying a portal signature updates the data types it names in place.
        if (revengService.isApplyingServerChanges(program)) {
            return;
        }
        DataType dataType = null;
        if (record.getNewValue() instanceof DataType changed) {
            dataType = changed;
        } else if (record.getOldValue() instanceof DataType previous) {
            dataType = previous;
        }
        if (dataType != null) {
            scheduleDataTypeScan(program, dataType);
        }
    }

    private static boolean isSyncable(Function function) {
        return function != null && !function.isExternal() && !function.isThunk();
    }

    private void scheduleRename(Program program, Address entryPoint) {
        UnpushedEdits.mark(program, UnpushedEdits.Kind.NAME, entryPoint);
        synchronized (dueRenames) {
            dueRenames.computeIfAbsent(program, p -> new LinkedHashSet<>()).add(entryPoint);
        }
        schedule(pendingRenames, program, program, () -> pushRenames(program));
    }

    private void scheduleTypes(Program program, Address entryPoint) {
        UnpushedEdits.mark(program, UnpushedEdits.Kind.TYPES, entryPoint);
        schedule(pendingTypes, new InProgram<>(program, entryPoint), program, () -> pushTypes(program, entryPoint));
    }

    private void scheduleDataTypeScan(Program program, DataType dataType) {
        var typeName = dataType.getName();
        schedule(pendingDataTypeScans, new InProgram<>(program, dataType.getPathName()), program,
                () -> pushFunctionsReferencingType(program, typeName));
    }

    private <K> void schedule(Map<K, ScheduledFuture<?>> pending, K key, Program program, Runnable task) {
        var existing = pending.get(key);
        if (existing != null) {
            existing.cancel(false);
        }
        pending.put(key, scheduler.schedule(() -> {
            pending.remove(key);
            // Nothing reads the future, so anything thrown here would vanish with it.
            try {
                task.run();
            } catch (Exception e) {
                onPushFailed(program, "Could not push a local edit", e);
            }
        }, DEBOUNCE_MS, TimeUnit.MILLISECONDS));
    }

    /// Push every server-known function that references the edited type, so a type edit is
    /// propagated to the portal.
    ///
    /// A data type is not attached to any one function, so an edit to it is turned back into
    /// function pushes: each affected function's own push re-resolves the type and writes its new
    /// definition. Rescheduling rather than pushing directly means the per-function debounce still
    /// applies, so editing several members of a struct collapses into one push per function.
    private void pushFunctionsReferencingType(Program program, String typeName) {
        var analysedProgram = revengService.getAnalysedProgram(program);
        if (analysedProgram.isEmpty()) {
            return;
        }
        for (Function function : analysedProgram.get().getFunctionMap().values()) {
            if (isSyncable(function)
                    && GhidraDataTypeEncoder.referencedTypeNames(function).contains(typeName)) {
                scheduleTypes(program, function.getEntryPoint());
            }
        }
    }

    /// Push every rename made in `program` since its last push, in one request.
    private void pushRenames(Program program) {
        Set<Address> entryPoints;
        synchronized (dueRenames) {
            entryPoints = dueRenames.remove(program);
        }
        var analysedProgram = revengService.getAnalysedProgram(program);
        if (entryPoints == null || analysedProgram.isEmpty()) {
            return;
        }
        List<Function> functions = new ArrayList<>();
        for (Address entryPoint : entryPoints) {
            var function = program.getFunctionManager().getFunctionAt(entryPoint);
            if (isSyncable(function)) {
                functions.add(function);
            }
        }
        try {
            var pushed = revengService.pushFunctionRenames(analysedProgram.get(), functions);
            if (pushed.size() == 1) {
                var only = pushed.entrySet().iterator().next();
                loggingService.info("Pushed rename of function at %s to \"%s\" to the RevEng.AI portal"
                        .formatted(only.getKey().getEntryPoint(), only.getValue()));
            } else if (!pushed.isEmpty()) {
                loggingService.info("Pushed renames of %d functions to the RevEng.AI portal".formatted(pushed.size()));
            }
            // Every one, including those that were gone or unknown to the portal: nothing is left to send.
            entryPoints.forEach(entryPoint -> UnpushedEdits.clear(program, UnpushedEdits.Kind.NAME, entryPoint));
            onPushSucceeded(program);
        } catch (Exception e) {
            // Marked again in case a push that started earlier succeeded and cleared them meanwhile.
            entryPoints.forEach(entryPoint -> UnpushedEdits.mark(program, UnpushedEdits.Kind.NAME, entryPoint));
            var what = functions.size() == 1
                    ? "the rename of \"%s\"".formatted(functions.get(0).getName())
                    : "the renames of %d functions".formatted(functions.size());
            onPushFailed(program, "Could not push " + what, e);
        }
    }

    private void pushTypes(Program program, Address entryPoint) {
        withAnalysedFunction(program, entryPoint, (analysedProgram, function) -> {
            try {
                switch (revengService.pushFunctionTypes(analysedProgram, function)) {
                    case SIGNATURE_WRITTEN -> loggingService.info(
                            "Pushed types for function \"%s\" at %s to the RevEng.AI portal"
                                    .formatted(function.getName(), entryPoint));
                    // The data types did reach the portal; only the signature had nothing to update.
                    // Saying so matters, because otherwise editing a type on a function the portal
                    // never extracted a signature for looks like it did nothing at all.
                    case TYPES_ONLY -> loggingService.info(
                            ("Pushed the data types for function \"%s\" at %s; the portal holds no extracted "
                                    + "signature for it, so its signature was left unchanged")
                                    .formatted(function.getName(), entryPoint));
                    case NOT_MATCHED -> {
                        // Not part of the analysis, so there was nothing to push.
                    }
                }
                UnpushedEdits.clear(program, UnpushedEdits.Kind.TYPES, entryPoint);
                onPushSucceeded(program);
            } catch (Exception e) {
                UnpushedEdits.mark(program, UnpushedEdits.Kind.TYPES, entryPoint);
                onPushFailed(program, "Could not push the types of \"%s\"".formatted(function.getName()), e);
            }
        });
    }

    // Everything from here on runs on the scheduler thread.

    /// Log the failure to Ghidra's console and decide what comes next: a retry after a wait when the
    /// portal could not be reached, and otherwise a retry straight away, which sends the marked edits
    /// one at a time where needed and finds out which ones the portal will not take.
    private void onPushFailed(Program program, String detail, Exception e) {
        Msg.warn(this, "%s: %s".formatted(detail, reasonOf(e)), e);
        if (PushFailure.of(e) == PushFailure.TRANSIENT) {
            reportOutage(e);
            scheduleRetry(program, nextDelay(program));
        } else {
            scheduleRetry(program, Duration.ZERO);
        }
    }

    /// A push got through, so the portal is likely back and the key good: retry the program's other
    /// edits now rather than at the end of the current wait.
    private void onPushSucceeded(Program program) {
        authReported = false;
        var waiting = pendingRetries.get(program);
        if (waiting != null && waiting.cancel(false)) {
            pendingRetries.remove(program);
            scheduleRetry(program, Duration.ZERO);
        } else if (stoppedOnAuth.remove(program)) {
            scheduleRetry(program, Duration.ZERO);
        }
    }

    private Duration nextDelay(Program program) {
        return retryDelays.get(Math.min(failedRetries.getOrDefault(program, 0), retryDelays.size() - 1));
    }

    private void scheduleRetry(Program program, Duration delay) {
        if (pendingRetries.containsKey(program) || !listeners.containsKey(program)) {
            return;
        }
        pendingRetries.put(program, scheduler.schedule(() -> retry(program), delay.toMillis(), TimeUnit.MILLISECONDS));
    }

    private void retry(Program program) {
        pendingRetries.remove(program);
        var analysedProgram = revengService.getAnalysedProgram(program);
        if (!listeners.containsKey(program) || analysedProgram.isEmpty()) {
            failedRetries.remove(program);
            endOutageIfOver();
            return;
        }
        GhidraRevengService.LocalEditFlush flush;
        try {
            flush = revengService.pushUnpushedEdits(analysedProgram.get());
        } catch (Exception e) {
            flush = PushFailure.of(e) == PushFailure.TRANSIENT
                    ? new GhidraRevengService.LocalEditFlush(0, 1, e, List.of())
                    : new GhidraRevengService.LocalEditFlush(0, 0, null,
                            List.of(new GhidraRevengService.RejectedEdit("local edits", e)));
        }
        pushedSinceOutage += flush.pushed();
        if (flush.pushed() > 0) {
            authReported = false;
        }
        if (flush.unsent() > 0) {
            Msg.warn(this, "Retry of %d unpushed local edit(s) failed: %s"
                    .formatted(flush.unsent(), reasonOf(flush.unsentError())), flush.unsentError());
            reportOutage(flush.unsentError());
            failedRetries.merge(program, 1, Integer::sum);
            scheduleRetry(program, nextDelay(program));
            return;
        }
        failedRetries.remove(program);
        reportRejections(program, flush.rejected());
        endOutageIfOver();
    }

    private void reportOutage(Exception e) {
        if (!outageReported) {
            outageReported = true;
            announce(("RevEng.AI: could not push local edits to the portal (%s). They are kept and will be "
                    + "retried automatically.").formatted(reasonOf(e)), true);
        }
    }

    /// Report the edits that will not be retried automatically: a refused API key once until a push
    /// succeeds, and each edit the portal turned down once.
    private void reportRejections(Program program, List<GhidraRevengService.RejectedEdit> rejected) {
        var refusedKey = rejected.stream().filter(edit -> edit.failure() == PushFailure.AUTH).findFirst();
        if (refusedKey.isPresent()) {
            stoppedOnAuth.add(program);
            if (!authReported) {
                authReported = true;
                announce(("RevEng.AI: the portal refused the API key (%s), so local edits are not being pushed. "
                        + "Check the key in the RevEng.AI settings; the edits are kept and will be sent on the next "
                        + "Sync with portal.").formatted(reasonOf(refusedKey.get().error())), true);
            }
        }
        List<GhidraRevengService.RejectedEdit> turnedDown = rejected.stream()
                .filter(edit -> edit.failure() != PushFailure.AUTH)
                .toList();
        // Every marked edit was just sent, so this is the whole set the portal will not take; one that
        // has since gone up drops out of it.
        Set<String> reported = reportedRejections.computeIfAbsent(program, p -> ConcurrentHashMap.newKeySet());
        Set<String> current = new LinkedHashSet<>();
        turnedDown.forEach(edit -> current.add(edit.edit()));
        reported.retainAll(current);
        var fresh = turnedDown.stream().filter(edit -> !reported.contains(edit.edit())).toList();
        if (fresh.isEmpty()) {
            return;
        }
        for (var edit : fresh) {
            reported.add(edit.edit());
            loggingService.warn("RevEng.AI: the portal did not take the %s: %s".formatted(edit.edit(), reasonOf(edit.error())));
        }
        announce(("RevEng.AI: the portal did not take %d local edit(s) (%s). They will not be retried "
                + "automatically; the RevEng.AI log lists them, and they are kept for the next Sync with portal.")
                .formatted(fresh.size(), reasonOf(fresh.get(0).error())), true);
    }

    /// Once no program has edits waiting for a retry, say that the outage is over, once.
    private void endOutageIfOver() {
        if (!outageReported || !pendingRetries.isEmpty()) {
            return;
        }
        outageReported = false;
        if (pushedSinceOutage > 0) {
            announce("RevEng.AI: pushed %d local edit(s) that had failed earlier.".formatted(pushedSinceOutage), false);
        }
        pushedSinceOutage = 0;
    }

    private void announce(String message, boolean warning) {
        if (warning) {
            loggingService.warn(message);
        } else {
            loggingService.info(message);
        }
        statusNotifier.accept(message, warning);
    }

    private static String reasonOf(@Nullable Exception e) {
        if (e == null) {
            return "unknown error";
        }
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }

    private void withAnalysedFunction(Program program, Address entryPoint,
                                      BiConsumer<AnalysedProgram, Function> action) {
        var analysedProgram = revengService.getAnalysedProgram(program);
        if (analysedProgram.isEmpty()) {
            return;
        }
        var function = program.getFunctionManager().getFunctionAt(entryPoint);
        if (function == null) {
            return;
        }
        action.accept(analysedProgram.get(), function);
    }
}

package ai.reveng.toolkit.ghidra.core.services.sync;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService.AnalysedProgram;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.DomainObjectListenerBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.FunctionChangeRecord;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import ghidra.util.Msg;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

/**
 * Reactive push-back of local edits to the portal (PLU-322). Registers a {@link DomainObjectListener}
 * on analysed programs and, when the user renames a function or edits its signature / variables,
 * pushes that change back to the portal in the background.
 *
 * <p>Mirrors the IDA plugin's {@code hooks/reactive.py} + {@code hooks/artifacts.py}: edits are
 * coalesced per function (debounced) and pushes are suppressed while the plugin is applying
 * server-sourced changes locally (see {@link GhidraRevengService#isPushbackSuppressed()}), so
 * sync-applied changes are not echoed straight back.
 */
public class LocalEditSyncService {

    /// Coalesce rapid successive edits to the same function before pushing, matching IDA's debounce.
    private static final long DEBOUNCE_MS = 400;

    private final GhidraRevengService revengService;
    private final ScheduledExecutorService scheduler;
    private final Map<Program, DomainObjectListener> listeners = new ConcurrentHashMap<>();
    private final Map<Address, ScheduledFuture<?>> pendingRenames = new ConcurrentHashMap<>();
    private final Map<Address, ScheduledFuture<?>> pendingTypes = new ConcurrentHashMap<>();

    public LocalEditSyncService(GhidraRevengService revengService) {
        this.revengService = revengService;
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
    }

    public void dispose() {
        listeners.forEach(Program::removeListener);
        listeners.clear();
        scheduler.shutdownNow();
    }

    private DomainObjectListener buildListener(Program program) {
        return new DomainObjectListenerBuilder(this)
                .ignoreWhen(revengService::isPushbackSuppressed)
                .each(ProgramEvent.SYMBOL_RENAMED).call(record -> onSymbolRenamed(program, record))
                .each(ProgramEvent.FUNCTION_CHANGED).call(record -> onFunctionChanged(program, record))
                .build();
    }

    private void onSymbolRenamed(Program program, DomainObjectChangeRecord record) {
        if (!(record instanceof ProgramChangeRecord programChange)
                || !(programChange.getObject() instanceof Symbol symbol)) {
            return;
        }
        if (symbol.getSource() != SourceType.USER_DEFINED) {
            return;
        }
        var symbolType = symbol.getSymbolType();
        if (symbolType == ghidra.program.model.symbol.SymbolType.FUNCTION) {
            var function = program.getFunctionManager().getFunctionAt(symbol.getAddress());
            if (isSyncable(function)) {
                scheduleRename(program, function.getEntryPoint());
            }
        } else if (symbolType == ghidra.program.model.symbol.SymbolType.LOCAL_VAR
                || symbolType == ghidra.program.model.symbol.SymbolType.PARAMETER) {
            // A variable was renamed; push the containing function's variables.
            if (symbol.getParentNamespace() instanceof Function function && isSyncable(function)) {
                scheduleTypes(program, function.getEntryPoint());
            }
        }
    }

    private void onFunctionChanged(Program program, DomainObjectChangeRecord record) {
        if (!(record instanceof FunctionChangeRecord functionChange)) {
            return;
        }
        var function = functionChange.getFunction();
        if (!isSyncable(function)) {
            return;
        }
        // Modifier-only changes (inline/no-return/thunk/...) carry no type information to sync.
        // Everything else (return type, parameters, variable types) is pushed; sync-applied changes
        // are already excluded by the ignoreWhen(isPushbackSuppressed) guard on the listener.
        if (functionChange.isFunctionModifierChange()) {
            return;
        }
        scheduleTypes(program, function.getEntryPoint());
    }

    private static boolean isSyncable(Function function) {
        return function != null && !function.isExternal() && !function.isThunk();
    }

    private void scheduleRename(Program program, Address entryPoint) {
        schedule(pendingRenames, entryPoint, () -> pushRename(program, entryPoint));
    }

    private void scheduleTypes(Program program, Address entryPoint) {
        schedule(pendingTypes, entryPoint, () -> pushTypes(program, entryPoint));
    }

    private void schedule(Map<Address, ScheduledFuture<?>> pending, Address key, Runnable task) {
        var existing = pending.get(key);
        if (existing != null) {
            existing.cancel(false);
        }
        pending.put(key, scheduler.schedule(() -> {
            pending.remove(key);
            task.run();
        }, DEBOUNCE_MS, TimeUnit.MILLISECONDS));
    }

    private void pushRename(Program program, Address entryPoint) {
        withAnalysedFunction(program, entryPoint, (analysedProgram, function) -> {
            try {
                revengService.pushFunctionRename(analysedProgram, function);
            } catch (ApiException e) {
                Msg.warn(this, "Failed to push rename for %s to portal".formatted(function.getName()), e);
            }
        });
    }

    private void pushTypes(Program program, Address entryPoint) {
        withAnalysedFunction(program, entryPoint, (analysedProgram, function) -> {
            try {
                revengService.pushFunctionTypes(analysedProgram, function);
            } catch (ApiException e) {
                Msg.warn(this, "Failed to push types for %s to portal".formatted(function.getName()), e);
            }
        });
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

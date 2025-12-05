package ai.reveng.toolkit.ghidra.binarysimilarity.cmds;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import javax.annotation.Nullable;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static java.util.stream.Collectors.groupingBy;

/**
 * Task to compute type information for a given function or list of functions
 *
 * uses https://api.reveng.ai/v2/docs#tag/Function-Overview/operation/generate_function_datatypes_v2_analyses__analysis_id__functions_data_types_post
 *
 */
public class ComputeTypeInfoTask extends Task {
    private final List<TypedApiInterface.FunctionID> functions;
    private final GhidraRevengService service;
    private final DataTypeAvailableCallback callback;

    public ComputeTypeInfoTask(GhidraRevengService service,
                               List<TypedApiInterface.FunctionID> functions,
                               @Nullable DataTypeAvailableCallback callback) {
        super("Computing Type Info", true, true, false);
        this.service = service;
        this.functions = functions;
        this.callback = callback;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
        monitor.setMessage("Generating Type Info");
        monitor.setProgress(0);
        monitor.setMaximum(functions.size());

        functions.stream()
                .map( f -> service.getApi().getFunctionDetails(f))
                .collect(groupingBy(FunctionDetails::analysisId))
                .forEach((analysisID, functions) -> {
                    service.getApi().generateFunctionDataTypes(analysisID, functions.stream().map(FunctionDetails::functionId).toList());
                });

        Set<TypedApiInterface.FunctionID> missing = new HashSet<>(functions);

        while (!missing.isEmpty()) {
            try {
                // JDK 17 doesn't support passing a Duration to Thread.sleep
                Thread.sleep(Duration.ofMillis(250).toMillis());
            } catch (InterruptedException e) {
                throw new CancelledException("Task Thread was interrupted");
            }
            monitor.checkCancelled();
            monitor.setMessage("Checking type info for remaining %s functions".formatted( missing.size()));
            DataTypeList newList = service.getApi().getFunctionDataTypes(missing.stream().toList());
            missing.clear();
            for (FunctionDataTypeStatus status : newList.dataTypes()) {
                if (status.completed()) {
                    if (this.callback != null) {
                        this.callback.dataTypeAvailable(status.functionID(), status);
                    }
                    monitor.increment();
                } else {
                    missing.add(status.functionID());
                }
            }
        }
    }

    public interface DataTypeAvailableCallback {
        void dataTypeAvailable(TypedApiInterface.FunctionID functionID, FunctionDataTypeStatus dataTypeStatus);
    }
}

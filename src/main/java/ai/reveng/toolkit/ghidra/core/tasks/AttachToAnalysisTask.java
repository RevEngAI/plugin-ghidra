package ai.reveng.toolkit.ghidra.core.tasks;

import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisResultsLoaded;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import javax.annotation.Nullable;
import java.util.List;

/**
 * Task that handles attaching to an existing analysis.
 * This involves fetching function information from the server and mapping function IDs,
 * which can take non-trivial time for large binaries.
 */
public class AttachToAnalysisTask extends Task {

    private final GhidraRevengService.ProgramWithID programWithID;
    private final GhidraRevengService service;
    private final PluginTool tool;
    @Nullable
    private final List<Function> selectedFunctions;

    /**
     * Creates a task to attach to an existing analysis.
     *
     * @param programWithID The program with associated analysis ID
     * @param selectedFunctions Optional list of functions to include in mapping. If null, all functions are included.
     * @param service The RevEng.AI service
     * @param tool The plugin tool for firing events
     */
    public AttachToAnalysisTask(
            GhidraRevengService.ProgramWithID programWithID,
            @Nullable List<Function> selectedFunctions,
            GhidraRevengService service,
            PluginTool tool
    ) {
        super("Attaching to RevEng.AI Analysis", false, true, false);
        this.programWithID = programWithID;
        this.selectedFunctions = selectedFunctions;
        this.service = service;
        this.tool = tool;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
        monitor.setMessage("Fetching function information from server...");
        monitor.setIndeterminate(false);

        var analysedProgram = service.registerFinishedAnalysisForProgram(
                programWithID,
                selectedFunctions,
                monitor
        );

        monitor.setMessage("Analysis attached successfully");

        tool.firePluginEvent(
                new RevEngAIAnalysisResultsLoaded(
                        "AttachToAnalysisTask",
                        analysedProgram
                )
        );
    }
}
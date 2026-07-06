package ai.reveng.toolkit.ghidra.core.tasks;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.core.AnalysisLogConsumer;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;


/// Task that handles starting an analysis in the Background without blocking the thread that started it
/// (usually the Swing thread)
/// Uploading the binary and registering the analysis can take non-trivial amounts of time, so this
/// requires a dedicated task
///
public class StartAnalysisTask extends Task {

    private final AnalysisOptionsBuilder options;
    private final GhidraRevengService reService;
    private final Program program;
    private final AnalysisLogConsumer log;
    private final PluginTool tool;

    public StartAnalysisTask(Program program,
                             AnalysisOptionsBuilder options,
                             GhidraRevengService reService,
                             AnalysisLogConsumer logConsumer,
                             PluginTool tool
    ) {
        super("Running RevEng.AI Analysis", true, false, false);
        this.options = options;
        this.reService = reService;
        this.program = program;
        this.log = logConsumer;
        this.tool = tool;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
        ReaiLoggingService loggingService = tool.getService(ReaiLoggingService.class);

        monitor.setMessage("Uploading Binary");
        try {
            reService.upload(program);
        } catch (RuntimeException e) {
            reportFailure(monitor, loggingService, "Failed to upload binary", e);
            return;
        }

        monitor.setMessage("Sending Analysis Request");
        GhidraRevengService.ProgramWithID programWithID;
        try {
            programWithID = reService.startAnalysis(program, options);
        } catch (ApiException e) {
            reportFailure(monitor, loggingService, "Analysis request was rejected by the server", e);
            return;
        } catch (RuntimeException e) {
            reportFailure(monitor, loggingService, "Failed to start analysis", e);
            return;
        }

        String successMessage = "Analysis started successfully (analysis ID %s)"
                .formatted(programWithID.analysisID().id());
        monitor.setMessage(successMessage);
        if (loggingService != null) {
            loggingService.info(successMessage);
        }

        tool.firePluginEvent(new RevEngAIAnalysisStatusChangedEvent(
                "StartAnalysisTask",
                programWithID,
                AnalysisStatus.Queued)
        );
    }

    private void reportFailure(TaskMonitor monitor,
                               ReaiLoggingService loggingService,
                               String context,
                               Throwable error) {
        String message = context + ": " + describe(error);
        monitor.setMessage("Analysis Request Failed");
        if (loggingService != null) {
            loggingService.error(message);
        }
        Msg.error(this, message, error);
        Msg.showError(this, null,
                ReaiPluginPackage.WINDOW_PREFIX + "Failed to start analysis",
                message, error);
    }

    private static String describe(Throwable error) {
        Throwable cause = error;
        if (!(cause instanceof ApiException) && cause.getCause() instanceof ApiException) {
            cause = cause.getCause();
        }
        if (cause instanceof ApiException apiException) {
            String body = apiException.getResponseBody();
            String detail = (body != null && !body.isBlank()) ? body : apiException.getMessage();
            return "HTTP " + apiException.getCode() + " — " + detail;
        }
        return cause.getMessage() != null ? cause.getMessage() : cause.toString();
    }

    @Override
    public boolean getWaitForTaskCompleted() {
        return super.getWaitForTaskCompleted();
    }
}

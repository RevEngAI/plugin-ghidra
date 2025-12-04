package ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.types.AIDecompilationStatus;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.dialogs.InputDialog;
import generic.theme.GIcon;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import java.awt.*;
import java.util.Map;
import java.util.Objects;

public class AIDecompilationdWindow extends ComponentProviderAdapter {


    private RSyntaxTextArea textArea;
    private RTextScrollPane sp;
    private JTextArea descriptionArea;
    private JComponent component;
    private Function function;
    private TaskMonitorComponent taskMonitorComponent;
    private final Map<Function, AIDecompilationStatus> cache = new java.util.HashMap<>();

    public AIDecompilationdWindow(PluginTool tool, String owner) {
        super(tool, ReaiPluginPackage.WINDOW_PREFIX + "AI Decompilation", owner);

        setIcon(ReaiPluginPackage.REVENG_16);
        component = buildComponent();
        addLocalAction(new DockingAction("Positive Feedback Action", getName()) {
            {
                setToolBarData(new ToolBarData(new GIcon("icon.checkmark.green"), null));
                setDescription("Send positive feedback about the decompilation to RevEng.AI");
            }

            @Override
            public void actionPerformed(ActionContext context) {
                if (function != null) {
                    var service = tool.getService(GhidraRevengService.class);
                    var fID = service.getFunctionIDFor(function);
                    fID.ifPresent(id -> {
                        try {
                            service.getApi().aiDecompRating(id, "POSITIVE", "");
                        } catch (ApiException e) {
                            // Fail silently because this is not a critical feature
                            Msg.error(this, "Failed to send positive feedback for function %s: %s".formatted(function.getName(), e.getMessage()));
                        }
                    });
                }
            }

            @Override
            public boolean isEnabled() {
                // TODO: Only enable it if there is a decompilation to give feedback on
                return super.isEnabled();
            }


        });

        addLocalAction(new DockingAction("Negative Feedback Action", getName()) {
            {
                setToolBarData(new ToolBarData(new GIcon("icon.error"), null));
                setDescription("Report an issue with the decompilation to RevEng.AI");

            }
            @Override
            public void actionPerformed(ActionContext context) {
                // Spawn textbox to enter reason for negative feedback

                var dialog = new InputDialog("Negative Feedback", "Please provide details about what was wrong with the decompilation:", "");
                tool.showDialog(dialog);
                if (!dialog.isCanceled()) {
                    if (function != null) {
                        var service = tool.getService(GhidraRevengService.class);
                        var fID = service.getFunctionIDFor(function);
                        fID.ifPresent(id -> {
                            try {
                                service.getApi().aiDecompRating(id, "NEGATIVE", dialog.getValue());
                            } catch (ApiException e) {
                                // Fail silently because this is not a critical feature
                                Msg.error(this, "Failed to send negative feedback for function %s: %s".formatted(function.getName(), e.getMessage()));
                            }
                        });
                    }
                }
            }

            @Override
            public boolean isEnabled() {
                // TODO: Only enable it if there is a decompilation to give feedback on
                return super.isEnabled();
            }
        });
    }


    private JComponent buildComponent() {

        component = new JPanel(new BorderLayout());


        descriptionArea = new JTextArea(10, 60);
        descriptionArea.setLineWrap(true);
        descriptionArea.setText("No function selected or binary not analysed yet with RevEng.AI");
        descriptionArea.setEditable(false);
        component.add(descriptionArea, BorderLayout.NORTH);


        textArea = new RSyntaxTextArea(20, 60);
        textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_C);
        textArea.setEditable(false);
        sp = new RTextScrollPane(textArea);

        component.add(sp, BorderLayout.CENTER);
        taskMonitorComponent = new TaskMonitorComponent(false, true);
        taskMonitorComponent.setVisible(false);
        taskMonitorComponent.setIndeterminate(true);
        component.add(taskMonitorComponent, BorderLayout.SOUTH);
        return component;
    }

    @Override
    public JComponent getComponent() {
        return component;
    }


    public void setDisplayedValuesBasedOnStatus(Function function, AIDecompilationStatus status) {
        this.function = function;
        if (status.status().equals("success")) {
            setCode(status.decompilation());
            descriptionArea.setText(status.getMarkedUpSummary());
        } else if (status.status().equals("error")) {
            setCode("");
            descriptionArea.setText("Decompilation failed");
        }
    }

    private void setCode(String code) {
        String text = code;
        textArea.setText(text);
    }

    private void clear() {
        this.function = null;
        setCode("");
        descriptionArea.setText("");
    }

    public void refresh(Function function) {
        // Check if we know this function already
        var cachedStatus = cache.get(function);
        if (cachedStatus != null) {
            setDisplayedValuesBasedOnStatus(function, cachedStatus);
        } else {
            // TODO: Allow toggling auto decomp mode via local toggle action, for now do it always

            // Only start decompilation if the window is visible and the status of the analysis is complete.
            if (this.isVisible()) {
                taskMonitorComponent.setVisible(true);
                // Start a new background task to decompile the function
                var task = new AIDecompTask(tool, function);
                var builder = TaskBuilder.withTask(task);
                builder.launchInBackground(taskMonitorComponent);
            }
        }
    }

    public void locationChanged(ProgramLocation loc) {
        var functionMgr = loc.getProgram().getFunctionManager();
        var newFuncLocation = functionMgr.getFunctionContaining(loc.getAddress());

        // If we changed to a different function, we want to clear the output of the old function
        if (function != null && newFuncLocation != function) {
            clear();
        }

        function = newFuncLocation;
        if (function != null && !function.isExternal() && !function.isThunk()) {
            refresh(function);
        }
    }


    void newStatusForFunction(Function function, AIDecompilationStatus status) {
        cache.put(function, status);
        if (function == this.function) {
            SwingUtilities.invokeLater(() ->
                    setDisplayedValuesBasedOnStatus(function, status)
            );
        }
        if (status.status().equals("success")) {
            var logger = tool.getService(ReaiLoggingService.class);
            logger.info("AI Decompilation finished for function %s: %s".formatted(function.getName(), status.decompilation()));
            if (!hasPendingDecompilations()) {
                taskMonitorComponent.setVisible(false);
            }
        } else if (status.status().equals("error")) {
            if (!hasPendingDecompilations()) {
                taskMonitorComponent.setVisible(false);
            }
        }
    }

    private boolean hasPendingDecompilations() {
        return cache.values().stream().anyMatch(s -> s.status().equals("pending") || s.status().equals("running") || s.status().equals("queued"));
    }
    class AIDecompTask extends Task {

        private final GhidraRevengService service;
        private final Function function;

        public AIDecompTask(PluginTool tool, Function function) {
            super("AI Decomp task", true, false, false);
            service = tool.getService(GhidraRevengService.class);
            this.function = function;
        }

        @Override
        public void run(TaskMonitor monitor) throws CancelledException {
            var fID = service.getFunctionIDFor(function)
                    .orElseThrow(() -> new RuntimeException("Function has no associated FunctionID"));
            // Check if there is an existing process already, because the trigger API will fail with 400 if there is
            if (service.getApi().pollAIDecompileStatus(fID).status().equals("uninitialised")) {
                // Trigger the decompilation
                service.getApi().triggerAIDecompilationForFunctionID(fID);
            }
            waitForDecomp(fID, monitor);
            // TODO: Inform the component that something is finished
        }


        private void waitForDecomp(FunctionID id, TaskMonitor monitor) throws CancelledException {
            var logger = tool.getService(ReaiLoggingService.class);
            var api = service.getApi();
            AIDecompilationStatus lastDecompStatus = null;
            while (true) {
                var newStatus = api.pollAIDecompileStatus(id);
                if (lastDecompStatus == null || !Objects.equals(newStatus.status(), lastDecompStatus.status())) {
                    lastDecompStatus = newStatus;

                    newStatusForFunction(function, newStatus);
                }
                monitor.setMessage("Waiting for AI Decompilation for %s ... Current status: %s".formatted(function.getName(), lastDecompStatus.status()));
                monitor.checkCancelled();
                switch (newStatus.status()) {
                    case "pending":
                    case "uninitialised":
                    case "queued":
                    case "running":
                        try {
                            // Wait a second before polling again. We don't want to spam the API with requests too often
                            Thread.sleep(1000);
                        } catch (InterruptedException e) {
                            throw new RuntimeException(e);
                        }
                        break;
                    case "success":
                        monitor.setProgress(monitor.getMaximum());
                        return;
                    case "error":
                        logger.error("Decompilation failed: %s".formatted(newStatus.decompilation()));
                        return;
                    default:
                        throw new RuntimeException("Unknown status: %s".formatted(newStatus.status()));
                }

            }
        }

    }
}

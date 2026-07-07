package ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.DecompilationData;
import ai.reveng.model.WorkflowProgress;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.AIDecompilationStatus;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
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
    private JEditorPane descriptionArea;
    private JLabel predictedNameLabel;
    private JButton usePredictedNameButton;
    private JPanel predictedNamePanel;
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
                sendFeedbackInBackground(function, "POSITIVE", "");
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
                final Function target = function;
                if (target == null) {
                    return;
                }
                var dialog = new InputDialog("Negative Feedback", "Please provide details about what was wrong with the decompilation:", "");
                tool.showDialog(dialog);
                if (!dialog.isCanceled()) {
                    sendFeedbackInBackground(target, "NEGATIVE", dialog.getValue());
                }
            }

            @Override
            public boolean isEnabled() {
                // TODO: Only enable it if there is a decompilation to give feedback on
                return super.isEnabled();
            }
        });
    }

    private void sendFeedbackInBackground(Function target, String rating, String reason) {
        if (target == null) {
            return;
        }
        final String detail = reason == null ? "" : reason;
        tool.execute(new Task("Send AI Decompilation Feedback", false, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                var service = tool.getService(GhidraRevengService.class);
                var analyzedProgram = service.getAnalysedProgram(target.getProgram());
                if (analyzedProgram.isEmpty()) {
                    Msg.error(AIDecompilationdWindow.this,
                            "Failed to send %s feedback: Program is not known to RevEng.AI".formatted(rating));
                    return;
                }
                var fID = analyzedProgram.get().getIDForFunction(target);
                if (fID.isEmpty()) {
                    Msg.error(AIDecompilationdWindow.this,
                            "Failed to send %s feedback: function %s not known to RevEng.AI".formatted(rating, target.getName()));
                    return;
                }
                try {
                    service.getApi().aiDecompRating(fID.get().functionID(), rating, detail);
                } catch (ApiException e) {
                    Msg.error(AIDecompilationdWindow.this,
                            "Failed to send %s feedback for function %s: %s".formatted(rating, target.getName(), e.getMessage()));
                }
            }
        }, 0);
    }


    private JComponent buildComponent() {

        component = new JPanel(new BorderLayout());

        // Create header panel to hold description and predicted name panel
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));

        // Description area
        descriptionArea = new JEditorPane();
        descriptionArea.setContentType("text/html");
        descriptionArea.setEditable(false);
        descriptionArea.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        descriptionArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        descriptionArea.setText("No function selected or binary not analysed yet with RevEng.AI");
        headerPanel.add(descriptionArea);

        // Visual divider
        headerPanel.add(new JSeparator(SwingConstants.HORIZONTAL));

        // Predicted name panel (between description and code)
        predictedNamePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        predictedNameLabel = new JLabel("Predicted name: ");
        usePredictedNameButton = new JButton("Use Predicted Name");
        usePredictedNameButton.addActionListener(e -> applyPredictedName());
        predictedNamePanel.add(predictedNameLabel);
        predictedNamePanel.add(usePredictedNameButton);
        predictedNamePanel.setVisible(false); // Hidden until we have a prediction
        headerPanel.add(predictedNamePanel);

        component.add(headerPanel, BorderLayout.NORTH);

        // Code area
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

    /**
     * Apply the predicted function name to the current function
     */
    private void applyPredictedName() {
        if (function == null) {
            return;
        }

        var cachedStatus = cache.get(function);
        if (cachedStatus == null || cachedStatus.predictedFunctionName() == null) {
            return;
        }

        String predictedName = cachedStatus.predictedFunctionName();
        var program = function.getProgram();

        int txId = program.startTransaction("Rename function to predicted name");
        try {
            function.setName(predictedName, ghidra.program.model.symbol.SourceType.USER_DEFINED);
            Msg.info(this, "Renamed function to predicted name: " + predictedName);
        } catch (Exception ex) {
            Msg.showError(this, this.component, "Failed to rename function:", ex.getMessage(), ex);
        } finally {
            program.endTransaction(txId, true);
        }
    }

    public void setDisplayedValuesBasedOnStatus(Function function, AIDecompilationStatus status) {
        this.function = function;
        switch (status.status()) {
            case COMPLETED -> {
                setCode(withInlineComments(status.decompilation(), status.inlineComments()));
                descriptionArea.setText("<html>%s</html>".formatted(status.summary() == null ? "" : status.summary()));

                String predictedName = status.predictedFunctionName();
                if (predictedName != null && !predictedName.isEmpty()) {
                    predictedNameLabel.setText("Predicted name: " + predictedName);
                    predictedNamePanel.setVisible(true);
                } else {
                    predictedNamePanel.setVisible(false);
                }
            }
            case FAILED -> {
                setCode("");
                descriptionArea.setText("Decompilation failed");
                predictedNamePanel.setVisible(false);
            }
            case UNINITIALISED, PENDING, RUNNING -> {
                setCode("");
                descriptionArea.setText("Decompiling %s ...".formatted(function.getName()));
                predictedNamePanel.setVisible(false);
            }
            default -> {
                // Unknown status — leave existing UI state untouched.
            }
        }
    }

    /**
     * Splice inline comments into the decompilation as `// comment` lines above each
     * targeted line (1-indexed). Preserves the leading indentation of the target line.
     */
    private static String withInlineComments(String decompilation, java.util.List<AIDecompilationStatus.InlineCommentEntry> comments) {
        if (decompilation == null || decompilation.isEmpty() || comments == null || comments.isEmpty()) {
            return decompilation == null ? "" : decompilation;
        }
        var byLine = new java.util.HashMap<Long, String>();
        for (var entry : comments) {
            byLine.put(entry.line(), entry.comment());
        }
        String[] lines = decompilation.split("\n", -1);
        var out = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            long lineNumber = i + 1L;
            String comment = byLine.get(lineNumber);
            if (comment != null) {
                int indentEnd = 0;
                while (indentEnd < lines[i].length() && Character.isWhitespace(lines[i].charAt(indentEnd))) {
                    indentEnd++;
                }
                String indent = lines[i].substring(0, indentEnd);
                out.append(indent).append("// ").append(comment).append('\n');
            }
            out.append(lines[i]);
            if (i < lines.length - 1) {
                out.append('\n');
            }
        }
        return out.toString();
    }

    private void setCode(String code) {
        String text = code;
        textArea.setText(text);
    }

    private void clear() {
        this.function = null;
        setCode("");
        descriptionArea.setText("");
        predictedNamePanel.setVisible(false);
    }

    public void refresh(GhidraRevengService.FunctionWithID function) {
        // Check if we know this function already
        var cachedStatus = cache.get(function.function());
        if (cachedStatus != null) {
            setDisplayedValuesBasedOnStatus(function.function(), cachedStatus);
        } else {
            // TODO: Allow toggling auto decomp mode via local toggle action, for now do it always

            // Only start decompilation if the window is visible and the status of the analysis is complete.
            if (this.isVisible()) {
                taskMonitorComponent.setVisible(true);
                // Replace the initial "no function selected" placeholder before the first poll lands.
                this.function = function.function();
                setCode("");
                descriptionArea.setText("Decompiling %s ...".formatted(function.function().getName()));
                predictedNamePanel.setVisible(false);
                // Start a new background task to decompile the function
                var task = new AIDecompTask(tool, function);
                var builder = TaskBuilder.withTask(task);
                builder.launchInBackground(taskMonitorComponent);
            }
        }
    }

    public void locationChanged(ProgramLocation loc) {
        var service = tool.getService(GhidraRevengService.class);
        var analyzedProgram = service.getAnalysedProgram(loc.getProgram());
        if (analyzedProgram.isEmpty()) {
            clear();
            return;
        }

        var functionMgr = loc.getProgram().getFunctionManager();
        var newFuncLocation = functionMgr.getFunctionContaining(loc.getAddress());

        // If we changed to a different function, we want to clear the output of the old function
        if (function != null && !isSameFunction(newFuncLocation, function)) {
            clear();
        }

        function = newFuncLocation;
        var functionWithID = analyzedProgram.get().getIDForFunction(function);
        functionWithID.ifPresent(this::refresh);
    }


    void newStatusForFunction(Function function, AIDecompilationStatus status) {
        cache.put(function, status);
        if (isCurrentFunction(function)) {
            SwingUtilities.invokeLater(() ->
                    setDisplayedValuesBasedOnStatus(function, status)
            );
        }
        if (status.status() == DecompilationData.StatusEnum.COMPLETED) {
            var logger = tool.getService(ReaiLoggingService.class);
            logger.info("AI Decompilation finished for function %s: %s".formatted(function.getName(), status.decompilation()));
            if (!hasPendingDecompilations()) {
                taskMonitorComponent.setVisible(false);
            }
        } else if (status.status() == DecompilationData.StatusEnum.FAILED) {
            if (!hasPendingDecompilations()) {
                taskMonitorComponent.setVisible(false);
            }
        }
    }

    private boolean hasPendingDecompilations() {
        return cache.values().stream().anyMatch(s ->
                s.status() == DecompilationData.StatusEnum.PENDING
                        || s.status() == DecompilationData.StatusEnum.RUNNING);
    }

    private static boolean isSameFunction(Function a, Function b) {
        return a != null && b != null && a.getEntryPoint().equals(b.getEntryPoint());
    }

    private boolean isCurrentFunction(Function candidate) {
        return isSameFunction(candidate, this.function);
    }

    private void reportDecompFailure(Function failedFunction, Exception e) {
        var logger = tool.getService(ReaiLoggingService.class);
        logger.error("AI Decompilation failed for function %s: %s".formatted(failedFunction.getName(), e.getMessage()));
        Msg.error(this, "AI Decompilation failed for function %s".formatted(failedFunction.getName()), e);
        SwingUtilities.invokeLater(() -> {
            if (isCurrentFunction(failedFunction)) {
                descriptionArea.setText("AI Decompilation failed: " + e.getMessage());
                if (!hasPendingDecompilations()) {
                    taskMonitorComponent.setVisible(false);
                }
            }
        });
    }
    class AIDecompTask extends Task {

        private final GhidraRevengService service;
        private final GhidraRevengService.FunctionWithID functionWithID;

        public AIDecompTask(PluginTool tool, GhidraRevengService.FunctionWithID functionWithID) {
            super("AI Decomp task", true, false, false);
            service = tool.getService(GhidraRevengService.class);
            this.functionWithID = functionWithID;
        }

        @Override
        public void run(TaskMonitor monitor) throws CancelledException {
            try {
                var fID = functionWithID.functionID();
                // Check if there is an existing process already, because the trigger API will fail with 400 if there is
                if (service.getApi().pollAIDecompileStatus(fID).status() == DecompilationData.StatusEnum.UNINITIALISED) {
                    // Trigger the decompilation
                    service.getApi().triggerAIDecompilationForFunctionID(fID);
                }
                waitForDecomp(fID, monitor);
                // TODO: Inform the component that something is finished
            } catch (CancelledException e) {
                throw e;
            } catch (Exception e) {
                reportDecompFailure(functionWithID.function(), e);
            }
        }


        private void waitForDecomp(TypedApiInterface.FunctionID id, TaskMonitor monitor) throws CancelledException {
            var logger = tool.getService(ReaiLoggingService.class);
            var api = service.getApi();
            AIDecompilationStatus lastDecompStatus = null;
            boolean inlineCommentsTriggered = false;
            boolean summaryTriggered = false;
            while (true) {
                var newStatus = api.pollAIDecompileStatus(id);
                if (lastDecompStatus == null
                        || !Objects.equals(newStatus.status(), lastDecompStatus.status())
                        || !Objects.equals(newStatus.summaryStatus(), lastDecompStatus.summaryStatus())
                        || !Objects.equals(newStatus.inlineCommentsStatus(), lastDecompStatus.inlineCommentsStatus())
                        || newStatus.inlineComments().size() != lastDecompStatus.inlineComments().size()) {
                    lastDecompStatus = newStatus;
                    newStatusForFunction(functionWithID.function(), newStatus);
                }
                monitor.setMessage("Waiting for AI Decompilation for %s ... Current status: %s".formatted(functionWithID.function().getName(), lastDecompStatus.status()));
                monitor.checkCancelled();
                switch (newStatus.status()) {
                    case PENDING:
                    case RUNNING:
                    case UNINITIALISED:
                        try {
                            // Wait a second before polling again. We don't want to spam the API with requests too often
                            Thread.sleep(1000);
                        } catch (InterruptedException e) {
                            throw new RuntimeException(e);
                        }
                        break;
                    case COMPLETED:
                        monitor.setProgress(monitor.getMaximum());
                        // Decompilation is done; now wait for inline comments to land before stopping.
                        var commentsStatus = newStatus.inlineCommentsStatus();
                        if (commentsStatus == WorkflowProgress.StatusEnum.COMPLETED) {
                            return;
                        }
                        if (commentsStatus == WorkflowProgress.StatusEnum.FAILED) {
                            logger.error("Inline comments generation failed for function %s".formatted(functionWithID.function().getName()));
                            return;
                        }
                        var summaryStatus = newStatus.summaryStatus();
                        if (!summaryTriggered) {
                            // Summary generation is no longer automatic on the create-decompilation call;
                            // callers must POST to kick it off, like inline comments.
                            summaryTriggered = true;
                            try {
                                api.triggerAIDecompilationSummary(id);
                            } catch (RuntimeException e) {
                                logger.error("Failed to trigger summary: %s".formatted(e.getMessage()));
                            }
                        }
                        if (summaryStatus == WorkflowProgress.StatusEnum.FAILED) {
                            // Server requires a summary to exist before inline comments can be generated;
                            // if the summary failed there's no point triggering comments.
                            logger.error("Summary generation failed for function %s; skipping inline comments".formatted(functionWithID.function().getName()));
                            return;
                        }
                        if (summaryStatus == WorkflowProgress.StatusEnum.COMPLETED && !inlineCommentsTriggered) {
                            // Gate the inline-comments POST on summary completion — the server rejects it
                            // with HTTP 400 otherwise ("A summary is required before inline comments can be generated").
                            inlineCommentsTriggered = true;
                            try {
                                api.triggerAIDecompilationInlineComments(id);
                            } catch (RuntimeException e) {
                                logger.error("Failed to trigger inline comments: %s".formatted(e.getMessage()));
                                return;
                            }
                        }
                        try {
                            Thread.sleep(1000);
                        } catch (InterruptedException e) {
                            throw new RuntimeException(e);
                        }
                        break;
                    case FAILED:
                        logger.error("Decompilation failed: %s".formatted(newStatus.decompilation()));
                        return;
                    default:
                        throw new RuntimeException("Unknown status: %s".formatted(newStatus.status()));
                }

            }
        }

    }
}

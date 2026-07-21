package ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.AIDecompFunctionMapping;
import ai.reveng.model.DecompilationData;
import ai.reveng.model.ProgressMessage;
import ai.reveng.model.ReplacementValue;
import ai.reveng.model.TokenisedData;
import ai.reveng.model.WorkflowProgress;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
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
import javax.swing.text.BadLocationException;
import javax.swing.text.Utilities;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    /// Function IDs with a decompilation task currently running. Several functions can decompile
    /// concurrently in the background; this guards against launching a second task for a function
    /// that is already in flight (which would double-POST the trigger).
    private final java.util.Set<Long> inFlightDecompilations = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /// Line map for the currently displayed decompilation, used to translate a click position in the
    /// text area back to a source line/identifier for rename and comment editing. Null while no
    /// completed decompilation is shown.
    private RenderModel currentRenderModel;

    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z_]\\w*");


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

        addLocalAction(new DockingAction("Refresh AI Decompilation", getName()) {
            {
                setToolBarData(new ToolBarData(new GIcon("icon.refresh"), null));
                setDescription("Re-pull the AI decompilation for the current function from RevEng.AI");
            }

            @Override
            public void actionPerformed(ActionContext context) {
                refreshCurrentFunction();
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
        // The view stays read-only; edits are driven through double-click (rename) and the
        // right-click context menu (comments) so they can be synced back to RevEng.AI.
        textArea.setPopupMenu(null);
        textArea.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    handleDoubleClick(e.getPoint());
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                maybeShowPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                maybeShowPopup(e);
            }

            private void maybeShowPopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    showContextMenu(e.getPoint());
                }
            }
        });
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
                setCode(renderWithMap(status.decompilation(), status.inlineComments()));
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
                currentRenderModel = null;
                String detail = status.decompilation();
                setCode(detail != null && !detail.isBlank() ? detail : "");
                descriptionArea.setText("AI Decompilation failed");
                predictedNamePanel.setVisible(false);
            }
            case UNINITIALISED, PENDING, RUNNING -> {
                currentRenderModel = null;
                WorkflowProgress progress = status.decompilationProgress();
                setCode(progress != null ? renderProgress(progress) : "");
                descriptionArea.setText("Decompiling %s ...".formatted(function.getName()));
                predictedNamePanel.setVisible(false);
            }
            default -> {
                // Unknown status — leave existing UI state untouched.
            }
        }
    }

    private static final DateTimeFormatter PROGRESS_TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

    /**
     * Render the decompilation pipeline progress as `//` comment lines so it can be shown
     * in the code box while we wait. Mirrors the IDA plugin's progress view.
     */
    private static String renderProgress(WorkflowProgress progress) {
        var lines = new ArrayList<String>();
        lines.add("// RevEng.AI — AI decompilation in progress…");
        lines.add("//");

        long stepsTotal = progress.getStepsTotal() == null ? 0 : progress.getStepsTotal();
        long stepIndex = progress.getStepIndex() == null ? 0 : progress.getStepIndex();
        String step = progress.getStep() == null ? "" : progress.getStep();
        String status = progress.getStatus() == null ? "" : progress.getStatus().getValue();

        if (stepsTotal > 0) {
            long current = Math.min(stepIndex + 1, stepsTotal);
            lines.add("// Step %d/%d: %s [%s]".formatted(current, stepsTotal, step, status));
        } else if (!step.isEmpty()) {
            lines.add("// %s [%s]".formatted(step, status));
        } else {
            lines.add("// %s".formatted(status));
        }

        List<ProgressMessage> messages = progress.getMessages();
        if (messages != null && !messages.isEmpty()) {
            lines.add("//");
            for (var message : messages) {
                lines.add("// " + formatProgressMessage(message));
            }
        }
        return String.join("\n", lines);
    }

    private static String formatProgressMessage(ProgressMessage message) {
        String stamp = formatProgressTime(message.getTimestamp());
        String prefix = stamp.isEmpty() ? "" : stamp + " ";
        return "%s[%s] %s".formatted(prefix, message.getLevel(), message.getText());
    }

    private static String formatProgressTime(OffsetDateTime timestamp) {
        if (timestamp == null) {
            return "";
        }
        try {
            return timestamp.format(PROGRESS_TIME);
        } catch (RuntimeException e) {
            return "";
        }
    }

    /**
     * Render the decompilation into displayable text while recording the mapping from each display
     * line back to its 1-indexed source line. Inline comments are spliced in as `// comment` lines
     * above the line they annotate, preserving that line's indentation. Mirrors the IDA plugin's
     * {@code render_view_with_map}.
     */
    private String renderWithMap(String decompilation, List<AIDecompilationStatus.InlineCommentEntry> comments) {
        String[] codeLines = (decompilation == null ? "" : decompilation).split("\n", -1);
        var commentBySource = new java.util.HashMap<Long, String>();
        if (comments != null) {
            for (var entry : comments) {
                if (entry.line() >= 1 && entry.line() <= codeLines.length) {
                    commentBySource.put(entry.line(), entry.comment());
                }
            }
        }

        var displayLines = new ArrayList<String>();
        var displaySource = new ArrayList<Integer>();
        var displayIsCode = new ArrayList<Boolean>();

        for (int idx = 0; idx < codeLines.length; idx++) {
            int sourceLine = idx + 1;
            String code = codeLines[idx];
            String comment = commentBySource.get((long) sourceLine);
            if (comment != null) {
                String indent = leadingWhitespace(code);
                for (String part : comment.split("\n", -1)) {
                    displayLines.add(indent + "// " + part);
                    displaySource.add(sourceLine);
                    displayIsCode.add(false);
                }
            }
            displayLines.add(code);
            displaySource.add(sourceLine);
            displayIsCode.add(true);
        }

        currentRenderModel = new RenderModel(List.of(codeLines), commentBySource, displaySource, displayIsCode);
        return String.join("\n", displayLines);
    }

    private static String leadingWhitespace(String line) {
        int end = 0;
        while (end < line.length() && Character.isWhitespace(line.charAt(end))) {
            end++;
        }
        return line.substring(0, end);
    }

    private void setCode(String code) {
        String text = code;
        textArea.setText(text);
    }

    private void clear() {
        this.function = null;
        this.currentRenderModel = null;
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
                // Replace the initial "no function selected" placeholder before the first poll lands.
                this.function = function.function();
                setCode("");
                descriptionArea.setText("Decompiling %s ...".formatted(function.function().getName()));
                predictedNamePanel.setVisible(false);
                // Start a background task unless this function is already being decompiled. Multiple
                // functions decompile in parallel in the background; a running task updates the view
                // when it polls, so revisiting an in-flight function just shows this placeholder.
                if (inFlightDecompilations.add(function.functionID().value())) {
                    taskMonitorComponent.setVisible(true);
                    var task = new AIDecompTask(tool, function);
                    var builder = TaskBuilder.withTask(task);
                    builder.launchInBackground(taskMonitorComponent);
                }
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

    /**
     * Evict the current function from the local cache and re-pull its decompilation from the portal.
     * The plugin never re-fetches automatically once a result is cached, so this is the only way to
     * pick up changes made elsewhere.
     */
    private void refreshCurrentFunction() {
        Function target = this.function;
        if (target == null) {
            return;
        }
        cache.remove(target);
        currentRenderModel = null;
        var service = tool.getService(GhidraRevengService.class);
        var analysed = service.getAnalysedProgram(target.getProgram());
        if (analysed.isEmpty()) {
            return;
        }
        analysed.get().getIDForFunction(target).ifPresent(this::refresh);
    }

    // --- Rename / comment editing -------------------------------------------------------------

    private void handleDoubleClick(Point point) {
        try {
            int offset = textArea.viewToModel2D(point);
            if (offset < 0) {
                return;
            }
            int displayLine = textArea.getLineOfOffset(offset);
            String word = wordAtOffset(offset);
            if (word != null && !word.isEmpty()) {
                handleRename(displayLine, word);
            }
        } catch (BadLocationException e) {
            // Click outside of any text — nothing to do.
        }
    }

    private void showContextMenu(Point point) {
        try {
            int offset = textArea.viewToModel2D(point);
            if (offset < 0) {
                return;
            }
            int displayLine = textArea.getLineOfOffset(offset);
            String word = wordAtOffset(offset);

            JPopupMenu menu = new JPopupMenu();
            if (word != null && !word.isEmpty()
                    && currentRenderModel != null && currentRenderModel.isCodeLine(displayLine)) {
                JMenuItem rename = new JMenuItem("Rename '%s'…".formatted(word));
                rename.addActionListener(a -> handleRename(displayLine, word));
                menu.add(rename);
            }
            JMenuItem editComment = new JMenuItem("Add / edit comment…");
            editComment.addActionListener(a -> handleEditComment(displayLine));
            menu.add(editComment);
            JMenuItem removeComment = new JMenuItem("Remove comment");
            removeComment.addActionListener(a -> handleRemoveComment(displayLine));
            menu.add(removeComment);

            if (menu.getComponentCount() > 0) {
                menu.show(textArea, point.x, point.y);
            }
        } catch (BadLocationException e) {
            // Click outside of any text — nothing to do.
        }
    }

    private String wordAtOffset(int offset) throws BadLocationException {
        int start = Utilities.getWordStart(textArea, offset);
        int end = Utilities.getWordEnd(textArea, offset);
        String word = textArea.getText(start, end - start);
        return IDENTIFIER.matcher(word).matches() ? word : null;
    }

    private void handleRename(int displayLine, String word) {
        RenderModel model = currentRenderModel;
        Function target = this.function;
        if (model == null || target == null || word == null || word.isBlank()) {
            return;
        }
        if (!model.isCodeLine(displayLine)) {
            return;
        }
        Integer sourceLine = model.sourceLine(displayLine);
        if (sourceLine == null) {
            return;
        }
        String codeLine = model.codeLines.get(sourceLine - 1);
        int identIndex = indexOfIdentifier(codeLine, word);
        if (identIndex < 0) {
            return;
        }
        FunctionID functionID = resolveFunctionId(target);
        if (functionID == null) {
            return;
        }

        var dialog = new InputDialog("Rename", "Rename '%s' to:".formatted(word), word);
        tool.showDialog(dialog);
        if (dialog.isCanceled()) {
            return;
        }
        String newName = dialog.getValue();
        if (newName == null || newName.isBlank() || newName.equals(word)) {
            return;
        }

        final int sourceIndex = sourceLine - 1;
        var service = tool.getService(GhidraRevengService.class);
        tool.execute(new Task("Rename AI decompilation identifier", true, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    TokenisedData tokenised = service.getApi().getAIDecompilationTokenised(functionID);
                    String token = resolveToken(tokenised, sourceIndex, identIndex, word);
                    if (token == null) {
                        SwingUtilities.invokeLater(() -> Msg.showInfo(AIDecompilationdWindow.this, component,
                                "Rename", "'%s' is not a renameable variable or type.".formatted(word)));
                        return;
                    }
                    service.getApi().applyAIDecompilationOverrides(functionID, Map.of(token, newName));
                    newStatusForFunction(target, service.getApi().pollAIDecompileStatus(functionID));
                } catch (Exception e) {
                    reportEditError("Rename", e);
                }
            }
        }, 0);
    }

    private void handleEditComment(int displayLine) {
        RenderModel model = currentRenderModel;
        Function target = this.function;
        if (model == null || target == null) {
            return;
        }
        Integer sourceLine = model.sourceLine(displayLine);
        if (sourceLine == null) {
            return;
        }
        FunctionID functionID = resolveFunctionId(target);
        if (functionID == null) {
            return;
        }
        final long line = sourceLine;
        boolean hadComment = model.commentBySource.containsKey(line);
        String existing = model.commentBySource.getOrDefault(line, "");

        var dialog = new InputDialog("Comment", "Comment for line %d:".formatted(line), existing);
        tool.showDialog(dialog);
        if (dialog.isCanceled()) {
            return;
        }
        String value = dialog.getValue();
        final String comment = value == null ? "" : value.strip();

        var service = tool.getService(GhidraRevengService.class);
        tool.execute(new Task("Update AI decompilation comment", true, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    if (comment.isEmpty()) {
                        if (!hadComment) {
                            return;
                        }
                        service.getApi().deleteAIDecompilationInlineComment(functionID, line);
                    } else {
                        service.getApi().setAIDecompilationInlineComment(functionID, line, comment);
                    }
                    newStatusForFunction(target, service.getApi().pollAIDecompileStatus(functionID));
                } catch (Exception e) {
                    reportEditError("Update comment", e);
                }
            }
        }, 0);
    }

    private void handleRemoveComment(int displayLine) {
        RenderModel model = currentRenderModel;
        Function target = this.function;
        if (model == null || target == null) {
            return;
        }
        Integer sourceLine = model.sourceLine(displayLine);
        if (sourceLine == null) {
            return;
        }
        final long line = sourceLine;
        if (!model.commentBySource.containsKey(line)) {
            Msg.showInfo(this, component, "Remove comment", "No comment on this line.");
            return;
        }
        FunctionID functionID = resolveFunctionId(target);
        if (functionID == null) {
            return;
        }
        var service = tool.getService(GhidraRevengService.class);
        tool.execute(new Task("Remove AI decompilation comment", true, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    service.getApi().deleteAIDecompilationInlineComment(functionID, line);
                    newStatusForFunction(target, service.getApi().pollAIDecompileStatus(functionID));
                } catch (Exception e) {
                    reportEditError("Remove comment", e);
                }
            }
        }, 0);
    }

    private FunctionID resolveFunctionId(Function target) {
        if (target == null) {
            return null;
        }
        var service = tool.getService(GhidraRevengService.class);
        var analysed = service.getAnalysedProgram(target.getProgram());
        if (analysed.isEmpty()) {
            return null;
        }
        return analysed.get().getIDForFunction(target)
                .map(GhidraRevengService.FunctionWithID::functionID)
                .orElse(null);
    }

    private void reportEditError(String action, Exception e) {
        var logger = tool.getService(ReaiLoggingService.class);
        logger.error("%s failed: %s".formatted(action, e.getMessage()));
        SwingUtilities.invokeLater(() ->
                Msg.showError(this, component, action + " failed", e.getMessage(), e));
    }

    /**
     * Position of the first identifier equal to {@code word} within {@code line}. The tokenised
     * decompilation carries a token at the same identifier position, which is how a displayed name
     * is resolved back to the token to override.
     */
    static int indexOfIdentifier(String line, String word) {
        var identifiers = identifiers(line);
        return identifiers.indexOf(word);
    }

    private static List<String> identifiers(String line) {
        var result = new ArrayList<String>();
        Matcher matcher = IDENTIFIER.matcher(line == null ? "" : line);
        while (matcher.find()) {
            result.add(matcher.group());
        }
        return result;
    }

    /**
     * Resolve a displayed identifier to the token to override, mirroring the IDA plugin's
     * {@code resolve_token}: prefer the token at the same identifier position in the tokenised line,
     * and fall back to a unique match across the renameable categories by effective value.
     */
    static String resolveToken(TokenisedData tokenised, int sourceIndex, int identIndex, String oldIdent) {
        if (tokenised == null) {
            return null;
        }
        AIDecompFunctionMapping mapping = tokenised.getFunctionMapping();
        if (mapping == null) {
            return null;
        }

        String tokenisedText = tokenised.getTokenisedDecompilation();
        String[] tokenisedLines = (tokenisedText == null ? "" : tokenisedText).split("\n", -1);
        if (sourceIndex >= 0 && sourceIndex < tokenisedLines.length) {
            var tokenIdentifiers = identifiers(tokenisedLines[sourceIndex]);
            if (identIndex >= 0 && identIndex < tokenIdentifiers.size()) {
                String candidate = tokenIdentifiers.get(identIndex);
                for (TokenEntry entry : renameableTokens(mapping)) {
                    if (entry.token().equals(candidate)
                            && oldIdent.equals(effectiveValue(mapping, entry.token(), entry.replacement()))) {
                        return candidate;
                    }
                }
            }
        }

        String uniqueMatch = null;
        for (TokenEntry entry : renameableTokens(mapping)) {
            if (oldIdent.equals(effectiveValue(mapping, entry.token(), entry.replacement()))) {
                if (uniqueMatch != null) {
                    return null;
                }
                uniqueMatch = entry.token();
            }
        }
        return uniqueMatch;
    }

    private record TokenEntry(String token, ReplacementValue replacement) {}

    private static List<TokenEntry> renameableTokens(AIDecompFunctionMapping mapping) {
        var entries = new ArrayList<TokenEntry>();
        addTokens(entries, mapping.getUnmatchedVars());
        addTokens(entries, mapping.getUnmatchedGlobalVars());
        addTokens(entries, mapping.getUnmatchedExternalVars());
        addTokens(entries, mapping.getUnmatchedCustomTypes());
        addTokens(entries, mapping.getUnmatchedEnums());
        return entries;
    }

    private static void addTokens(List<TokenEntry> entries, Map<String, ReplacementValue> category) {
        if (category == null) {
            return;
        }
        for (var e : category.entrySet()) {
            entries.add(new TokenEntry(e.getKey(), e.getValue()));
        }
    }

    private static String effectiveValue(AIDecompFunctionMapping mapping, String token, ReplacementValue replacement) {
        Map<String, String> overrides = mapping.getUserOverrideMappings();
        if (overrides != null && overrides.containsKey(token)) {
            return overrides.get(token);
        }
        return replacement == null ? null : replacement.getValue();
    }


    void newStatusForFunction(Function function, AIDecompilationStatus status) {
        var previous = cache.get(function);
        cache.put(function, status);
        if (isCurrentFunction(function)) {
            SwingUtilities.invokeLater(() ->
                    setDisplayedValuesBasedOnStatus(function, status)
            );
        }
        if (status.status() == DecompilationData.StatusEnum.COMPLETED) {
            boolean justCompleted = previous == null || previous.status() != DecompilationData.StatusEnum.COMPLETED;
            if (justCompleted) {
                var logger = tool.getService(ReaiLoggingService.class);
                logger.info("AI Decompilation finished for function %s".formatted(function.getName()));
            }
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

    /**
     * Maps each display line of the rendered decompilation back to its source line, so a click in
     * the text area can be resolved to the line/identifier to rename or comment on.
     */
    private static final class RenderModel {
        private final List<String> codeLines;
        private final Map<Long, String> commentBySource;
        private final List<Integer> displaySource;
        private final List<Boolean> displayIsCode;

        RenderModel(List<String> codeLines, Map<Long, String> commentBySource,
                    List<Integer> displaySource, List<Boolean> displayIsCode) {
            this.codeLines = codeLines;
            this.commentBySource = commentBySource;
            this.displaySource = displaySource;
            this.displayIsCode = displayIsCode;
        }

        Integer sourceLine(int displayLine) {
            if (displayLine < 0 || displayLine >= displaySource.size()) {
                return null;
            }
            return displaySource.get(displayLine);
        }

        boolean isCodeLine(int displayLine) {
            return displayLine >= 0 && displayLine < displayIsCode.size() && displayIsCode.get(displayLine);
        }
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
            } finally {
                inFlightDecompilations.remove(functionWithID.functionID().value());
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
                        || newStatus.inlineComments().size() != lastDecompStatus.inlineComments().size()
                        || !Objects.equals(newStatus.decompilationProgress(), lastDecompStatus.decompilationProgress())) {
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

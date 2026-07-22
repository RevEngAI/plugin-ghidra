package ai.reveng.toolkit.ghidra.chat.ui;

import ai.reveng.toolkit.ghidra.chat.model.ChatState;
import ai.reveng.toolkit.ghidra.chat.model.ChatTranscriptRenderer;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.ToolConfirmation;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationContext;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationSummary;
import ai.reveng.toolkit.ghidra.chat.service.ChatService;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.BrowserLoader;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.net.URI;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Dockable Agent Chat panel. A thin {@link ChatView} over a {@link ChatController}: it renders the
 * transcript, forwards button/link input, and resolves Ghidra-side context (current analysis +
 * function) and view refreshes. Modelled on {@code AIDecompilationdWindow}; the IDA analogue is
 * {@code ChatPanel}.
 */
public class AgentChatWindow extends ComponentProviderAdapter implements ChatView {

    private final ChatController controller;
    private final Executor workerExecutor;

    private JComponent component;
    private JLabel titleLabel;
    private JLabel contextLabel;
    private DefaultListModel<ConversationSummary> historyModel;
    private JScrollPane historyScroll;
    private JEditorPane transcript;
    private JPanel confirmBar;
    private JLabel confirmMessage;
    private JTextArea input;
    private JButton sendButton;
    private JButton stopButton;

    private String pendingConfirmId;
    private String lastRenderedHtml;
    private Function currentFunction;

    public AgentChatWindow(PluginTool tool, String owner, ChatService service) {
        super(tool, ReaiPluginPackage.WINDOW_PREFIX + "Agent Chat", owner);
        setIcon(ReaiPluginPackage.REVENG_16);

        this.workerExecutor = Executors.newSingleThreadExecutor(runnable -> {
            var thread = new Thread(runnable, "RevEng.AI-AgentChat");
            thread.setDaemon(true);
            return thread;
        });
        this.component = buildComponent();
        this.controller = new ChatController(service, this, loggingService(),
                SwingUtilities::invokeLater, workerExecutor, new ControllerCallbacks());
        render(ChatState.initial());
    }

    private JComponent buildComponent() {
        JPanel root = new JPanel(new BorderLayout(6, 6));
        root.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        // Header: title + History / New chat
        JPanel header = new JPanel(new BorderLayout());
        titleLabel = new JLabel("AI Agent");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        JPanel headerButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        JButton historyButton = new JButton("History");
        JButton newChatButton = new JButton("New chat");
        historyButton.addActionListener(e -> onHistoryClicked());
        newChatButton.addActionListener(e -> controller.newConversation());
        headerButtons.add(historyButton);
        headerButtons.add(newChatButton);
        header.add(titleLabel, BorderLayout.WEST);
        header.add(headerButtons, BorderLayout.EAST);

        JPanel top = new JPanel(new BorderLayout(0, 4));
        top.add(header, BorderLayout.NORTH);

        contextLabel = new JLabel("No analysis attached");
        contextLabel.setForeground(Color.GRAY);
        top.add(contextLabel, BorderLayout.CENTER);

        historyModel = new DefaultListModel<>();
        JList<ConversationSummary> historyList = new JList<>(historyModel);
        historyList.setCellRenderer((list, value, index, selected, focused) ->
                new JLabel(value.title() != null ? value.title() : "Untitled"));
        historyList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                ConversationSummary selected = historyList.getSelectedValue();
                if (selected != null) {
                    controller.loadConversation(selected.conversationUuid());
                }
            }
        });
        historyScroll = new JScrollPane(historyList);
        historyScroll.setPreferredSize(new Dimension(0, 120));
        historyScroll.setVisible(false);
        top.add(historyScroll, BorderLayout.SOUTH);

        root.add(top, BorderLayout.NORTH);

        transcript = new JEditorPane();
        transcript.setContentType("text/html");
        transcript.setEditable(false);
        transcript.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        transcript.addHyperlinkListener(e -> {
            if (e.getEventType() == javax.swing.event.HyperlinkEvent.EventType.ACTIVATED) {
                onLinkActivated(e.getDescription());
            }
        });
        root.add(new JScrollPane(transcript), BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout(0, 4));

        confirmBar = new JPanel(new BorderLayout(4, 0));
        confirmMessage = new JLabel();
        JPanel confirmButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        JButton approve = new JButton("Approve");
        JButton reject = new JButton("Reject");
        approve.addActionListener(e -> onConfirm(true));
        reject.addActionListener(e -> onConfirm(false));
        confirmButtons.add(approve);
        confirmButtons.add(reject);
        confirmBar.add(confirmMessage, BorderLayout.CENTER);
        confirmBar.add(confirmButtons, BorderLayout.EAST);
        confirmBar.setVisible(false);
        bottom.add(confirmBar, BorderLayout.NORTH);

        JPanel inputRow = new JPanel(new BorderLayout(4, 0));
        input = new JTextArea(3, 40);
        input.setLineWrap(true);
        input.setWrapStyleWord(true);
        // Enter sends; Shift+Enter inserts a newline.
        input.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "reai-send");
        input.getActionMap().put("reai-send", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                onSendClicked();
            }
        });
        JPanel buttonColumn = new JPanel(new GridLayout(2, 1, 0, 4));
        sendButton = new JButton("Send");
        stopButton = new JButton("Stop");
        sendButton.addActionListener(e -> onSendClicked());
        stopButton.addActionListener(e -> controller.stop());
        stopButton.setEnabled(false);
        buttonColumn.add(sendButton);
        buttonColumn.add(stopButton);
        inputRow.add(new JScrollPane(input), BorderLayout.CENTER);
        inputRow.add(buttonColumn, BorderLayout.EAST);
        bottom.add(inputRow, BorderLayout.CENTER);

        root.add(bottom, BorderLayout.SOUTH);
        return root;
    }

    @Override
    public JComponent getComponent() {
        return component;
    }

    // --- ChatView ----------------------------------------------------------------------------

    @Override
    public void render(ChatState state) {
        String html = ChatTranscriptRenderer.renderTranscriptHtml(state);
        if (!html.equals(lastRenderedHtml)) {
            lastRenderedHtml = html;
            transcript.setText(html);
            transcript.setCaretPosition(transcript.getDocument().getLength());
        }

        boolean running = "running".equals(state.runStatus());
        sendButton.setEnabled(!running);
        stopButton.setEnabled(running);
        titleLabel.setText(state.title() != null ? state.title() : "AI Agent");

        ToolConfirmation pending = ChatTranscriptRenderer.findPendingConfirmation(state);
        if (pending != null) {
            pendingConfirmId = pending.id();
            confirmMessage.setText(!pending.message().isEmpty()
                    ? pending.message()
                    : "Approve tool '%s'?".formatted(ChatTranscriptRenderer.titleCase(pending.toolName())));
            confirmBar.setVisible(true);
        } else {
            pendingConfirmId = null;
            confirmBar.setVisible(false);
        }
        component.revalidate();
        component.repaint();
    }

    @Override
    public void setContextChip(String text) {
        contextLabel.setText(text == null || text.isEmpty() ? "No analysis attached" : text);
    }

    @Override
    public void setHistory(List<ConversationSummary> summaries) {
        historyModel.clear();
        for (ConversationSummary summary : summaries) {
            historyModel.addElement(summary);
        }
    }

    // --- Tool wiring -------------------------------------------------------------------------

    /// Called by the plugin when the cursor moves, to keep the context chip current.
    public void locationChanged(ProgramLocation location) {
        if (location == null || location.getProgram() == null) {
            return;
        }
        Program program = location.getProgram();
        var analysed = revengService().getAnalysedProgram(program);
        currentFunction = analysed.isPresent()
                ? program.getFunctionManager().getFunctionContaining(location.getAddress())
                : null;
        setContextChip(resolveContextChipText());
    }

    private void onSendClicked() {
        String text = input.getText();
        if (text == null || text.strip().isEmpty()) {
            return;
        }
        input.setText("");
        controller.send(text);
    }

    private void onConfirm(boolean approved) {
        if (pendingConfirmId != null) {
            controller.confirmTool(pendingConfirmId, approved);
        }
    }

    private void onHistoryClicked() {
        boolean show = !historyScroll.isVisible();
        historyScroll.setVisible(show);
        if (show) {
            controller.requestHistory();
        }
        component.revalidate();
    }

    private void onLinkActivated(String href) {
        if (href == null) {
            return;
        }
        Long offset = ChatTranscriptRenderer.parseJumpHref(href);
        if (offset != null) {
            Program program = currentProgram();
            GoToService goToService = tool.getService(GoToService.class);
            if (program != null && goToService != null) {
                Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
                goToService.goTo(new ProgramLocation(program, address));
            }
            return;
        }
        // A link from the agent's markdown (e.g. a portal or docs URL) — open it in the browser.
        if (href.startsWith("http://") || href.startsWith("https://")) {
            try {
                BrowserLoader.display(URI.create(href).toURL());
            } catch (Exception e) {
                loggingService().warn("Failed to open link " + href + ": " + e.getMessage());
            }
        }
    }

    // --- ChatController.Callbacks ------------------------------------------------------------

    private final class ControllerCallbacks implements ChatController.Callbacks {
        @Override
        public ConversationContext resolveContext() {
            Long analysisId = null;
            Long functionId = null;
            Program program = currentProgram();
            if (program != null) {
                var analysed = revengService().getAnalysedProgram(program);
                if (analysed.isPresent()) {
                    analysisId = (long) analysed.get().analysisID().id();
                    Function function = currentFunction;
                    if (function != null) {
                        var withId = analysed.get().getIDForFunction(function);
                        if (withId.isPresent()) {
                            functionId = withId.get().functionID().value();
                        }
                    }
                }
            }
            return new ConversationContext(analysisId, functionId);
        }

        @Override
        public void onFunctionsTouched(List<Long> functionIds) {
            Program program = currentProgram();
            if (program == null) {
                return;
            }
            var analysed = revengService().getAnalysedProgram(program);
            if (analysed.isEmpty()) {
                return;
            }
            // Re-pull names the agent changed server-side so they appear without a manual refresh.
            // A refresh must never take down the chat: a failure here is logged, not propagated.
            tool.execute(new Task("Refresh functions after agent tool", false, false, false) {
                @Override
                public void run(TaskMonitor monitor) {
                    try {
                        revengService().pullFunctionInfoFromAnalysis(analysed.get(), monitor);
                    } catch (Exception e) {
                        loggingService().warn("Failed to refresh functions after agent tool: " + e.getMessage());
                    }
                }
            }, 0);
        }
    }

    private String resolveContextChipText() {
        Program program = currentProgram();
        if (program == null) {
            return "No analysis attached";
        }
        var analysed = revengService().getAnalysedProgram(program);
        if (analysed.isEmpty()) {
            return "No analysis attached";
        }
        StringBuilder bits = new StringBuilder();
        if (currentFunction != null) {
            bits.append("fn: ").append(currentFunction.getName());
        }
        if (bits.length() > 0) {
            bits.append("   ");
        }
        bits.append("analysis #").append(analysed.get().analysisID().id());
        return bits.toString();
    }

    private Program currentProgram() {
        ProgramManager programManager = tool.getService(ProgramManager.class);
        return programManager == null ? null : programManager.getCurrentProgram();
    }

    private GhidraRevengService revengService() {
        return tool.getService(GhidraRevengService.class);
    }

    private ReaiLoggingService loggingService() {
        return tool.getService(ReaiLoggingService.class);
    }

    public void dispose() {
        controller.dispose();
    }
}

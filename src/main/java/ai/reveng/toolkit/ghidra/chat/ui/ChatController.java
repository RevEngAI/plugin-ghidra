package ai.reveng.toolkit.ghidra.chat.ui;

import ai.reveng.toolkit.ghidra.chat.model.ChatEvent;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer.ApiError;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer.Cancel;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer.ConfirmTool;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer.EventAction;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer.SendMessage;
import ai.reveng.toolkit.ghidra.chat.model.ChatState;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationContext;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationReplay;
import ai.reveng.toolkit.ghidra.chat.service.ChatService;
import ai.reveng.toolkit.ghidra.chat.service.ChatServiceException;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Owns the {@link ChatState}, the active conversation, and the streaming worker lifecycle; wires the
 * {@link ChatView} to the {@link ChatService}. Every state transition goes through the pure
 * {@link ChatReducer}. Port of the IDA plugin's {@code ChatCoordinator}.
 *
 * <p>Swing-free and unit-testable: network work is submitted to {@code workerExecutor} and all state
 * mutations / view calls run on {@code uiExecutor}. Public methods are expected to be called on the
 * UI thread.
 */
public class ChatController {

    /// Ghidra-specific hooks the controller needs but must not depend on directly.
    public interface Callbacks {
        /// Resolve the current chat context (analysis + focused function) from the tool state.
        ConversationContext resolveContext();

        /// A tool result reported these function ids as changed; refresh the local view for them.
        void onFunctionsTouched(List<Long> functionIds);
    }

    private final ChatService service;
    private final ChatView view;
    private final ReaiLoggingService log;
    private final Executor uiExecutor;
    private final Executor workerExecutor;
    private final Callbacks callbacks;

    private ChatState state = ChatState.initial();
    private String conversationId;
    private Long lastEventId;
    private volatile StreamWorker currentWorker;

    public ChatController(ChatService service, ChatView view, ReaiLoggingService log,
                          Executor uiExecutor, Executor workerExecutor, Callbacks callbacks) {
        this.service = service;
        this.view = view;
        this.log = log;
        this.uiExecutor = uiExecutor;
        this.workerExecutor = workerExecutor;
        this.callbacks = callbacks;
    }

    public ChatState state() {
        return state;
    }

    public void send(String text) {
        String content = text == null ? "" : text.strip();
        if (content.isEmpty() || "running".equals(state.runStatus())) {
            return;
        }
        setState(ChatReducer.reduce(state, new SendMessage(newId(), content)));
        ConversationContext context = callbacks.resolveContext();
        startWorker(new StreamWorker(conversationId, content, context, null));
    }

    public void stop() {
        stopCurrentWorker();
        setState(ChatReducer.reduce(state, new Cancel()));
        String id = conversationId;
        if (id != null) {
            runAsync("cancel run", () -> service.cancelRun(id));
        }
    }

    public void confirmTool(String toolCallId, boolean approved) {
        setState(ChatReducer.reduce(state, new ConfirmTool(toolCallId, approved)));
        String id = conversationId;
        if (id == null) {
            return;
        }
        runAsync("confirm tool", () -> service.confirmTool(id, approved));
        if (approved && !isStreaming()) {
            startWorker(new StreamWorker(id, null, callbacks.resolveContext(), lastEventId));
        }
    }

    public void newConversation() {
        stopCurrentWorker();
        conversationId = null;
        lastEventId = null;
        setState(ChatState.initial());
    }

    public void loadConversation(String conversationUuid) {
        stopCurrentWorker();
        workerExecutor.execute(() -> {
            try {
                ConversationReplay replay = service.getConversation(conversationUuid);
                ChatState loaded = ChatReducer.buildInitialState(replay.events());
                ChatState withTitle = new ChatState(loaded.items(), replay.title(),
                        loaded.runStatus(), loaded.runError());
                runOnUi(() -> {
                    conversationId = conversationUuid;
                    lastEventId = null;
                    setState(withTitle);
                });
            } catch (ChatServiceException e) {
                log.warn("Failed to load conversation: " + e.getMessage());
            }
        });
    }

    public void requestHistory() {
        workerExecutor.execute(() -> {
            try {
                var summaries = service.listConversations();
                runOnUi(() -> view.setHistory(summaries));
            } catch (ChatServiceException e) {
                log.warn("Failed to list conversations: " + e.getMessage());
            }
        });
    }

    public void dispose() {
        stopCurrentWorker();
    }

    private boolean isStreaming() {
        StreamWorker worker = currentWorker;
        return worker != null && !worker.stopped.get();
    }

    private void startWorker(StreamWorker worker) {
        stopCurrentWorker();
        currentWorker = worker;
        workerExecutor.execute(worker);
    }

    private void stopCurrentWorker() {
        StreamWorker worker = currentWorker;
        currentWorker = null;
        if (worker != null) {
            worker.stop();
        }
    }

    private void onStreamEvent(ChatEvent event) {
        setState(ChatReducer.reduce(state, new EventAction(event)));
        if (event.eventId() != null) {
            lastEventId = event.eventId();
        }
        if ("TOOL_CALL_RESULT".equals(event.type()) && !event.isError()) {
            handleToolResult(event);
        }
    }

    private void handleToolResult(ChatEvent event) {
        if (event.updated() == null) {
            return;
        }
        var functionIds = new ArrayList<Long>();
        for (var update : event.updated()) {
            if ("function".equals(update.type())) {
                functionIds.addAll(update.ids());
            }
        }
        if (!functionIds.isEmpty()) {
            callbacks.onFunctionsTouched(functionIds);
        }
    }

    private void runAsync(String action, NetworkCall call) {
        workerExecutor.execute(() -> {
            try {
                call.run();
            } catch (ChatServiceException e) {
                log.warn("Failed to %s: %s".formatted(action, e.getMessage()));
            }
        });
    }

    private void setState(ChatState newState) {
        state = newState;
        view.render(newState);
    }

    private void runOnUi(Runnable runnable) {
        uiExecutor.execute(runnable);
    }

    private static String newId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private interface NetworkCall {
        void run() throws ChatServiceException;
    }

    /// Runs one network turn (create → send → stream) off the UI thread, marshalling results back.
    private final class StreamWorker implements Runnable {
        private final String conversationId;
        private final String content;
        private final ConversationContext context;
        private final Long resumeFromEventId;
        private final AtomicBoolean stopped = new AtomicBoolean(false);

        StreamWorker(String conversationId, String content, ConversationContext context, Long resumeFromEventId) {
            this.conversationId = conversationId;
            this.content = content;
            this.context = context;
            this.resumeFromEventId = resumeFromEventId;
        }

        void stop() {
            stopped.set(true);
            service.closeActiveStream();
        }

        @Override
        public void run() {
            try {
                String id = conversationId;
                if (id == null) {
                    id = service.createConversation(context, null);
                    final String created = id;
                    runOnUi(() -> ChatController.this.conversationId = created);
                }
                if (stopped.get()) {
                    return;
                }
                if (content != null) {
                    service.sendMessage(id, content, context);
                }
                if (stopped.get()) {
                    return;
                }
                service.stream(id, resumeFromEventId, stopped::get,
                        event -> runOnUi(() -> onStreamEvent(event)));
            } catch (ChatServiceException e) {
                if (!stopped.get()) {
                    runOnUi(() -> setState(ChatReducer.reduce(state, new ApiError(e.getMessage()))));
                }
            } finally {
                runOnUi(() -> {
                    if (currentWorker == this) {
                        currentWorker = null;
                    }
                });
            }
        }
    }
}

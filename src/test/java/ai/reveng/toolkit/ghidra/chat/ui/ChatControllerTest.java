package ai.reveng.toolkit.ghidra.chat.ui;

import ai.reveng.toolkit.ghidra.chat.model.ChatEvent;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.AssistantMessage;
import ai.reveng.toolkit.ghidra.chat.model.ChatState;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationContext;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationReplay;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationSummary;
import ai.reveng.toolkit.ghidra.chat.service.ChatService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import org.junit.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link ChatController} orchestration, using a scripted fake {@link ChatService} and
 * synchronous executors so a {@code send} runs create → send → stream to completion inline.
 */
public class ChatControllerTest {

    private static final ReaiLoggingService NOOP_LOG = new ReaiLoggingService() {
        @Override public void info(String message) {}
        @Override public void warn(String message) {}
        @Override public void error(String message) {}
        @Override public void export(String targetDirectoryPath, String exportedFileName) {}
    };

    private static ChatEvent event(String type, Map<String, Object> data) {
        return ChatEvent.normalize(type, data, null);
    }

    /** Records calls and replays scripted event batches, one per {@code stream} invocation. */
    private static class FakeChatService implements ChatService {
        final Deque<List<ChatEvent>> scripts = new ArrayDeque<>();
        int createCount = 0;
        final List<String> sentMessages = new ArrayList<>();
        final List<Boolean> confirmations = new ArrayList<>();
        int cancelCount = 0;

        @Override
        public String createConversation(ConversationContext context, String title) {
            createCount++;
            return "conv-uuid";
        }

        @Override
        public void sendMessage(String conversationId, String content, ConversationContext context) {
            sentMessages.add(content);
        }

        @Override
        public void confirmTool(String conversationId, boolean approved) {
            confirmations.add(approved);
        }

        @Override
        public void cancelRun(String conversationId) {
            cancelCount++;
        }

        @Override
        public List<ConversationSummary> listConversations() {
            return List.of(new ConversationSummary("conv-uuid", "Prior chat", null));
        }

        @Override
        public ConversationReplay getConversation(String conversationId) {
            return new ConversationReplay(conversationId, "Prior chat", List.of());
        }

        @Override
        public void stream(String conversationId, Long lastEventId, BooleanSupplier isCancelled,
                           Consumer<ChatEvent> onEvent) {
            List<ChatEvent> script = scripts.isEmpty() ? List.of() : scripts.poll();
            for (ChatEvent event : script) {
                if (isCancelled.getAsBoolean()) {
                    return;
                }
                onEvent.accept(event);
            }
        }

        @Override
        public void closeActiveStream() {}
    }

    private static class RecordingView implements ChatView {
        ChatState lastState;
        List<ConversationSummary> history;

        @Override public void render(ChatState state) { lastState = state; }
        @Override public void setContextChip(String text) {}
        @Override public void setHistory(List<ConversationSummary> summaries) { history = summaries; }
    }

    private static class RecordingCallbacks implements ChatController.Callbacks {
        final List<Long> touched = new ArrayList<>();

        @Override public ConversationContext resolveContext() { return new ConversationContext(1L, null); }
        @Override public void onFunctionsTouched(List<Long> functionIds) { touched.addAll(functionIds); }
    }

    private ChatController controller(FakeChatService service, RecordingView view, RecordingCallbacks callbacks) {
        return new ChatController(service, view, NOOP_LOG, Runnable::run, Runnable::run, callbacks);
    }

    @Test
    public void sendCreatesConversationStreamsAndRenders() {
        var service = new FakeChatService();
        service.scripts.add(List.of(
                event("RUN_STARTED", Map.of()),
                event("TEXT_MESSAGE_START", Map.of("message_id", "m1")),
                event("TEXT_MESSAGE_CONTENT", Map.of("message_id", "m1", "delta", "Hello")),
                event("TEXT_MESSAGE_END", Map.of("message_id", "m1")),
                event("RUN_FINISHED", Map.of())));
        var view = new RecordingView();
        var controller = controller(service, view, new RecordingCallbacks());

        controller.send("hi");

        assertEquals(1, service.createCount);
        assertEquals(List.of("hi"), service.sentMessages);
        ChatState state = view.lastState;
        assertEquals("idle", state.runStatus());
        assertEquals(2, state.items().size());
        assertEquals("Hello", ((AssistantMessage) state.items().get(1)).content());
    }

    @Test
    public void secondSendReusesConversation() {
        var service = new FakeChatService();
        service.scripts.add(List.of(event("RUN_FINISHED", Map.of())));
        service.scripts.add(List.of(event("RUN_FINISHED", Map.of())));
        var controller = controller(service, new RecordingView(), new RecordingCallbacks());

        controller.send("first");
        controller.send("second");

        assertEquals(1, service.createCount);
        assertEquals(List.of("first", "second"), service.sentMessages);
    }

    @Test
    public void toolResultTriggersFunctionRefresh() {
        var service = new FakeChatService();
        Map<String, Object> update = Map.of("type", "function", "ids", List.of(7, 9));
        service.scripts.add(List.of(
                event("TOOL_CALL_START", Map.of("tool_call_id", "t1", "tool_name", "rename")),
                event("TOOL_CALL_RESULT", Map.of("tool_call_id", "t1", "is_error", false, "updated", List.of(update))),
                event("RUN_FINISHED", Map.of())));
        var callbacks = new RecordingCallbacks();
        var controller = controller(service, new RecordingView(), callbacks);

        controller.send("rename them");

        assertEquals(List.of(7L, 9L), callbacks.touched);
    }

    @Test
    public void approvingToolResumesStreamWithoutRecreatingConversation() {
        var service = new FakeChatService();
        service.scripts.add(List.of(
                event("RUN_STARTED", Map.of()),
                event("TOOL_CONFIRMATION_REQUIRED", Map.of("tool_call_id", "t1", "tool_name", "edit", "message", "ok?"))));
        service.scripts.add(List.of(
                event("TEXT_MESSAGE_START", Map.of("message_id", "m1")),
                event("TEXT_MESSAGE_CONTENT", Map.of("message_id", "m1", "delta", "done")),
                event("TEXT_MESSAGE_END", Map.of("message_id", "m1")),
                event("RUN_FINISHED", Map.of())));
        var view = new RecordingView();
        var controller = controller(service, view, new RecordingCallbacks());

        controller.send("edit please");
        controller.confirmTool("t1", true);

        assertEquals(1, service.createCount);
        assertEquals(List.of(Boolean.TRUE), service.confirmations);
        assertEquals("idle", view.lastState.runStatus());
        assertTrue(view.lastState.items().stream()
                .anyMatch(it -> it instanceof AssistantMessage m && m.content().equals("done")));
    }

    @Test
    public void stopFinalizesRunningItemsAndCancelsRun() {
        var service = new FakeChatService();
        // Stream leaves an assistant message mid-stream (no END, no terminal event).
        service.scripts.add(List.of(
                event("TEXT_MESSAGE_START", Map.of("message_id", "m1")),
                event("TEXT_MESSAGE_CONTENT", Map.of("message_id", "m1", "delta", "partial"))));
        var view = new RecordingView();
        var controller = controller(service, view, new RecordingCallbacks());

        controller.send("go");
        assertTrue(((AssistantMessage) view.lastState.items().get(1)).isStreaming());

        controller.stop();

        assertEquals("idle", view.lastState.runStatus());
        assertEquals(1, service.cancelCount);
        assertTrue(view.lastState.items().stream()
                .noneMatch(it -> it instanceof AssistantMessage m && m.isStreaming()));
    }

    @Test
    public void requestHistoryPopulatesView() {
        var service = new FakeChatService();
        var view = new RecordingView();
        var controller = controller(service, view, new RecordingCallbacks());

        controller.requestHistory();

        assertEquals(1, view.history.size());
        assertEquals("Prior chat", view.history.get(0).title());
    }

    @Test
    public void loadConversationSetsTitleAndState() {
        var service = new FakeChatService();
        var view = new RecordingView();
        var controller = controller(service, view, new RecordingCallbacks());

        controller.loadConversation("conv-uuid");

        assertEquals("Prior chat", view.lastState.title());
    }
}

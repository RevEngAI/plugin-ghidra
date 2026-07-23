package ai.reveng.toolkit.ghidra.chat.model;

import ai.reveng.toolkit.ghidra.chat.model.ChatItem.AssistantMessage;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.Step;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.ToolCall;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.ToolConfirmation;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.UserMessage;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer.ApiError;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer.Cancel;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer.ConfirmTool;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer.EventAction;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer.SendMessage;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.StoredEvent;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.UserMessageReplay;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** Unit tests for the pure {@link ChatReducer} state machine. */
public class ChatReducerTest {

    private static ChatEvent event(String type, Map<String, Object> data) {
        return ChatEvent.normalize(type, data, null);
    }

    @Test
    public void sendMessageAppendsUserItemAndRuns() {
        ChatState state = ChatReducer.reduce(ChatState.initial(), new SendMessage("u1", "hello"));
        assertEquals("running", state.runStatus());
        assertEquals(1, state.items().size());
        assertEquals(new UserMessage("u1", "hello"), state.items().get(0));
    }

    @Test
    public void assistantMessageStreamsContentThenStops() {
        ChatState state = ChatReducer.reduce(ChatState.initial(), new SendMessage("u1", "hi"));
        state = ChatReducer.reduce(state, new EventAction(event("TEXT_MESSAGE_START", Map.of("message_id", "m1"))));
        state = ChatReducer.reduce(state, new EventAction(event("TEXT_MESSAGE_CONTENT", Map.of("message_id", "m1", "delta", "Hel"))));
        state = ChatReducer.reduce(state, new EventAction(event("TEXT_MESSAGE_CONTENT", Map.of("message_id", "m1", "delta", "lo"))));

        AssistantMessage streaming = (AssistantMessage) state.items().get(1);
        assertEquals("Hello", streaming.content());
        assertTrue(streaming.isStreaming());

        state = ChatReducer.reduce(state, new EventAction(event("TEXT_MESSAGE_END", Map.of("message_id", "m1"))));
        assertFalse(((AssistantMessage) state.items().get(1)).isStreaming());
    }

    @Test
    public void duplicateTextMessageStartIsIgnored() {
        ChatState state = ChatReducer.reduce(ChatState.initial(),
                new EventAction(event("TEXT_MESSAGE_START", Map.of("message_id", "m1"))));
        state = ChatReducer.reduce(state, new EventAction(event("TEXT_MESSAGE_START", Map.of("message_id", "m1"))));
        assertEquals(1, state.items().size());
    }

    @Test
    public void toolCallLifecycleFinishesAndCarriesFunctions() {
        ChatState state = ChatReducer.reduce(ChatState.initial(),
                new EventAction(event("TOOL_CALL_START", Map.of("tool_call_id", "t1", "tool_name", "rename_function"))));
        assertEquals("running", ((ToolCall) state.items().get(0)).status());

        Map<String, Object> ref = Map.of("id", 7, "name", "main", "vaddr", 0x4000);
        Map<String, Object> update = Map.of("type", "function", "ids", List.of(7), "refs", List.of(ref));
        state = ChatReducer.reduce(state, new EventAction(
                event("TOOL_CALL_RESULT", Map.of("tool_call_id", "t1", "is_error", false, "updated", List.of(update)))));

        ToolCall call = (ToolCall) state.items().get(0);
        assertEquals("finished", call.status());
        assertFalse(call.isError());
        assertEquals(1, call.functions().size());
        assertEquals("main", call.functions().get(0).name());
        assertEquals(0x4000, call.functions().get(0).address());
    }

    @Test
    public void toolConfirmationApprovalUpdatesStatusAndResumesRun() {
        ChatState state = ChatReducer.reduce(ChatState.initial(), new EventAction(
                event("TOOL_CONFIRMATION_REQUIRED", Map.of("tool_call_id", "t1", "tool_name", "edit", "message", "ok?"))));
        assertEquals("pending", ((ToolConfirmation) state.items().get(0)).status());

        state = ChatReducer.reduce(state, new ConfirmTool("t1", true));
        assertEquals("approved", ((ToolConfirmation) state.items().get(0)).status());
        assertEquals("running", state.runStatus());
    }

    @Test
    public void cancelFinalizesRunningItems() {
        ChatState state = ChatReducer.reduce(ChatState.initial(),
                new EventAction(event("STEP_STARTED", Map.of())));
        state = ChatReducer.reduce(state,
                new EventAction(event("TOOL_CALL_START", Map.of("tool_call_id", "t1", "tool_name", "x"))));
        state = ChatReducer.reduce(state, new Cancel());

        assertEquals("idle", state.runStatus());
        assertEquals("finished", ((Step) state.items().get(0)).status());
        assertEquals("finished", ((ToolCall) state.items().get(1)).status());
    }

    @Test
    public void runErrorSetsErrorStateWithMessage() {
        ChatState state = ChatReducer.reduce(ChatState.initial(),
                new EventAction(event("RUN_ERROR", Map.of("error", "boom"))));
        assertEquals("error", state.runStatus());
        assertEquals("boom", state.runError().message());
    }

    @Test
    public void apiErrorFinalizesAndRecordsError() {
        ChatState state = ChatReducer.reduce(ChatState.initial(),
                new EventAction(event("TEXT_MESSAGE_START", Map.of("message_id", "m1"))));
        state = ChatReducer.reduce(state, new ApiError("network down"));
        assertEquals("error", state.runStatus());
        assertEquals("network down", state.runError().message());
        assertFalse(((AssistantMessage) state.items().get(0)).isStreaming());
    }

    @Test
    public void titleUpdatedSetsTitle() {
        ChatState state = ChatReducer.reduce(ChatState.initial(),
                new EventAction(event("TITLE_UPDATED", Map.of("title", "My chat"))));
        assertEquals("My chat", state.title());
    }

    @Test
    public void buildInitialStateReplaysUserAndAssistantTurns() {
        var stored = List.of(
                StoredEvent.of(new UserMessageReplay("u1", "hello")),
                StoredEvent.of(event("TEXT_MESSAGE_START", Map.of("message_id", "m1"))),
                StoredEvent.of(event("TEXT_MESSAGE_CONTENT", Map.of("message_id", "m1", "delta", "hi there"))),
                StoredEvent.of(event("TEXT_MESSAGE_END", Map.of("message_id", "m1"))),
                StoredEvent.of(event("RUN_FINISHED", Map.of())));

        ChatState state = ChatReducer.buildInitialState(stored);
        assertEquals(2, state.items().size());
        assertEquals(new UserMessage("u1", "hello"), state.items().get(0));
        assertEquals("hi there", ((AssistantMessage) state.items().get(1)).content());
        assertEquals("idle", state.runStatus());
    }
}

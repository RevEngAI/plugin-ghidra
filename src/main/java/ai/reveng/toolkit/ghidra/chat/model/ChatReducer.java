package ai.reveng.toolkit.ghidra.chat.model;

import ai.reveng.toolkit.ghidra.chat.model.ChatItem.AssistantMessage;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.ContextCompacted;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.FunctionRef;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.Step;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.ToolCall;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.ToolConfirmation;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.UserMessage;
import ai.reveng.toolkit.ghidra.chat.model.ChatState.RunError;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.StoredEvent;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Pure reducer state machine for the Agent Chat feature. Direct port of the IDA plugin's
 * {@code services/chat/reducer.py} (itself a port of the Dashboard's {@code reducer.ts}). Operates
 * only on {@link ChatState}/{@link ChatEvent} — no Ghidra/SDK imports — so it is unit-testable.
 */
public final class ChatReducer {

    private ChatReducer() {}

    /// An action driving a chat state transition. Java analogue of Python's {@code ChatAction} union.
    public sealed interface ChatAction
            permits SendMessage, Cancel, ConfirmTool, EventAction, ApiError, Reset {}

    public record SendMessage(String id, String content) implements ChatAction {}

    public record Cancel() implements ChatAction {}

    public record ConfirmTool(String id, boolean approved) implements ChatAction {}

    public record EventAction(ChatEvent event) implements ChatAction {}

    public record ApiError(String message, String code, String docUrl) implements ChatAction {
        public ApiError(String message) {
            this(message, null, null);
        }
    }

    public record Reset(List<StoredEvent> storedEvents) implements ChatAction {}

    public static ChatState reduce(ChatState state, ChatAction action) {
        return switch (action) {
            case SendMessage a -> withItems(
                    append(state.items(), new UserMessage(a.id(), a.content())),
                    state.title(), "running", null);
            case Reset a -> buildInitialState(a.storedEvents());
            case Cancel ignored -> new ChatState(
                    finalizeRunningItems(state.items()), state.title(), "idle", state.runError());
            case ConfirmTool a -> new ChatState(
                    findLastAndUpdate(state.items(),
                            it -> it instanceof ToolConfirmation c && c.id().equals(a.id()),
                            it -> withStatus((ToolConfirmation) it, a.approved() ? "approved" : "rejected")),
                    state.title(),
                    a.approved() ? "running" : state.runStatus(),
                    state.runError());
            case ApiError a -> new ChatState(
                    finalizeRunningItems(state.items()), state.title(), "error",
                    new RunError(a.message(), a.code(), a.docUrl()));
            case EventAction a -> reduceEvent(state, a.event());
        };
    }

    private static ChatState reduceEvent(ChatState state, ChatEvent event) {
        return switch (event.type()) {
            case "RUN_STARTED" -> new ChatState(state.items(), state.title(), "running", null);
            case "RUN_FINISHED" -> new ChatState(state.items(), state.title(), "idle", state.runError());
            case "RUN_ERROR" -> new ChatState(
                    finalizeRunningItems(state.items()), state.title(), "error",
                    new RunError(event.message() != null ? event.message() : "Unknown error", null, null));
            case "STEP_STARTED" -> withItems(
                    append(state.items(), new Step(newId(), "Processing", "running")),
                    state.title(), state.runStatus(), state.runError());
            case "STEP_FINISHED" -> replaceItems(state, findLastAndUpdate(state.items(),
                    it -> it instanceof Step s && s.status().equals("running"),
                    it -> withStatus((Step) it, "finished")));
            case "TEXT_MESSAGE_START" -> reduceTextMessageStart(state, event);
            case "TEXT_MESSAGE_CONTENT" -> replaceItems(state, findLastAndUpdate(state.items(),
                    it -> it instanceof AssistantMessage m && m.id().equals(event.messageId()),
                    it -> appendContent((AssistantMessage) it, event.delta())));
            case "TEXT_MESSAGE_END" -> replaceItems(state, findLastAndUpdate(state.items(),
                    it -> it instanceof AssistantMessage m && m.id().equals(event.messageId()),
                    it -> stopStreaming((AssistantMessage) it)));
            case "TOOL_CALL_START" -> withItems(
                    append(state.items(), new ToolCall(
                            event.toolCallId() != null ? event.toolCallId() : newId(),
                            event.toolName() != null ? event.toolName() : "", "running", false, null)),
                    state.title(), state.runStatus(), state.runError());
            case "TOOL_CALL_END" -> replaceItems(state, findLastAndUpdate(state.items(),
                    it -> it instanceof ToolCall c && c.id().equals(event.toolCallId()),
                    it -> withStatus((ToolCall) it, "finished")));
            case "TOOL_CALL_RESULT" -> reduceToolCallResult(state, event);
            case "TITLE_UPDATED" -> new ChatState(state.items(), event.title(), state.runStatus(), state.runError());
            case "RUN_CANCELLED" -> new ChatState(
                    finalizeRunningItems(state.items()), state.title(), "idle", state.runError());
            case "CONTEXT_COMPACTED" -> withItems(
                    append(state.items(), new ContextCompacted(newId())),
                    state.title(), state.runStatus(), state.runError());
            case "TOOL_CONFIRMATION_REQUIRED" -> withItems(
                    append(state.items(), new ToolConfirmation(
                            event.toolCallId() != null ? event.toolCallId() : newId(),
                            event.toolName() != null ? event.toolName() : "",
                            event.message() != null ? event.message() : "", "pending")),
                    state.title(), state.runStatus(), state.runError());
            default -> state;
        };
    }

    private static ChatState reduceTextMessageStart(ChatState state, ChatEvent event) {
        boolean exists = state.items().stream()
                .anyMatch(it -> it instanceof AssistantMessage m && m.id().equals(event.messageId()));
        if (exists) {
            return state;
        }
        return withItems(
                append(state.items(), new AssistantMessage(
                        event.messageId() != null ? event.messageId() : newId(), "", true)),
                state.title(), state.runStatus(), state.runError());
    }

    private static ChatState reduceToolCallResult(ChatState state, ChatEvent event) {
        List<FunctionRef> functions = functionsFromUpdates(event.updated());
        var items = findLastAndUpdate(state.items(),
                it -> it instanceof ToolCall c && c.id().equals(event.toolCallId()),
                it -> {
                    ToolCall c = (ToolCall) it;
                    return new ToolCall(c.id(), c.name(), "finished", event.isError(),
                            functions != null ? functions : c.functions());
                });
        items = findLastAndUpdate(items,
                it -> it instanceof ToolConfirmation c
                        && c.id().equals(event.toolCallId()) && c.status().equals("pending"),
                it -> withStatus((ToolConfirmation) it, event.isError() ? "rejected" : "approved"));
        return replaceItems(state, items);
    }

    private static List<FunctionRef> functionsFromUpdates(List<ChatEvent.EntityUpdate> updates) {
        if (updates == null) {
            return null;
        }
        var out = new ArrayList<FunctionRef>();
        for (var update : updates) {
            if (!"function".equals(update.type())) {
                continue;
            }
            for (var ref : update.refs()) {
                if (ref.name() != null && !ref.name().isEmpty() && ref.vaddr() != 0) {
                    out.add(new FunctionRef(ref.vaddr(), ref.name()));
                }
            }
        }
        return out.isEmpty() ? null : out;
    }

    /**
     * Replay stored/normalized events into a {@link ChatState} (history reload). Mirrors
     * {@code build_initial_state}: a {@code UserMessageReplay} drives a SendMessage action,
     * everything else an EventAction.
     */
    public static ChatState buildInitialState(List<StoredEvent> storedEvents) {
        ChatState state = ChatState.initial();
        if (storedEvents == null) {
            return state;
        }
        for (var stored : storedEvents) {
            if (stored.userMessage() != null) {
                state = reduce(state, new SendMessage(stored.userMessage().id(), stored.userMessage().content()));
            } else if (stored.event() != null) {
                state = reduce(state, new EventAction(stored.event()));
            }
        }
        return state;
    }

    // --- helpers -----------------------------------------------------------------------------

    private static List<ChatItem> finalizeRunningItems(List<ChatItem> items) {
        var out = new ArrayList<ChatItem>(items.size());
        for (var item : items) {
            if (item instanceof AssistantMessage m && m.isStreaming()) {
                out.add(stopStreaming(m));
            } else if (item instanceof ToolCall c && c.status().equals("running")) {
                out.add(withStatus(c, "finished"));
            } else if (item instanceof Step s && s.status().equals("running")) {
                out.add(withStatus(s, "finished"));
            } else if (item instanceof ToolConfirmation c && c.status().equals("pending")) {
                out.add(withStatus(c, "rejected"));
            } else {
                out.add(item);
            }
        }
        return List.copyOf(out);
    }

    /// Update the last item matching {@code guard}; returns the same list unchanged if none match.
    private static List<ChatItem> findLastAndUpdate(List<ChatItem> items,
                                                    Predicate<ChatItem> guard,
                                                    Function<ChatItem, ChatItem> update) {
        for (int idx = items.size() - 1; idx >= 0; idx--) {
            if (guard.test(items.get(idx))) {
                var next = new ArrayList<>(items);
                next.set(idx, update.apply(items.get(idx)));
                return List.copyOf(next);
            }
        }
        return items;
    }

    private static List<ChatItem> append(List<ChatItem> items, ChatItem item) {
        var next = new ArrayList<>(items);
        next.add(item);
        return List.copyOf(next);
    }

    private static ChatState withItems(List<ChatItem> items, String title, String runStatus, RunError error) {
        return new ChatState(items, title, runStatus, error);
    }

    private static ChatState replaceItems(ChatState state, List<ChatItem> items) {
        return new ChatState(items, state.title(), state.runStatus(), state.runError());
    }

    private static AssistantMessage appendContent(AssistantMessage m, String delta) {
        return new AssistantMessage(m.id(), m.content() + (delta != null ? delta : ""), m.isStreaming());
    }

    private static AssistantMessage stopStreaming(AssistantMessage m) {
        return new AssistantMessage(m.id(), m.content(), false);
    }

    private static ToolCall withStatus(ToolCall c, String status) {
        return new ToolCall(c.id(), c.name(), status, c.isError(), c.functions());
    }

    private static Step withStatus(Step s, String status) {
        return new Step(s.id(), s.stepName(), status);
    }

    private static ToolConfirmation withStatus(ToolConfirmation c, String status) {
        return new ToolConfirmation(c.id(), c.toolName(), c.message(), status);
    }

    private static String newId() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}

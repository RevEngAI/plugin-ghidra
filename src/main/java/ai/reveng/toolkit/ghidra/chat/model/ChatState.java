package ai.reveng.toolkit.ghidra.chat.model;

import java.util.List;

/**
 * Immutable UI state for the Agent Chat panel. Port of {@code ChatState} from the IDA plugin's
 * {@code services/chat/schema.py}. Produced by {@link ChatReducer}; consumed by the renderer.
 *
 * <p>{@code runStatus} is one of {@code "idle"}, {@code "running"}, {@code "error"}.
 */
public record ChatState(List<ChatItem> items, String title, String runStatus, RunError runError) {

    public record RunError(String message, String code, String docUrl) {}

    public static ChatState initial() {
        return new ChatState(List.of(), null, "idle", null);
    }
}

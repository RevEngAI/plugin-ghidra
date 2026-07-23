package ai.reveng.toolkit.ghidra.chat.model;

import java.util.List;

/**
 * A single item in the rendered chat transcript. Port of the discriminated union in the IDA
 * plugin's {@code services/chat/schema.py}; the pure {@link ChatReducer} produces these from the
 * agent event stream and the renderer turns them into a transcript.
 */
public sealed interface ChatItem
        permits ChatItem.UserMessage, ChatItem.AssistantMessage, ChatItem.ToolCall,
        ChatItem.Step, ChatItem.ToolConfirmation, ChatItem.ContextCompacted {

    String id();

    record UserMessage(String id, String content) implements ChatItem {}

    record AssistantMessage(String id, String content, boolean isStreaming) implements ChatItem {}

    /// A function the agent touched, resolved to a local address for navigation.
    record FunctionRef(long address, String name) {}

    record ToolCall(String id, String name, String status, boolean isError,
                    List<FunctionRef> functions) implements ChatItem {}

    record Step(String id, String stepName, String status) implements ChatItem {}

    record ToolConfirmation(String id, String toolName, String message, String status) implements ChatItem {}

    record ContextCompacted(String id) implements ChatItem {}
}

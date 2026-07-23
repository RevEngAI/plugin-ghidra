package ai.reveng.toolkit.ghidra.chat.model;

import java.util.List;

/**
 * Plain, SDK-free conversation DTOs exchanged between the chat service and the controller. Port of
 * the conversation dataclasses in the IDA plugin's {@code services/chat/schema.py}.
 */
public final class Conversations {

    private Conversations() {}

    /// Context (analysis + focused function) attached to a conversation or message.
    public record ConversationContext(Long analysisId, Long functionId) {
        public boolean isEmpty() {
            return analysisId == null && functionId == null;
        }
    }

    /// Lightweight conversation row for the history browser.
    public record ConversationSummary(String conversationUuid, String title, String updatedAt) {}

    /// Reconstructed user message emitted only during history replay.
    public record UserMessageReplay(String id, String content) {}

    /**
     * A stored event during history replay: either a normalized {@link ChatEvent} or a
     * reconstructed {@link UserMessageReplay}. Modelled as a two-field holder (exactly one set)
     * because Java records can't express Python's {@code Union}.
     */
    public record StoredEvent(ChatEvent event, UserMessageReplay userMessage) {
        public static StoredEvent of(ChatEvent event) {
            return new StoredEvent(event, null);
        }

        public static StoredEvent of(UserMessageReplay userMessage) {
            return new StoredEvent(null, userMessage);
        }
    }

    /// A full conversation reloaded from history, normalized for the reducer.
    public record ConversationReplay(String conversationUuid, String title, List<StoredEvent> events) {}
}

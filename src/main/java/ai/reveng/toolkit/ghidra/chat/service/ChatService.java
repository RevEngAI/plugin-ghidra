package ai.reveng.toolkit.ghidra.chat.service;

import ai.reveng.toolkit.ghidra.chat.model.ChatEvent;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationContext;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationReplay;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationSummary;

import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * The network lifecycle of the Agent Chat feature: create / send / stream / confirm / cancel / list
 * / get, wrapping the RevEng.AI conversations endpoints. Mirrors the IDA plugin's {@code ChatService}.
 *
 * <p>An interface so the controller can be driven by a fake in tests without a live backend.
 */
public interface ChatService {

    /// Create a new conversation and return its uuid.
    String createConversation(ConversationContext context, String title) throws ChatServiceException;

    /// Post a user message to an existing conversation, kicking off an agent run.
    void sendMessage(String conversationId, String content, ConversationContext context) throws ChatServiceException;

    /// Approve or reject a tool the agent asked to run.
    void confirmTool(String conversationId, boolean approved) throws ChatServiceException;

    /// Cancel the in-progress run for a conversation.
    void cancelRun(String conversationId) throws ChatServiceException;

    /// List the user's conversations for the history browser.
    List<ConversationSummary> listConversations() throws ChatServiceException;

    /// Load a full conversation for history replay.
    ConversationReplay getConversation(String conversationId) throws ChatServiceException;

    /**
     * Stream normalized events from the live SSE endpoint, invoking {@code onEvent} per event on the
     * calling thread until a terminal event, {@code isCancelled} turning true, or the stream closing.
     */
    void stream(String conversationId, Long lastEventId, BooleanSupplier isCancelled,
                Consumer<ChatEvent> onEvent) throws ChatServiceException;

    /// Interrupt a blocked {@link #stream} read from another thread (for cancellation).
    void closeActiveStream();
}

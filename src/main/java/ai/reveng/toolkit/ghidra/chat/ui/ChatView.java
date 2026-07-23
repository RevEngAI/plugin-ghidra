package ai.reveng.toolkit.ghidra.chat.ui;

import ai.reveng.toolkit.ghidra.chat.model.ChatState;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationSummary;

import java.util.List;

/**
 * The view surface the {@link ChatController} drives. Kept minimal and Swing-free so the controller
 * can be unit-tested with a fake view. All methods are invoked on the UI executor.
 */
public interface ChatView {
    void render(ChatState state);

    void setContextChip(String text);

    void setHistory(List<ConversationSummary> summaries);
}

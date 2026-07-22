package ai.reveng.toolkit.ghidra.chat.model;

import ai.reveng.toolkit.ghidra.chat.model.ChatItem.ToolConfirmation;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer.EventAction;
import ai.reveng.toolkit.ghidra.chat.model.ChatReducer.SendMessage;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/** Unit tests for the pure {@link ChatTranscriptRenderer}. */
public class ChatTranscriptRendererTest {

    @Test
    public void jumpHrefRoundTrips() {
        String href = ChatTranscriptRenderer.jumpHref(0x401000L);
        assertEquals(Long.valueOf(0x401000L), ChatTranscriptRenderer.parseJumpHref(href));
        assertNull(ChatTranscriptRenderer.parseJumpHref("http://example.com"));
    }

    @Test
    public void titleCaseHumanizesToolNames() {
        assertEquals("Rename Function", ChatTranscriptRenderer.titleCase("rename_function"));
        assertEquals("tool", ChatTranscriptRenderer.titleCase(""));
    }

    @Test
    public void rendersUserAndEscapesHtml() {
        ChatState state = ChatReducer.reduce(ChatState.initial(), new SendMessage("u1", "a < b & c"));
        String html = ChatTranscriptRenderer.renderTranscriptHtml(state);
        assertTrue(html.contains("<b>You:</b>"));
        assertTrue(html.contains("a &lt; b &amp; c"));
    }

    @Test
    public void rendersThinkingWhileAwaitingFirstReply() {
        ChatState state = ChatReducer.reduce(ChatState.initial(), new SendMessage("u1", "hi"));
        assertTrue(ChatTranscriptRenderer.renderTranscriptHtml(state).contains("Thinking"));
    }

    @Test
    public void findsPendingConfirmation() {
        ChatState state = ChatReducer.reduce(ChatState.initial(), new EventAction(
                ChatEvent.normalize("TOOL_CONFIRMATION_REQUIRED",
                        Map.of("tool_call_id", "t1", "tool_name", "edit", "message", "ok?"), null)));
        ToolConfirmation pending = ChatTranscriptRenderer.findPendingConfirmation(state);
        assertEquals("t1", pending.id());
    }
}

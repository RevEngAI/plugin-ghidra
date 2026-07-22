package ai.reveng.toolkit.ghidra.chat.model;

import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/** Unit tests for {@link ChatEvent#resolveType} and {@link ChatEvent#normalize}. */
public class ChatEventNormalizationTest {

    @Test
    public void resolveTypeHandlesIntegerAndStringForms() {
        assertEquals("TEXT_MESSAGE_CONTENT", ChatEvent.resolveType(7));
        assertEquals("TOOL_CALL_RESULT", ChatEvent.resolveType(12));
        assertEquals("RUN_STARTED", ChatEvent.resolveType("RUN_STARTED"));
        assertNull(ChatEvent.resolveType(999));
        assertNull(ChatEvent.resolveType(""));
        assertNull(ChatEvent.resolveType(null));
    }

    @Test
    public void normalizeReturnsNullForUnknownType() {
        assertNull(ChatEvent.normalize(999, Map.of(), null));
    }

    @Test
    public void textMessageStartRoleIsAssistant() {
        ChatEvent ev = ChatEvent.normalize("TEXT_MESSAGE_START", Map.of("message_id", "m1"), 5L);
        assertEquals("assistant", ev.role());
        assertEquals("m1", ev.messageId());
        assertEquals(Long.valueOf(5L), ev.eventId());
    }

    @Test
    public void runErrorDefaultsMessageWhenAbsent() {
        ChatEvent ev = ChatEvent.normalize("RUN_ERROR", Map.of(), null);
        assertEquals("Unknown error", ev.message());
    }

    @Test
    public void errorKeyIsUsedAsMessageFallback() {
        ChatEvent ev = ChatEvent.normalize("RUN_ERROR", Map.of("error", "kaboom"), null);
        assertEquals("kaboom", ev.message());
    }

    @Test
    public void entityUpdatesAndRefsAreParsed() {
        Map<String, Object> ref = Map.of("id", 7, "name", "main", "vaddr", 0x4000);
        Map<String, Object> update = Map.of("type", "function", "ids", List.of(7, 8), "refs", List.of(ref));
        ChatEvent ev = ChatEvent.normalize("TOOL_CALL_RESULT",
                Map.of("tool_call_id", "t1", "updated", List.of(update)), null);

        assertEquals(1, ev.updated().size());
        var parsed = ev.updated().get(0);
        assertEquals("function", parsed.type());
        assertEquals(List.of(7L, 8L), parsed.ids());
        assertEquals("main", parsed.refs().get(0).name());
        assertEquals(0x4000L, parsed.refs().get(0).vaddr());
    }

    @Test
    public void unknownEntityUpdateTypesAreDropped() {
        Map<String, Object> update = Map.of("type", "widget", "ids", List.of(1));
        ChatEvent ev = ChatEvent.normalize("TOOL_CALL_RESULT",
                Map.of("tool_call_id", "t1", "updated", List.of(update)), null);
        assertNull(ev.updated());
    }

    @Test
    public void isErrorFlagIsCoercedToBoolean() {
        assertTrue(ChatEvent.normalize("TOOL_CALL_RESULT", Map.of("is_error", true), null).isError());
        assertEquals(false, ChatEvent.normalize("TOOL_CALL_RESULT", Map.of(), null).isError());
    }
}

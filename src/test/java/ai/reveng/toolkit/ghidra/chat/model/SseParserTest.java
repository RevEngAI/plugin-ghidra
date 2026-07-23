package ai.reveng.toolkit.ghidra.chat.model;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/** Unit tests for the pure {@link SseParser}. */
public class SseParserTest {

    private static List<ChatEvent> parse(String stream) throws Exception {
        var events = new ArrayList<ChatEvent>();
        SseParser.parse(new BufferedReader(new StringReader(stream)), () -> false, events::add);
        return events;
    }

    @Test
    public void ignoresNonDataAndSentinelLines() {
        assertNull(SseParser.parseDataLine(": comment"));
        assertNull(SseParser.parseDataLine("event: ping"));
        assertNull(SseParser.parseDataLine("data: [DONE]"));
        assertNull(SseParser.parseDataLine("data:   "));
        assertNull(SseParser.parseDataLine("data: not-json"));
    }

    @Test
    public void parsesFramesAndStopsAtTerminalEvent() throws Exception {
        String stream = String.join("\n",
                "data: {\"type\": 6, \"event_id\": 1, \"data\": {\"message_id\": \"m1\"}}",
                "data: {\"type\": 7, \"event_id\": 2, \"data\": {\"message_id\": \"m1\", \"delta\": \"hi\"}}",
                "data: {\"type\": 2, \"event_id\": 3, \"data\": {}}",
                "data: {\"type\": 7, \"event_id\": 4, \"data\": {\"message_id\": \"m1\", \"delta\": \"ignored\"}}",
                "");
        List<ChatEvent> events = parse(stream);

        assertEquals(3, events.size());
        assertEquals("TEXT_MESSAGE_START", events.get(0).type());
        assertEquals(Long.valueOf(1L), events.get(0).eventId());
        assertEquals("hi", events.get(1).delta());
        assertEquals("RUN_FINISHED", events.get(2).type());
    }

    @Test
    public void cooperativeCancellationStopsIteration() throws Exception {
        String stream = String.join("\n",
                "data: {\"type\": 6, \"event_id\": 1, \"data\": {\"message_id\": \"m1\"}}",
                "data: {\"type\": 7, \"event_id\": 2, \"data\": {\"message_id\": \"m1\", \"delta\": \"hi\"}}",
                "");
        var events = new ArrayList<ChatEvent>();
        SseParser.parse(new BufferedReader(new StringReader(stream)), () -> true, events::add);
        assertTrue(events.isEmpty());
    }

    @Test
    public void malformedFramesAreSkipped() throws Exception {
        String stream = String.join("\n",
                "data: {bad json",
                "data: {\"type\": 1, \"event_id\": 1, \"data\": {}}",
                "");
        List<ChatEvent> events = parse(stream);
        assertEquals(1, events.size());
        assertEquals("RUN_STARTED", events.get(0).type());
    }
}

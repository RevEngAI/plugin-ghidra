package ai.reveng.toolkit.ghidra.chat.model;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Pure Server-Sent-Events frame parsing for the Agent Chat stream. Port of the IDA plugin's
 * {@code services/chat/sse.py}: line-based framing, only {@code data:} frames, {@code [DONE]}
 * handling, and stopping on a terminal event. No Ghidra/SDK imports, so it is unit-testable against
 * a plain {@link java.io.StringReader}.
 */
public final class SseParser {

    private SseParser() {}

    private static final Gson GSON = new Gson();

    /**
     * Read SSE frames from {@code reader}, emitting a normalized {@link ChatEvent} per decodable
     * {@code data:} frame. {@code stop} is polled between lines for cooperative cancellation;
     * iteration ends after a terminal event (RUN_FINISHED / RUN_ERROR / RUN_CANCELLED), when
     * {@code stop} returns true, or at end of stream.
     */
    public static void parse(BufferedReader reader, BooleanSupplier stop, Consumer<ChatEvent> sink)
            throws IOException {
        String line;
        while ((line = reader.readLine()) != null) {
            if (stop.getAsBoolean()) {
                return;
            }
            Map<String, Object> frame = parseDataLine(line);
            if (frame == null) {
                continue;
            }
            ChatEvent event = eventFromFrame(frame);
            if (event == null) {
                continue;
            }
            sink.accept(event);
            if (ChatEvent.TERMINAL_EVENTS.contains(event.type())) {
                return;
            }
        }
    }

    /**
     * Decode a single SSE line into its JSON object, or {@code null}. Only {@code data:} lines carry
     * payloads; {@code event:} / {@code id:} / comment lines and the {@code [DONE]} sentinel are ignored.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseDataLine(String line) {
        String trimmed = line.strip();
        if (!trimmed.startsWith("data:")) {
            return null;
        }
        String payload = trimmed.substring("data:".length()).strip();
        if (payload.isEmpty() || payload.equals("[DONE]")) {
            return null;
        }
        try {
            Object obj = GSON.fromJson(payload, Map.class);
            return obj instanceof Map ? (Map<String, Object>) obj : null;
        } catch (JsonSyntaxException e) {
            return null;
        }
    }

    /// Turn a decoded {@code {type, event_id, data}} envelope into a normalized {@link ChatEvent}.
    @SuppressWarnings("unchecked")
    public static ChatEvent eventFromFrame(Map<String, Object> frame) {
        Object leaf = frame.get("data");
        Map<String, Object> data = leaf instanceof Map ? (Map<String, Object>) leaf : null;
        Long eventId = frame.get("event_id") instanceof Number n ? n.longValue() : null;
        return ChatEvent.normalize(frame.get("type"), data, eventId);
    }
}

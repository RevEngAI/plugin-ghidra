package ai.reveng.toolkit.ghidra.chat.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A normalized agent event. Fields are a flattened superset of every event type; only the fields
 * relevant to {@link #type} are populated. Port of {@code ChatEvent} + {@code normalize_event} from
 * the IDA plugin's {@code services/chat/schema.py}, which in turn mirrors the Dashboard's
 * {@code parseApiEvent}. Kept free of Ghidra/SDK imports so it is unit-testable in isolation.
 */
public record ChatEvent(
        String type,
        String messageId,
        String delta,
        String toolCallId,
        String toolName,
        String result,
        boolean isError,
        List<EntityUpdate> updated,
        String message,
        String title,
        String toolArgs,
        String role,
        Long eventId) {

    /// A backend entity a tool result reports as changed. Drives the view refresh.
    public record EntityUpdate(String type, List<Long> ids, List<EntityRef> refs) {}

    public record EntityRef(long id, String name, long vaddr) {}

    private static final Map<Integer, String> EVENT_TYPE_NAMES = Map.ofEntries(
            Map.entry(1, "RUN_STARTED"),
            Map.entry(2, "RUN_FINISHED"),
            Map.entry(3, "RUN_ERROR"),
            Map.entry(4, "STEP_STARTED"),
            Map.entry(5, "STEP_FINISHED"),
            Map.entry(6, "TEXT_MESSAGE_START"),
            Map.entry(7, "TEXT_MESSAGE_CONTENT"),
            Map.entry(8, "TEXT_MESSAGE_END"),
            Map.entry(9, "TOOL_CALL_START"),
            Map.entry(10, "TOOL_CALL_ARGS_DELTA"),
            Map.entry(11, "TOOL_CALL_END"),
            Map.entry(12, "TOOL_CALL_RESULT"),
            Map.entry(13, "TITLE_UPDATED"),
            Map.entry(14, "RUN_CANCELLED"),
            Map.entry(15, "CONTEXT_COMPACTED"),
            Map.entry(16, "TOOL_CONFIRMATION_REQUIRED"),
            Map.entry(17, "TOOL_CALL_PROGRESS"));

    public static final Set<String> TERMINAL_EVENTS = Set.of("RUN_FINISHED", "RUN_ERROR", "RUN_CANCELLED");

    public static final int ROLE_USER = 2;
    public static final int ROLE_SYSTEM = 3;
    public static final int ROLE_TOOL = 4;

    /// Resolve a wire {@code type} (string name or integer 1..17) to its canonical name.
    public static String resolveType(Object typeField) {
        if (typeField instanceof String s) {
            return s.isEmpty() ? null : s;
        }
        if (typeField instanceof Number n) {
            return EVENT_TYPE_NAMES.get(n.intValue());
        }
        return null;
    }

    /**
     * Normalize a raw SSE {@code {type, data}} frame into a {@link ChatEvent}. {@code leaf} is the
     * nested {@code data} object holding snake_case leaf fields. Returns {@code null} for
     * unknown/undecodable event types (mirrors the FE's {@code parseApiEvent} returning null).
     */
    public static ChatEvent normalize(Object typeField, Map<String, Object> leaf, Long eventId) {
        String etype = resolveType(typeField);
        if (etype == null) {
            return null;
        }
        Map<String, Object> data = leaf != null ? leaf : Map.of();

        String message = str(data.get("message"));
        if (message == null) {
            message = str(data.get("error"));
        }
        if (etype.equals("RUN_ERROR") && (message == null || message.isEmpty())) {
            message = "Unknown error";
        }

        String role;
        if (etype.equals("TEXT_MESSAGE_START")) {
            role = "assistant";
        } else {
            role = str(data.get("role"));
        }

        return new ChatEvent(
                etype,
                str(data.get("message_id")),
                str(data.get("delta")),
                str(data.get("tool_call_id")),
                str(data.get("tool_name")),
                str(data.get("result")),
                bool(data.get("is_error")),
                parseEntityUpdates(data.get("updated")),
                message,
                str(data.get("title")),
                strOrEmpty(data.get("tool_args")),
                role,
                eventId);
    }

    private static List<EntityUpdate> parseEntityUpdates(Object raw) {
        if (!(raw instanceof List<?> list)) {
            return null;
        }
        var out = new ArrayList<EntityUpdate>();
        for (var element : list) {
            if (!(element instanceof Map<?, ?> item)) {
                continue;
            }
            Object etype = item.get("type");
            Object ids = item.get("ids");
            if (!("function".equals(etype) || "analysis".equals(etype) || "capabilities".equals(etype))) {
                continue;
            }
            if (!(ids instanceof List<?> idList)) {
                continue;
            }
            try {
                var parsedIds = new ArrayList<Long>();
                for (var id : idList) {
                    parsedIds.add(((Number) id).longValue());
                }
                out.add(new EntityUpdate((String) etype, parsedIds, parseRefs(item.get("refs"))));
            } catch (RuntimeException e) {
                // Skip malformed entity updates, matching the FE's defensive decode.
            }
        }
        return out.isEmpty() ? null : out;
    }

    private static List<EntityRef> parseRefs(Object raw) {
        if (!(raw instanceof List<?> list)) {
            return List.of();
        }
        var out = new ArrayList<EntityRef>();
        for (var element : list) {
            if (!(element instanceof Map<?, ?> item) || !item.containsKey("id")) {
                continue;
            }
            try {
                out.add(new EntityRef(
                        ((Number) item.get("id")).longValue(),
                        strOrEmpty(item.get("name")),
                        item.get("vaddr") instanceof Number v ? v.longValue() : 0L));
            } catch (RuntimeException e) {
                // Skip malformed refs.
            }
        }
        return out;
    }

    private static String str(Object value) {
        return value == null ? null : value.toString();
    }

    private static String strOrEmpty(Object value) {
        return value == null ? "" : value.toString();
    }

    private static boolean bool(Object value) {
        return value instanceof Boolean b && b;
    }
}

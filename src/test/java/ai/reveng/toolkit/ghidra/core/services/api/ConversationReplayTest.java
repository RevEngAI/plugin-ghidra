package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiClient;
import ai.reveng.invoker.Configuration;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationReplay;
import ai.reveng.toolkit.ghidra.chat.service.ChatServiceException;
import ai.reveng.toolkit.ghidra.chat.service.ConversationsApiChatService;
import com.sun.net.httpserver.HttpServer;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * History replay decodes /v2/conversations/{id} through the SDK's own models, where {@code type} is
 * an enum over the documented event numbers and {@code data} an anyOf over the per-type payloads.
 * Neither is a number or a map any more, so a replay that reads them as such compiles and silently
 * returns an empty transcript. This pins the decode end to end against a served body.
 */
public class ConversationReplayTest extends AbstractStubServerTest {

    private static final String UUID = "11111111-2222-3333-4444-555555555555";

    @Override
    protected void configureStubs(HttpServer server) {
        server.createContext("/v2/conversations/" + UUID, exchange -> respondJson(exchange, body()));
    }

    private ConversationReplay replay() throws ChatServiceException {
        ApiClient client = Configuration.getDefaultApiClient();
        client.setBasePath("http://127.0.0.1:" + server.getAddress().getPort());
        return new ConversationsApiChatService().getConversation(UUID);
    }

    @Test
    public void replay_collapsesUserTextEventsIntoOneMessage() throws Exception {
        var events = replay().events();

        var user = events.get(0).userMessage();
        assertNotNull("the user's three TEXT_MESSAGE_* events should replay as one message", user);
        assertEquals("rename this", user.content());
        assertEquals("m1", user.id());
        assertNull(events.get(0).event());
    }

    @Test
    public void replay_normalisesAssistantEventsWithTheirPayloads() throws Exception {
        var events = replay().events();

        assertEquals(List.of("TEXT_MESSAGE_START", "TEXT_MESSAGE_CONTENT", "TOOL_CALL_RESULT"),
                events.stream().skip(1).map(e -> e.event().type()).toList());

        var content = events.get(2).event();
        assertEquals("sure thing", content.delta());
        assertEquals("m2", content.messageId());

        var result = events.get(3).event();
        assertEquals("renamed", result.result());
        assertEquals("rename_function", result.toolName());
        assertEquals("call-1", result.toolCallId());
        assertTrue(result.isError());
        assertEquals(1, result.updated().size());
        assertEquals("function", result.updated().get(0).type());
        assertEquals(List.of(7L), result.updated().get(0).ids());
        assertEquals(7L, result.updated().get(0).refs().get(0).id());
        assertEquals("main", result.updated().get(0).refs().get(0).name());
    }

    @Test
    public void replay_dropsEventsWhoseTypeNumberThePluginDoesNotKnow() throws Exception {
        // 18 is USER_ANSWERED, which the plugin has no normalization for. The SDK does not declare
        // it either, so it arrives as the enum's unknown sentinel.
        assertEquals(4, replay().events().size());
    }

    private static String body() {
        return """
                {
                  "conversation_uuid": "%s",
                  "title": "a title",
                  "created_at": "2026-10-28T09:00:00Z",
                  "updated_at": "2026-10-28T09:05:00Z",
                  "user_id": 1,
                  "events": [
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                  ]
                }
                """.formatted(UUID,
                event(1, 6, 2, "{\"message_id\": \"m1\"}"),
                event(2, 7, 2, "{\"message_id\": \"m1\", \"delta\": \"rename this\"}"),
                event(3, 8, 2, "{\"message_id\": \"m1\"}"),
                event(4, 6, 1, "{\"message_id\": \"m2\"}"),
                event(5, 7, 1, "{\"message_id\": \"m2\", \"delta\": \"sure thing\"}"),
                event(6, 12, 1, """
                        {"tool_call_id": "call-1", "tool_name": "rename_function", "result": "renamed",
                         "is_error": true,
                         "updated": [{"type": "function", "ids": [7],
                                      "refs": [{"id": 7, "name": "main", "vaddr": 4096}]}]}"""),
                event(7, 18, 1, "{}"));
    }

    private static String event(long eventId, int type, int role, String data) {
        return """
                {
                  "conversation_uuid": "%s",
                  "created_at": "2026-10-28T09:00:00Z",
                  "event_id": %d,
                  "role": %d,
                  "tokens_used": 0,
                  "type": %d,
                  "data": %s
                }
                """.formatted(UUID, eventId, role, type, data);
    }
}

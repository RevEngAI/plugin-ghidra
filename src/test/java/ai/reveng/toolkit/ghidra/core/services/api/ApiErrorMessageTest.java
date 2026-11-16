package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.chat.service.ChatServiceException;
import ai.reveng.toolkit.ghidra.chat.service.ConversationsApiChatService;
import com.sun.net.httpserver.HttpServer;
import org.junit.Test;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/// A failed request must reach the user as the server's `error.message`, not as a dropped body or
/// the SDK's full {@link ApiException} dump of message, body and headers.
public class ApiErrorMessageTest extends AbstractStubServerTest {

    private static final String SERVER_MESSAGE = "page_size must be at most 500";
    private static final String CONVERSATION_ID = "11111111-2222-3333-4444-555555555555";

    @Override
    protected void configureStubs(HttpServer server) {
        server.createContext("/", exchange -> {
            byte[] bytes = "{\"error\":{\"code\":\"BAD_REQUEST\",\"message\":\"%s\"}}"
                    .formatted(SERVER_MESSAGE).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(422, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
    }

    /// Goes through the generated `*Call` and reads the body by hand.
    @Test
    public void rawCallKeepsTheResponseBody() {
        try {
            api().createAnalysisDataTypes(new TypedApiInterface.AnalysisID(1),
                    new ai.reveng.model.CreateAnalysisDataTypesInputBody());
            fail("a 422 should raise");
        } catch (ApiException e) {
            assertEquals(422, e.getCode());
            assertTrue(e.getResponseBody(), e.getResponseBody().contains(SERVER_MESSAGE));
        }
    }

    @Test
    public void rawCallFailureShowsServerMessage() {
        assertShowsServerMessage(() -> api().listAnalysisDataTypes(new TypedApiInterface.AnalysisID(1), 0, 1000));
    }

    /// Goes through a generated model method.
    @Test
    public void modelCallFailureShowsServerMessage() {
        assertShowsServerMessage(() -> api().getFunctionDetails(new TypedApiInterface.FunctionID(1)));
    }

    /// Chat reads the conversation through the generated `*Call`.
    @Test
    public void chatRawCallFailureShowsServerMessage() {
        assertChatShowsServerMessage("load conversation", chat -> chat.getConversation(CONVERSATION_ID));
    }

    @Test
    public void chatModelCallFailureShowsServerMessage() {
        assertChatShowsServerMessage("cancel run", chat -> chat.cancelRun(CONVERSATION_ID));
    }

    private interface ChatRequest {
        void run(ConversationsApiChatService chat) throws ChatServiceException;
    }

    private void assertChatShowsServerMessage(String action, ChatRequest request) {
        var client = api().apiClient();
        try {
            request.run(new ConversationsApiChatService(() -> client));
            fail("a 422 should raise");
        } catch (ChatServiceException e) {
            assertEquals("Failed to " + action + ": HTTP 422 — " + SERVER_MESSAGE, e.getMessage());
        }
    }

    private static void assertShowsServerMessage(Runnable request) {
        try {
            request.run();
            fail("a 422 should raise");
        } catch (RuntimeException e) {
            assertEquals("HTTP 422 — " + SERVER_MESSAGE, e.getMessage());
            assertFalse(e.getMessage(), e.getMessage().contains("HTTP response headers"));
        }
    }
}

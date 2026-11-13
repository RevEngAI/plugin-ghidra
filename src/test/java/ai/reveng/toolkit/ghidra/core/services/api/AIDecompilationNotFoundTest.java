package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiException;
import com.sun.net.httpserver.HttpServer;
import org.junit.Test;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/// A function that was never decompiled answers 200 with status UNINITIALISED, so a 404 means the
/// function itself was not found. Reading it as UNINITIALISED made the window poll for ever.
public class AIDecompilationNotFoundTest extends AbstractStubServerTest {

    @Override
    protected void configureStubs(HttpServer server) {
        server.createContext("/v3/functions/7/ai-decompilation", exchange -> {
            byte[] body = "{\"error\": {\"code\": \"NOT_FOUND\", \"message\": \"function not found\"}}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(404, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
    }

    @Test
    public void notFoundIsAnErrorNotUninitialised() {
        var thrown = assertThrows(RuntimeException.class,
                () -> api().pollAIDecompileStatus(new TypedApiInterface.FunctionID(7)));
        assertTrue(thrown.getMessage(), thrown.getMessage().contains("could not find function 7"));
        assertTrue(thrown.getCause() instanceof ApiException api && api.getCode() == 404);
    }
}

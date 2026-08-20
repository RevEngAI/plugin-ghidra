package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiClient;
import ai.reveng.invoker.Configuration;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/// Base for tests that exercise {@link TypedApiImplementation} against a stub HTTP server bound to
/// an ephemeral loopback port. Subclasses only register their handlers in {@link #configureStubs}
/// and reach the client under test through {@link #api()}.
public abstract class AbstractStubServerTest extends AbstractGhidraHeadlessIntegrationTest {

    protected HttpServer server;
    private ApiClient originalApiClient;

    @Before
    public void startStubServer() throws Exception {
        // TypedApiImplementation mutates the ApiClient that Configuration holds as a process-global
        // singleton (base path, stacked interceptors). The test task forks in parallel and runs
        // several classes per fork, so without this save/restore one class leaks its client into
        // whichever class runs next in the same fork.
        originalApiClient = Configuration.getDefaultApiClient();
        Configuration.setDefaultApiClient(new ApiClient());

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        configureStubs(server);
        server.start();
    }

    @After
    public void stopStubServer() {
        if (server != null) {
            server.stop(0);
        }
        if (originalApiClient != null) {
            Configuration.setDefaultApiClient(originalApiClient);
        }
    }

    /// Registers the contexts this test serves. Called before the server is started.
    protected abstract void configureStubs(HttpServer server);

    protected TypedApiImplementation api() {
        return new TypedApiImplementation("http://127.0.0.1:" + server.getAddress().getPort(), "test-key");
    }

    protected static void respondJson(HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}

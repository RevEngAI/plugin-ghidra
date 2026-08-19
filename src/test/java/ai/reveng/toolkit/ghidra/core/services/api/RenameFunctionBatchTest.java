package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiClient;
import ai.reveng.invoker.Configuration;
import com.sun.net.httpserver.HttpServer;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * {@link TypedApiImplementation#renameFunction} maps a single rename onto the v3 batch endpoint,
 * which answers 200 with a renamed count instead of failing per item. This checks that the request
 * carries the full 64-bit function id and that a count of zero reaches the caller as a failure.
 */
public class RenameFunctionBatchTest extends AbstractGhidraHeadlessIntegrationTest {

    private static final long FUNCTION_ID = 5_000_000_000L;

    private HttpServer server;
    private ApiClient originalApiClient;
    private final List<String> requestBodies = new CopyOnWriteArrayList<>();
    private final AtomicLong renamedCount = new AtomicLong(1);

    @Before
    public void startStubServer() throws Exception {
        originalApiClient = Configuration.getDefaultApiClient();
        Configuration.setDefaultApiClient(new ApiClient());

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v3/functions/rename", exchange -> {
            requestBodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] bytes = "{\"renamed_count\":%d}".formatted(renamedCount.get()).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
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

    @Test
    public void renameFunction_postsOneItemBatchWithUnnarrowedId() {
        api().renameFunction(new TypedApiInterface.FunctionID(FUNCTION_ID), "new_name", "new_mangled_name");

        assertEquals(1, requestBodies.size());
        String body = requestBodies.get(0);
        assertTrue("should send the full function id, not a narrowed int: " + body,
                body.contains("\"function_id\":" + FUNCTION_ID));
        assertTrue(body.contains("\"new_name\":\"new_name\""));
        assertTrue(body.contains("\"new_mangled_name\":\"new_mangled_name\""));
    }

    @Test
    public void renameFunction_failsWhenServerRenamedNothing() {
        renamedCount.set(0);

        try {
            api().renameFunction(new TypedApiInterface.FunctionID(FUNCTION_ID), "new_name", "new_mangled_name");
            fail("a renamed_count of zero should not be reported as a successful rename");
        } catch (RuntimeException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(String.valueOf(FUNCTION_ID)));
        }
    }

    private TypedApiImplementation api() {
        return new TypedApiImplementation("http://127.0.0.1:" + server.getAddress().getPort(), "test-key");
    }
}

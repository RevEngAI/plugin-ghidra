package ai.reveng.toolkit.ghidra.core.services.api;

import com.sun.net.httpserver.HttpServer;
import org.junit.Test;

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
public class RenameFunctionBatchTest extends AbstractStubServerTest {

    private static final long FUNCTION_ID = 5_000_000_000L;

    private final List<String> requestBodies = new CopyOnWriteArrayList<>();
    private final AtomicLong renamedCount = new AtomicLong(1);

    @Override
    protected void configureStubs(HttpServer server) {
        server.createContext("/v3/functions/rename", exchange -> {
            requestBodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respondJson(exchange, "{\"renamed_count\":%d}".formatted(renamedCount.get()));
        });
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
}

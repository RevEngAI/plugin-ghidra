package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.Configuration;
import ai.reveng.toolkit.ghidra.core.services.api.types.ApiInfo;
import com.sun.net.httpserver.HttpServer;
import org.junit.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

/**
 * Every {@link TypedApiImplementation} owns its HTTP client. They used to share the SDK's
 * process-global default client, so the setup wizard's throwaway validation instance re-targeted
 * the running session: a mistyped key there made every later call fail with 401.
 */
public class ApiClientIsolationTest extends AbstractStubServerTest {

    private final List<String> authorizations = new CopyOnWriteArrayList<>();

    @Override
    protected void configureStubs(HttpServer server) {
        server.createContext("/", exchange -> {
            authorizations.add(exchange.getRequestHeaders().getFirst("Authorization"));
            exchange.sendResponseHeaders(401, -1);
            exchange.close();
        });
    }

    private String stubUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /// Any request will do; only the credentials it carries are of interest.
    private static void call(TypedApiInterface api) {
        try {
            api.getAnalysisBasicInfo(new TypedApiInterface.AnalysisID(1));
        } catch (Exception expected) {
            // the stub answers 401
        }
    }

    @Test
    public void validatingOtherCredentialsDoesNotChangeTheRunningInstancesKey() {
        var running = new TypedApiImplementation(stubUrl(), "real-key");
        new TypedApiImplementation("http://127.0.0.1:1", "typo-key");

        call(running);

        assertEquals(List.of("real-key"), authorizations);
        assertEquals(stubUrl(), running.apiClient().getBasePath());
    }

    @Test
    public void instancesDoNotTouchTheSdksDefaultClient() {
        var defaultClient = Configuration.getDefaultApiClient();
        var basePath = defaultClient.getBasePath();

        var api = api();

        assertNotSame(defaultClient, api.apiClient());
        assertSame(defaultClient, Configuration.getDefaultApiClient());
        assertEquals(basePath, defaultClient.getBasePath());
    }

    /// Each instance used to add one more interceptor to the shared client, so every request was
    /// logged once per instance ever created.
    @Test
    public void eachClientLogsRequestsOnce() {
        api();
        api();
        var third = api();

        long loggers = third.apiClient().getHttpClient().interceptors().stream()
                .filter(LoggingInterceptor.class::isInstance)
                .count();
        assertEquals(1, loggers);
    }

    @Test
    public void reconfiguringTheServiceSwitchesItsCredentials() {
        var service = new GhidraRevengService(new ApiInfo(stubUrl(), "http://portal.invalid", "old-key"));
        var oldClient = service.apiClient();

        assertTrue(service.reconfigure(new ApiInfo(stubUrl(), "http://portal.invalid", "new-key")));
        call(service.getApi());

        assertEquals(List.of("new-key"), authorizations);
        assertNotSame(oldClient, service.apiClient());
    }

    @Test
    public void reconfiguringWithTheSameCredentialsKeepsTheClient() {
        var info = new ApiInfo(stubUrl(), "http://portal.invalid", "key");
        var service = new GhidraRevengService(info);
        var client = service.apiClient();

        assertFalse(service.reconfigure(new ApiInfo(stubUrl(), "http://portal.invalid", "key")));
        assertSame(client, service.apiClient());
    }
}

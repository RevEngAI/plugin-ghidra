package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiException;
import com.sun.net.httpserver.HttpServer;
import org.junit.Test;

/// `data` is optional on the base response wrapper, so a body without it must surface as an
/// {@link ApiException} rather than a NullPointerException.
public class EmptyResponseDataTest extends AbstractStubServerTest {

    private static final String EMPTY = "{\"status\": false, \"data\": null, \"message\": \"nope\"}";
    private static final String OPERATION_WITHOUT_ID = "{\"name\": \"operations/1\", \"done\": false}";

    @Override
    protected void configureStubs(HttpServer server) {
        server.createContext("/", exchange -> respondJson(exchange, EMPTY));
        server.createContext("/v3/analyses", exchange -> respondJson(exchange, OPERATION_WITHOUT_ID));
    }

    @Test(expected = ApiException.class)
    public void statusWithoutDataThrowsApiException() throws Exception {
        api().status(new TypedApiInterface.AnalysisID(1));
    }

    @Test(expected = ApiException.class)
    public void analyseWithoutAnalysisIdThrowsApiException() throws Exception {
        api().analyse(new AnalysisOptionsBuilder()
                .hash(new TypedApiInterface.BinaryHash("a".repeat(64)))
                .fileName("test.bin"));
    }
}

package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiClient;
import ai.reveng.invoker.Configuration;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import com.sun.net.httpserver.HttpServer;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * The v2 functions list endpoint caps page_size at 1000, so {@link TypedApiImplementation#getFunctionInfo}
 * must page through every result. This stubs the endpoint with a two-page response and checks that all
 * functions come back and that paging stops once the server reports no next page.
 */
public class GetFunctionInfoPaginationTest extends AbstractGhidraHeadlessIntegrationTest {

    private static final int ANALYSIS_ID = 123;

    private HttpServer server;
    private ApiClient originalApiClient;
    private final List<String> requestedQueries = new CopyOnWriteArrayList<>();

    @Before
    public void startStubServer() throws Exception {
        // TypedApiImplementation mutates the shared default ApiClient (base path, stacked interceptors).
        // Isolate this test from whatever ran before it in the same fork, and restore it afterwards.
        originalApiClient = Configuration.getDefaultApiClient();
        Configuration.setDefaultApiClient(new ApiClient());

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v2/analyses/" + ANALYSIS_ID + "/functions/list", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            requestedQueries.add(query);
            int page = pageParam(query);
            String body = page <= 1 ? pageResponse(List.of(10L, 11L), 1, true)
                                    : pageResponse(List.of(12L), 2, false);
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
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
    public void getFunctionInfo_walksEveryPage() {
        var api = new TypedApiImplementation("http://127.0.0.1:" + server.getAddress().getPort(), "test-key");

        List<FunctionInfo> functions = api.getFunctionInfo(new TypedApiInterface.AnalysisID(ANALYSIS_ID));

        List<Long> ids = functions.stream().map(f -> f.functionID().value()).collect(Collectors.toList());
        assertEquals("both pages should be combined", List.of(10L, 11L, 12L), ids);

        assertEquals("should stop after the page with has_next_page=false", 2, requestedQueries.size());
        assertTrue("first request should ask for page 1", requestedQueries.get(0).contains("page=1"));
        assertTrue("second request should ask for page 2", requestedQueries.get(1).contains("page=2"));
        assertTrue("should request the server's max page size", requestedQueries.get(0).contains("page_size=1000"));
    }

    private static int pageParam(String query) {
        if (query == null) {
            return 1;
        }
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).equals("page")) {
                return Integer.parseInt(pair.substring(eq + 1));
            }
        }
        return 1;
    }

    private static String pageResponse(List<Long> functionIds, int pageNumber, boolean hasNextPage) {
        String functions = functionIds.stream()
                .map(GetFunctionInfoPaginationTest::functionJson)
                .collect(Collectors.joining(","));
        return """
                {"status":true,"message":"ok","errors":[],\
                "data":{"functions":[%s]},\
                "meta":{"pagination":{"page_size":1000,"page_number":%d,"has_next_page":%b}}}\
                """.formatted(functions, pageNumber, hasNextPage);
    }

    private static String functionJson(long id) {
        return """
                {"function_id":%d,"function_name":"func_%d","function_mangled_name":"mangled_%d",\
                "function_vaddr":%d,"function_size":32,"debug":false}\
                """.formatted(id, id, id, 0x400000L + id);
    }
}

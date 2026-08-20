package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import com.sun.net.httpserver.HttpServer;
import org.junit.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

/**
 * The v3 functions list endpoint is paginated by offset and limit and reports the unpaginated
 * population size as {@code total_count}, so {@link TypedApiImplementation#getFunctionInfo} must
 * walk the offset forward until that many entries have arrived. These stubs serve a server that
 * caps a page below the requested limit, which is also what forces the offset to advance by the
 * number of entries actually returned.
 */
public class GetFunctionInfoPaginationTest extends AbstractStubServerTest {

    private static final int ANALYSIS_ID = 123;
    private static final int SERVER_PAGE_CAP = 2;

    private final List<String> requestedQueries = new CopyOnWriteArrayList<>();
    private volatile List<Long> allFunctionIds = List.of();

    @Override
    protected void configureStubs(HttpServer server) {
        server.createContext("/v3/analyses/" + ANALYSIS_ID + "/functions", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            requestedQueries.add(query);
            int offset = Math.toIntExact(longParam(query, "offset", 0));
            int limit = Math.toIntExact(longParam(query, "limit", 100));

            List<Long> ids = allFunctionIds;
            int from = Math.min(offset, ids.size());
            int to = Math.min(from + Math.min(limit, SERVER_PAGE_CAP), ids.size());
            respondJson(exchange, pageResponse(ids.subList(from, to), ids.size()));
        });
    }

    /** A trailing partial page: the last request comes back short of the server's own cap. */
    @Test
    public void getFunctionInfo_walksEveryPage() {
        allFunctionIds = List.of(10L, 11L, 12L);

        List<FunctionInfo> functions = fetch();

        assertEquals("every page should be combined, in order",
                List.of(10L, 11L, 12L), idsOf(functions));
        assertEquals("offset should advance by the entries actually returned",
                List.of("offset=0&limit=1000", "offset=2&limit=1000"), requestedQueries);
    }

    /**
     * A final page that exactly reaches total_count. Paging has to stop on the count rather than
     * on a short page, otherwise it issues one more request than it needs.
     */
    @Test
    public void getFunctionInfo_stopsOnceTotalCountIsReached() {
        allFunctionIds = List.of(10L, 11L, 12L, 13L);

        List<FunctionInfo> functions = fetch();

        assertEquals("every page should be combined, in order",
                List.of(10L, 11L, 12L, 13L), idsOf(functions));
        assertEquals("a full final page should not trigger another request",
                List.of("offset=0&limit=1000", "offset=2&limit=1000"), requestedQueries);
    }

    /** An analysis with no functions still answers 200, with an empty list and a zero count. */
    @Test
    public void getFunctionInfo_handlesAnEmptyAnalysis() {
        allFunctionIds = List.of();

        List<FunctionInfo> functions = fetch();

        assertEquals(List.of(), idsOf(functions));
        assertEquals("a single request is enough to learn the analysis is empty",
                List.of("offset=0&limit=1000"), requestedQueries);
    }

    /** mangled_name is optional on the v3 entry; callers rely on the plugin type carrying one. */
    @Test
    public void getFunctionInfo_fallsBackToTheFunctionNameWhenUnmangled() {
        allFunctionIds = List.of(10L, UNMANGLED_ID);

        List<FunctionInfo> functions = fetch();

        assertEquals(List.of("mangled_10", "func_" + UNMANGLED_ID),
                functions.stream().map(FunctionInfo::functionMangledName).collect(Collectors.toList()));
    }

    private List<FunctionInfo> fetch() {
        return api().getFunctionInfo(new TypedApiInterface.AnalysisID(ANALYSIS_ID));
    }

    private static List<Long> idsOf(List<FunctionInfo> functions) {
        return functions.stream().map(f -> f.functionID().value()).collect(Collectors.toList());
    }

    private static long longParam(String query, String name, long fallback) {
        if (query == null) {
            return fallback;
        }
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).equals(name)) {
                return Long.parseLong(pair.substring(eq + 1));
            }
        }
        return fallback;
    }

    private static String pageResponse(List<Long> functionIds, int totalCount) {
        String functions = functionIds.stream()
                .map(GetFunctionInfoPaginationTest::functionJson)
                .collect(Collectors.joining(","));
        return """
                {"functions":[%s],"total_count":%d}\
                """.formatted(functions, totalCount);
    }

    /** The id whose entry the stub serves without a mangled_name. */
    private static final long UNMANGLED_ID = 99L;

    private static String functionJson(long id) {
        String mangledName = id == UNMANGLED_ID ? "" : "\"mangled_name\":\"mangled_%d\",".formatted(id);
        return """
                {"function_id":%d,"function_name":"func_%d",%s\
                "function_vaddr":%d,"function_size":32,"binary_id":7,"debug":false,\
                "source_type":"analysis"}\
                """.formatted(id, id, mangledName, 0x400000L + id);
    }
}

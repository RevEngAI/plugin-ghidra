package ai.reveng.toolkit.ghidra.core.services.api;

import com.sun.net.httpserver.HttpServer;
import org.junit.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * {@link TypedApiImplementation#search} filters /v3/analyses by hash and follows next_page_token,
 * so this covers the query it sends, the multi-page walk and the empty "no analyses for this hash"
 * answer.
 */
public class ListAnalysesForHashTest extends AbstractStubServerTest {

    private static final String HASH = "b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6";

    private final List<String> requestQueries = new CopyOnWriteArrayList<>();
    private volatile String firstPage = emptyPage();
    private volatile String secondPage = emptyPage();

    @Override
    protected void configureStubs(HttpServer server) {
        server.createContext("/v3/analyses", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            requestQueries.add(query);
            respondJson(exchange, query != null && query.contains("next_page_token=") ? secondPage : firstPage);
        });
    }

    @Test
    public void search_filtersByHashOverEveryScope() {
        firstPage = page(null, record(11, 22));

        var results = api().search(new TypedApiInterface.BinaryHash(HASH));

        assertEquals(1, requestQueries.size());
        String query = requestQueries.get(0);
        assertTrue(query, query.contains("sha256_hash=" + HASH));
        assertTrue(query, query.contains("analysis_scope=PRIVATE"));
        assertTrue(query, query.contains("analysis_scope=TEAM"));
        assertTrue(query, query.contains("analysis_scope=PUBLIC"));

        assertEquals(1, results.size());
        assertEquals(Long.valueOf(11), results.get(0).getAnalysisId());
        assertEquals(Long.valueOf(22), results.get(0).getBinaryId());
        assertEquals("true", results.get(0).getBinaryName());
        assertEquals("Complete", results.get(0).getStatus());
    }

    @Test
    public void search_followsNextPageToken() {
        firstPage = page("cursor-1", record(11, 22));
        secondPage = page(null, record(12, 23));

        var results = api().search(new TypedApiInterface.BinaryHash(HASH));

        assertEquals(2, requestQueries.size());
        assertTrue(requestQueries.get(1), requestQueries.get(1).contains("next_page_token=cursor-1"));
        assertEquals(List.of(11L, 12L), results.stream().map(r -> r.getAnalysisId()).toList());
    }

    @Test
    public void search_returnsEmptyWhenNoAnalysisMatchesTheHash() {
        var results = api().search(new TypedApiInterface.BinaryHash(HASH));

        assertEquals(1, requestQueries.size());
        assertTrue(results.isEmpty());
    }

    /// Ids are 64-bit on the wire; base_address is what the Recent Analyses table matches against
    /// the program's image base.
    @Test
    public void search_readsIdsAndBaseAddressBeyondIntRange() {
        firstPage = page(null, """
                {
                  "analysis_id": 4321,
                  "analysis_scope": "PRIVATE",
                  "base_address": 4294967296,
                  "binary_id": 5000000000,
                  "binary_name": "true",
                  "binary_size": 9000000000,
                  "creation": "2024-04-19T08:57:18Z",
                  "detected_architecture": "x86_64",
                  "detected_binary_format": "ELF",
                  "detected_binary_type": "linux",
                  "function_boundaries_hash": "b48f61e8",
                  "is_owner": true,
                  "model_id": 1,
                  "model_name": "binnet-0.5",
                  "sha_256_hash": "%s",
                  "status": "Complete",
                  "supplied_architecture": "Auto",
                  "supplied_binary_format": "Auto",
                  "supplied_binary_type": "Auto",
                  "tags": [],
                  "username": "tester"
                }
                """.formatted(HASH));

        var record = api().search(new TypedApiInterface.BinaryHash(HASH)).get(0);

        assertEquals(Long.valueOf(5_000_000_000L), record.getBinaryId());
        assertEquals(Long.valueOf(4_294_967_296L), record.getBaseAddress());
        assertEquals(Long.valueOf(9_000_000_000L), record.getBinarySize());
        assertEquals("2024-04-19T08:57:18Z", record.getCreation().toString());
    }

    private static String emptyPage() {
        return page(null);
    }

    private static String page(String nextPageToken, String... records) {
        String token = nextPageToken == null ? "" : ", \"next_page_token\": \"" + nextPageToken + "\"";
        return "{ \"page_size\": 50, \"results\": [" + String.join(",", records) + "]" + token + " }";
    }

    private static String record(long analysisId, long binaryId) {
        return """
                {
                  "analysis_id": %d,
                  "analysis_scope": "PRIVATE",
                  "base_address": 4194304,
                  "binary_id": %d,
                  "binary_name": "true",
                  "binary_size": 1024,
                  "creation": "2024-04-19T08:57:18Z",
                  "detected_architecture": "x86_64",
                  "detected_binary_format": "ELF",
                  "detected_binary_type": "linux",
                  "function_boundaries_hash": "b48f61e8",
                  "is_owner": true,
                  "model_id": 1,
                  "model_name": "binnet-0.5",
                  "sha_256_hash": "%s",
                  "status": "Complete",
                  "supplied_architecture": "Auto",
                  "supplied_binary_format": "Auto",
                  "supplied_binary_type": "Auto",
                  "tags": [],
                  "username": "tester"
                }
                """.formatted(analysisId, binaryId, HASH);
    }
}

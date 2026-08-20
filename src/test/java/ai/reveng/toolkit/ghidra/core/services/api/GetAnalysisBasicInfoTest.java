package ai.reveng.toolkit.ghidra.core.services.api;

import com.sun.net.httpserver.HttpServer;
import org.junit.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * {@link TypedApiImplementation#getAnalysisBasicInfo} memoises per analysis id and its ids are
 * 64-bit on the wire, so this covers the cache and a binary id above 2^31.
 */
public class GetAnalysisBasicInfoTest extends AbstractStubServerTest {

    private static final int ANALYSIS_ID = 4321;
    private static final long BINARY_ID = 5_000_000_000L;

    private final List<String> requestPaths = new CopyOnWriteArrayList<>();

    @Override
    protected void configureStubs(HttpServer server) {
        server.createContext("/v3/analyses", exchange -> {
            requestPaths.add(exchange.getRequestURI().getPath());
            respondJson(exchange, body());
        });
    }

    @Test
    public void getAnalysisBasicInfo_readsTheV3Endpoint() throws Exception {
        var info = api().getAnalysisBasicInfo(new TypedApiInterface.AnalysisID(ANALYSIS_ID));

        assertEquals(List.of("/v3/analyses/" + ANALYSIS_ID + "/basic"), requestPaths);
        assertEquals("test_binary", info.getBinaryName());
        assertEquals("0".repeat(64), info.getSha256Hash());
        assertEquals("binnet-0.5", info.getModelName());
    }

    @Test
    public void getAnalysisBasicInfo_widensIdsBeyondIntRange() throws Exception {
        var info = api().getAnalysisBasicInfo(new TypedApiInterface.AnalysisID(ANALYSIS_ID));

        assertEquals(Long.valueOf(BINARY_ID), info.getBinaryId());
        assertEquals(Long.valueOf(9_000_000_000L), info.getBinarySize());
        assertEquals(Long.valueOf(4_294_967_296L), info.getBaseAddress());
    }

    @Test
    public void getAnalysisBasicInfo_secondReadOfTheSameIdIsServedFromCache() throws Exception {
        var api = api();
        var first = api.getAnalysisBasicInfo(new TypedApiInterface.AnalysisID(ANALYSIS_ID));
        var second = api.getAnalysisBasicInfo(new TypedApiInterface.AnalysisID(ANALYSIS_ID));

        assertEquals(1, requestPaths.size());
        assertTrue("a cache hit should return the memoised instance", first == second);

        api.getAnalysisBasicInfo(new TypedApiInterface.AnalysisID(ANALYSIS_ID + 1));
        assertEquals(2, requestPaths.size());
        assertEquals("/v3/analyses/" + (ANALYSIS_ID + 1) + "/basic", requestPaths.get(1));
    }

    private static String body() {
        return """
                {
                  "analysis_scope": "PRIVATE",
                  "base_address": 4294967296,
                  "binary_id": %d,
                  "binary_name": "test_binary",
                  "binary_size": 9000000000,
                  "binary_uuid": "1a2b3c4d-0000-0000-0000-000000000000",
                  "creation": "2026-01-01T00:00:00Z",
                  "debug": false,
                  "detected_architecture": "x86_64",
                  "detected_binary_format": "ELF",
                  "detected_binary_type": "EXEC",
                  "function_count": 12,
                  "is_advanced": false,
                  "is_owner": true,
                  "is_system": false,
                  "model_id": 7,
                  "model_name": "binnet-0.5",
                  "owner_username": "tester",
                  "sequencer_version": null,
                  "sha_256_hash": "%s",
                  "supplied_architecture": "Auto",
                  "supplied_binary_format": "Auto",
                  "supplied_binary_type": "Auto",
                  "team_id": 3
                }
                """.formatted(BINARY_ID, "0".repeat(64));
    }
}

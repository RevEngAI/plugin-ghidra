package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.model.DecompilationData;
import ai.reveng.model.GetMatchesStatusOutputBody;
import ai.reveng.model.ProgressMessage;
import ai.reveng.model.User;
import ai.reveng.model.WorkflowProgress;
import ai.reveng.toolkit.ghidra.core.services.api.types.AIDecompilationStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch;
import com.sun.net.httpserver.HttpServer;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/// Runs staging-shaped response bodies (`src/test/resources/sdk-responses`) through the generated
/// SDK models via the plugin's own {@link TypedApiImplementation} calls. {@link SdkSchemaTest} only
/// pins that the accessors exist; this checks that a real body deserialises — every required field
/// present, every enum value known — and that the values land where the plugin reads them.
public class SdkRecordedResponseTest extends AbstractStubServerTest {

    private static final long DECOMPILED_FUNCTION = 101;
    private static final long RUNNING_FUNCTION = 102;
    private static final int ANALYSIS = 7;

    private static final String DECOMP = "/v3/functions/" + DECOMPILED_FUNCTION + "/ai-decompilation";
    private static final String RUNNING_DECOMP = "/v3/functions/" + RUNNING_FUNCTION + "/ai-decompilation";

    /// "METHOD path" to the recorded body served for it.
    private static final Map<String, String> ROUTES = Map.ofEntries(
            Map.entry("GET " + DECOMP, "ai-decompilation.json"),
            Map.entry("GET " + DECOMP + "/summary/status", "ai-decompilation-summary-status.json"),
            Map.entry("GET " + DECOMP + "/summary", "ai-decompilation-summary.json"),
            Map.entry("GET " + DECOMP + "/inline-comments/status", "ai-decompilation-inline-comments-status.json"),
            Map.entry("GET " + DECOMP + "/inline-comments", "ai-decompilation-inline-comments.json"),
            Map.entry("PATCH " + DECOMP + "/inline-comments", "ai-decompilation-inline-comments-patch.json"),
            Map.entry("DELETE " + DECOMP + "/inline-comments/6", "ai-decompilation-inline-comments-delete.json"),
            Map.entry("GET " + RUNNING_DECOMP, "ai-decompilation-running.json"),
            Map.entry("GET " + RUNNING_DECOMP + "/status", "ai-decompilation-status.json"),
            Map.entry("GET /v3/analyses/" + ANALYSIS + "/auto-unstrip/status", "auto-unstrip-status.json"),
            Map.entry("POST /v3/functions/canonical-names", "canonical-names.json"),
            Map.entry("GET /v2/iam/me", "iam-me.json"),
            Map.entry("GET /v2/config", "config.json"),
            Map.entry("GET /v3/analyses/" + ANALYSIS + "/functions/matches/status", "matches-status-completed.json"),
            Map.entry("GET /v3/functions/matches/status", "matches-status-running.json"),
            Map.entry("GET /v3/analyses/" + ANALYSIS + "/functions/matches", "analysis-matches.json"),
            Map.entry("GET /v2/search/binaries", "search-binaries.json"),
            Map.entry("GET /v3/collections", "collections.json"));

    private final List<String> requests = new CopyOnWriteArrayList<>();

    @Override
    protected void configureStubs(HttpServer server) {
        server.createContext("/", exchange -> {
            String route = exchange.getRequestMethod() + " " + exchange.getRequestURI().getPath();
            requests.add(route);
            String fixture = ROUTES.get(route);
            if (fixture == null) {
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }
            respondJson(exchange, recorded(fixture));
        });
    }

    @Test
    public void completedDecompilationCarriesTextSummaryAndComments() {
        AIDecompilationStatus status = api().pollAIDecompileStatus(new TypedApiInterface.FunctionID(DECOMPILED_FUNCTION));

        assertEquals(DecompilationData.StatusEnum.COMPLETED, status.status());
        assertTrue(status.decompilation().startsWith("int parse_header(char *buf, int len)"));
        assertEquals(WorkflowProgress.StatusEnum.COMPLETED, status.summaryStatus());
        // ai_summary is the plain-text form; summary carries markup.
        assertEquals("Parses an HTTP header from buf and returns the length of the remaining payload, "
                + "or -1 if the buffer is shorter than 8 bytes.", status.summary());
        assertEquals(WorkflowProgress.StatusEnum.COMPLETED, status.inlineCommentsStatus());
        assertEquals(List.of(
                new AIDecompilationStatus.InlineCommentEntry(3, "Reject buffers too short to hold the 8-byte header."),
                new AIDecompilationStatus.InlineCommentEntry(6, "Skip the 4-byte magic and parse the length field.")),
                status.inlineComments());
    }

    @Test
    public void runningDecompilationCarriesPipelineProgress() {
        AIDecompilationStatus status = api().pollAIDecompileStatus(new TypedApiInterface.FunctionID(RUNNING_FUNCTION));

        assertEquals(DecompilationData.StatusEnum.RUNNING, status.status());
        WorkflowProgress progress = status.decompilationProgress();
        assertNotNull("the progress body should deserialise", progress);
        assertEquals(WorkflowProgress.StatusEnum.RUNNING, progress.getStatus());
        assertEquals("decompiling", progress.getStep());
        assertEquals(Long.valueOf(2), progress.getStepIndex());
        assertEquals(Long.valueOf(7), progress.getStepsTotal());
        assertEquals(4, progress.getMessages().size());
        ProgressMessage first = progress.getMessages().get(0);
        assertEquals(ProgressMessage.LevelEnum.INFO, first.getLevel());
        assertEquals("Preparing decompilation", first.getText());
        assertNotNull(first.getTimestamp());
    }

    @Test
    public void inlineCommentEditsDeserialiseTheirResponses() throws Exception {
        var api = api();
        api.setAIDecompilationInlineComment(new TypedApiInterface.FunctionID(DECOMPILED_FUNCTION), 6, "Length field is big-endian.");
        api.deleteAIDecompilationInlineComment(new TypedApiInterface.FunctionID(DECOMPILED_FUNCTION), 6);

        assertEquals(List.of("PATCH " + DECOMP + "/inline-comments", "DELETE " + DECOMP + "/inline-comments/6"), requests);
    }

    @Test
    public void autoUnstripStatusMapsToTheKnownState() throws Exception {
        assertEquals(TypedApiInterface.AutoUnstripStatus.COMPLETED,
                api().getAutoUnstripStatus(new TypedApiInterface.AnalysisID(ANALYSIS)));
    }

    @Test
    public void canonicalNamesComeBackKeyedByInput() throws Exception {
        assertEquals(Map.of("_ZN3fooC1Ev", "foo", "sub_401000", "sub_401000"),
                api().canonicalizeFunctionNames(List.of("_ZN3fooC1Ev", "sub_401000")));
    }

    @Test
    public void currentUserCarriesTier() {
        assertEquals(User.TierEnum.REVERSER, api().getMe().getTier());
    }

    @Test
    public void configCarriesMaxFileSize() {
        assertEquals(31_457_280L, api().getConfig().getMaxFileSizeBytes().longValue());
    }

    @Test
    public void matchingStatusBodiesDeserialise() throws Exception {
        var api = api();
        GetMatchesStatusOutputBody completed = api.getAnalysisFunctionMatchingStatus(new TypedApiInterface.AnalysisID(ANALYSIS));
        assertEquals(GetMatchesStatusOutputBody.StatusEnum.COMPLETED, completed.getStatus());
        assertTrue(completed.getMessages().isEmpty());

        GetMatchesStatusOutputBody running = api.getFunctionsMatchingStatus(List.of(1109480836L));
        assertEquals(GetMatchesStatusOutputBody.StatusEnum.RUNNING, running.getStatus());
        assertEquals("matching", running.getStep());
        assertEquals(Long.valueOf(1), running.getStepIndex());
        assertEquals(Long.valueOf(3), running.getStepsTotal());
        assertEquals("Searching for similar functions", running.getMessages().get(1).getText());
    }

    @Test
    public void matchedFunctionsCarryNameBinaryAndHash() throws Exception {
        var body = api().getAnalysisFunctionMatches(new TypedApiInterface.AnalysisID(ANALYSIS));
        var match = body.getMatches().get(0);
        var origin = new TypedApiInterface.FunctionID(match.getFunctionId());
        FunctionMatch best = FunctionMatch.fromMatchedFunctionAPIType(match.getMatchedFunctions().get(0), origin);

        assertEquals(new TypedApiInterface.FunctionID(1109480836L), best.origin_function_id());
        assertEquals(new TypedApiInterface.FunctionID(2209481173L), best.nearest_neighbor_id());
        assertEquals("std::thread::_M_start_thread", best.name());
        assertEquals("_ZNSt6thread15_M_start_threadESt10unique_ptrINS_6_StateESt14default_deleteIS1_EEPFvvE",
                best.nearest_neighbor_mangled_function_name());
        assertEquals("libstdc++.so.6", best.nearest_neighbor_binary_name());
        assertEquals(new TypedApiInterface.BinaryHash("7399e7775c542bf9bd036dccad91e9fea586a383ae2b958facfcdc03749f202e"),
                best.nearest_neighbor_sha_256_hash());
        assertEquals(new TypedApiInterface.AnalysisID(948099), best.nearest_neighbor_analysis_id());
        assertEquals(2, match.getMatchedFunctions().size());
    }

    @Test
    public void binarySearchResultsCarryAnalysisAndName() throws Exception {
        var results = api().searchBinaries("libstdc", null);
        assertEquals(1, results.size());
        assertEquals(Integer.valueOf(948099), results.get(0).getAnalysisId());
        assertEquals("libstdc++.so.6", results.get(0).getBinaryName());
    }

    @Test
    public void collectionResultsCarryIdAndName() throws Exception {
        var results = api().searchCollections("OpenSSL");
        assertEquals(1, results.size());
        assertEquals(Long.valueOf(42), results.get(0).getCollectionId());
        assertEquals("OpenSSL builds", results.get(0).getCollectionName());
    }

    private static String recorded(String name) throws IOException {
        try (InputStream in = SdkRecordedResponseTest.class.getResourceAsStream("/sdk-responses/" + name)) {
            if (in == null) {
                throw new IOException("missing recorded response " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}

package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.model.BatchFunctionSignatureEntry;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.FunctionSignatureBatch;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/// Tests for {@link FunctionSignatureService}, which batches reads of `/v3/functions/signatures`.
public class FunctionSignatureServiceTest {

    /// Records what the service asked for and answers with one entry per requested id.
    private static class RecordingApi extends UnimplementedAPI {
        final List<List<FunctionID>> requests = new ArrayList<>();
        final List<Boolean> includeDataTypesFlags = new ArrayList<>();

        @Override
        public FunctionSignatureBatch listFunctionSignatures(List<FunctionID> functionIDs, boolean includeDataTypes) {
            requests.add(List.copyOf(functionIDs));
            includeDataTypesFlags.add(includeDataTypes);
            List<BatchFunctionSignatureEntry> items = functionIDs.stream().map(id -> {
                var entry = new BatchFunctionSignatureEntry();
                entry.setAnalysisId(1L);
                entry.setFunctionId(id.value());
                entry.setFunctionName("f" + id.value());
                entry.setHasSignature(id.value() % 2 == 0);
                entry.setParameters(List.of());
                return entry;
            }).toList();
            var type = new ServerDataType(id(functionIDs), "", "int", ServerDataType.Kind.BASE,
                    4L, "AUTO", false, null, null, null);
            return new FunctionSignatureBatch(items, Map.of(new AnalysisID(1), List.of(type)));
        }

        private static long id(List<FunctionID> ids) {
            return ids.isEmpty() ? 0 : ids.get(0).value();
        }
    }

    private static List<FunctionID> ids(int count) {
        return IntStream.rangeClosed(1, count).mapToObj(i -> new FunctionID(i)).toList();
    }

    /// The ids ride in the query string, so a whole-binary request has to be chunked or the request
    /// URI overflows (HTTP 414).
    @Test
    public void chunksLargeIdListsIntoBatchesOfFifty() {
        var api = new RecordingApi();
        var batch = new FunctionSignatureService(api).getMany(ids(120));

        assertEquals(3, api.requests.size());
        assertEquals(50, api.requests.get(0).size());
        assertEquals(50, api.requests.get(1).size());
        assertEquals(20, api.requests.get(2).size());
        assertEquals("every requested id is answered for", 120, batch.items().size());
    }

    @Test
    public void mergesDataTypesFromEveryChunk() {
        var api = new RecordingApi();
        var batch = new FunctionSignatureService(api).getMany(ids(120));

        assertEquals(1, batch.dataTypes().size());
        assertEquals("one type per chunk, all under the same analysis",
                3, batch.dataTypesFor(new AnalysisID(1)).size());
    }

    @Test
    public void dedupesRepeatedIds() {
        var api = new RecordingApi();
        new FunctionSignatureService(api).getMany(List.of(
                new FunctionID(1), new FunctionID(1), new FunctionID(2)));

        assertEquals(1, api.requests.size());
        assertEquals(List.of(new FunctionID(1), new FunctionID(2)), api.requests.get(0));
    }

    @Test
    public void emptyRequestDoesNotHitTheApi() {
        var api = new RecordingApi();
        var batch = new FunctionSignatureService(api).getMany(List.of());

        assertTrue(api.requests.isEmpty());
        assertTrue(batch.items().isEmpty());
    }

    /// A presence check does not need the type closure attached, which is far cheaper to fetch.
    @Test
    public void presenceOnlyReadsSkipDataTypes() {
        var api = new RecordingApi();
        new FunctionSignatureService(api).getMany(ids(2), false);

        assertEquals(List.of(false), api.includeDataTypesFlags);
    }

    @Test
    public void getReturnsOnlyFunctionsTheServerHasASignatureFor() {
        var service = new FunctionSignatureService(new RecordingApi());

        // The stub reports a signature for even ids only.
        var present = service.get(new FunctionID(2));
        assertTrue(present.isPresent());
        assertEquals("f2", present.get().entry().getFunctionName());
        assertFalse("the analysis' types come along with the signature",
                present.get().dataTypes().isEmpty());

        assertTrue(service.get(new FunctionID(3)).isEmpty());
    }
}

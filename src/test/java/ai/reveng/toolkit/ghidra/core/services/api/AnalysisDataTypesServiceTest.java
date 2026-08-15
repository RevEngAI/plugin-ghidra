package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.AnalysisDataTypesService.TypeKey;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/// Tests for {@link AnalysisDataTypesService}, which owns an analysis' `data_type_id` namespace.
public class AnalysisDataTypesServiceTest {

    /// Serves `total` types, one page at a time, and records the paging it was asked for.
    private static class PagingApi extends UnimplementedAPI {
        final List<long[]> pages = new ArrayList<>();
        private final int total;
        int calls = 0;

        PagingApi(int total) {
            this.total = total;
        }

        @Override
        public List<ServerDataType> listAnalysisDataTypes(AnalysisID analysisID, long offset, long limit) {
            calls++;
            pages.add(new long[]{offset, limit});
            return IntStream.range(0, (int) Math.max(0, Math.min(limit, total - offset)))
                    .mapToObj(i -> type(offset + i))
                    .toList();
        }

        private static ServerDataType type(long id) {
            return new ServerDataType(id, "ns", "T" + id, ServerDataType.Kind.STRUCT,
                    8L, "AUTO", true, null, null, new ServerDataType.StructDefinition(List.of()));
        }
    }

    @Test
    public void pagesUntilTheServerRunsOut() {
        var api = new PagingApi(1200);
        var catalogue = new AnalysisDataTypesService(api).sync(new AnalysisID(1));

        assertEquals(1200, catalogue.size());
        assertEquals(3, api.calls);
        assertEquals(0, api.pages.get(0)[0]);
        assertEquals(500, api.pages.get(0)[1]);
        assertEquals(500, api.pages.get(1)[0]);
        assertEquals(1000, api.pages.get(2)[0]);
    }

    /// A final page that exactly fills the limit still needs one more request to learn it was the
    /// last one.
    @Test
    public void stopsOnTheFirstEmptyPage() {
        var api = new PagingApi(1000);
        var catalogue = new AnalysisDataTypesService(api).sync(new AnalysisID(1));

        assertEquals(1000, catalogue.size());
        assertEquals(3, api.calls);
    }

    @Test
    public void resolvesNamespaceNameAndKindToAnId() {
        var service = new AnalysisDataTypesService(new PagingApi(3));
        var analysis = new AnalysisID(1);

        assertEquals(java.util.Optional.of(2L),
                service.idOf(analysis, new TypeKey("ns", "T2", ServerDataType.Kind.STRUCT)));
        // Kind is part of the identity: the same name of another kind is a different type.
        assertTrue(service.idOf(analysis, new TypeKey("ns", "T2", ServerDataType.Kind.UNION)).isEmpty());
        assertTrue(service.idOf(analysis, new TypeKey("other", "T2", ServerDataType.Kind.STRUCT)).isEmpty());
    }

    @Test
    public void cachesTheCatalogueUntilInvalidated() {
        var api = new PagingApi(3);
        var service = new AnalysisDataTypesService(api);
        var analysis = new AnalysisID(1);

        service.catalogue(analysis);
        int afterFirst = api.calls;
        service.catalogue(analysis);
        assertEquals("second read is served from the cache", afterFirst, api.calls);

        service.invalidate(analysis);
        service.catalogue(analysis);
        assertTrue("invalidating forces a re-read", api.calls > afterFirst);
    }

    @Test
    public void looksTypesUpById() {
        var service = new AnalysisDataTypesService(new PagingApi(3));
        var type = service.get(new AnalysisID(1), 1L);

        assertTrue(type.isPresent());
        assertEquals("T1", type.get().name());
        assertTrue(service.get(new AnalysisID(1), 99L).isEmpty());
    }
}

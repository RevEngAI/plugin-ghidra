package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.model.CreateAnalysisDataTypesInputBody;
import ai.reveng.model.UpdateAnalysisDataTypesInputBody;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisDataTypesService.TypeKey;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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

    /// Serves a fixed catalogue, records every write, and assigns ids to created types the way the
    /// server does.
    private static class WritingApi extends UnimplementedAPI {
        final List<String> calls = new ArrayList<>();
        final List<CreateAnalysisDataTypesInputBody> creates = new ArrayList<>();
        final List<UpdateAnalysisDataTypesInputBody> updates = new ArrayList<>();
        private final List<ServerDataType> existing;
        private long nextId = 1000;

        WritingApi(List<ServerDataType> existing) {
            this.existing = existing;
        }

        @Override
        public List<ServerDataType> listAnalysisDataTypes(AnalysisID analysisID, long offset, long limit) {
            calls.add("list");
            return offset == 0 ? existing : List.of();
        }

        @Override
        public List<ServerDataType> createAnalysisDataTypes(AnalysisID analysisID,
                                                            CreateAnalysisDataTypesInputBody request) {
            calls.add("create");
            creates.add(request);
            List<ServerDataType> created = new ArrayList<>();
            for (var entry : request.getDataTypes()) {
                created.add(stored(entry.getActualInstance(), nextId++));
            }
            return created;
        }

        @Override
        public List<ServerDataType> updateAnalysisDataTypes(AnalysisID analysisID,
                                                            UpdateAnalysisDataTypesInputBody request) {
            calls.add("update");
            updates.add(request);
            return List.of();
        }

        /// Rebuilds the entry the server would have stored, which is all the service reads back.
        private static ServerDataType stored(Object created, long id) {
            String namespace = invoke(created, "getNamespace");
            String name = invoke(created, "getName");
            String kind = String.valueOf(invokeObject(created, "getKind"));
            return new ServerDataType(id, namespace == null ? "" : namespace, name,
                    ServerDataType.Kind.fromJson(kind), null, "USER", false, null, null, null);
        }

        private static String invoke(Object target, String method) {
            Object value = invokeObject(target, method);
            return value == null ? null : value.toString();
        }

        private static Object invokeObject(Object target, String method) {
            try {
                return target.getClass().getMethod(method).invoke(target);
            } catch (ReflectiveOperationException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static ServerDataType serverType(long id, String namespace, String name, ServerDataType.Kind kind) {
        return new ServerDataType(id, namespace, name, kind, null, "AUTO", true, null, null, null);
    }

    private static StructureDataType packetHeader() {
        var header = new StructureDataType("packet_header", 0);
        header.add(new IntegerDataType(), "length", null);
        header.add(new CharDataType(), "kind", null);
        return header;
    }

    /// The heart of it: a reactive push repeats on every edit, so a type the analysis already has
    /// must be resolved to its existing id and never posted again. Duplicating a type on each edit
    /// would corrupt the analysis, not merely waste a request.
    @Test
    public void resolvesExistingTypesInsteadOfCreatingThemAgain() throws Exception {
        var header = packetHeader();
        var api = new WritingApi(List.of(
                serverType(7L, "", "packet_header", ServerDataType.Kind.STRUCT),
                serverType(8L, "", "int", ServerDataType.Kind.BASE),
                serverType(9L, "", "char", ServerDataType.Kind.BASE)));
        var service = new AnalysisDataTypesService(api);

        var ids = service.ensure(new AnalysisID(1), List.of(header));

        assertFalse("nothing was missing, so nothing may be created", api.calls.contains("create"));
        assertEquals(Long.valueOf(7),
                ids.get(new TypeKey("", "packet_header", ServerDataType.Kind.STRUCT)));
        assertEquals(Long.valueOf(8), ids.get(new TypeKey("", "int", ServerDataType.Kind.BASE)));
    }

    /// The same push run twice must not create anything the second time round: the ids the first
    /// run minted are folded into the catalogue and resolved from there.
    @Test
    public void repeatedPushesCreateNothingTheSecondTime() throws Exception {
        var api = new WritingApi(List.of());
        var service = new AnalysisDataTypesService(api);
        var analysis = new AnalysisID(1);

        var first = service.ensure(analysis, List.of(packetHeader()));
        int createsAfterFirst = api.creates.size();
        var second = service.ensure(analysis, List.of(packetHeader()));

        assertTrue("the first push had to create the types", createsAfterFirst > 0);
        assertEquals("the second push resolves them instead", createsAfterFirst, api.creates.size());
        assertEquals("and lands on the same ids", first, second);
    }

    /// A `Create*` body has no `data_type_id`, so nothing in a batch can point at anything else in
    /// it. The types are therefore created empty to obtain ids, and the definitions written after.
    @Test
    public void createsInTwoPhasesWithTheUpdateCarryingTheAssignedIds() throws Exception {
        var api = new WritingApi(List.of());
        var service = new AnalysisDataTypesService(api);

        var ids = service.ensure(new AnalysisID(1), List.of(packetHeader()));

        assertEquals("list, then create, then update",
                List.of("list", "create", "update"), api.calls);

        var created = api.creates.get(0).getDataTypes();
        var createdStruct = created.stream()
                .map(entry -> entry.getActualInstance())
                .filter(instance -> instance instanceof ai.reveng.model.CreateStructDataType)
                .map(instance -> (ai.reveng.model.CreateStructDataType) instance)
                .findFirst().orElseThrow();
        assertTrue("phase one carries no members to point at",
                createdStruct.getDefinition().getMembers().isEmpty());

        var updated = api.updates.get(0).getDataTypes().stream()
                .map(entry -> entry.getActualInstance())
                .filter(instance -> instance instanceof ai.reveng.model.UpdateStructDataType)
                .map(instance -> (ai.reveng.model.UpdateStructDataType) instance)
                .findFirst().orElseThrow();
        var structId = ids.get(new TypeKey("", "packet_header", ServerDataType.Kind.STRUCT));
        assertEquals("phase two names the id the server assigned", structId, updated.getDataTypeId());
        assertEquals(2, updated.getDefinition().getMembers().size());
        assertEquals("and its members point at ids from the same pass",
                ids.get(new TypeKey("", "int", ServerDataType.Kind.BASE)),
                updated.getDefinition().getMembers().get(0).getDataTypeId());
    }

    /// Base types complete in the create phase — they carry no definition, so there is nothing for
    /// the update to say about them.
    @Test
    public void kindsWithoutADefinitionNeedNoSecondPhase() throws Exception {
        var api = new WritingApi(List.of());
        var service = new AnalysisDataTypesService(api);

        service.ensure(new AnalysisID(1), List.of(new IntegerDataType()));

        assertEquals(List.of("list", "create"), api.calls);
    }

    /// Every namespace the closure was written under, whichever create batch it went out in.
    private static List<String> createdNamespaces(WritingApi api, String name) {
        return api.creates.stream()
                .flatMap(request -> request.getDataTypes().stream())
                .map(entry -> entry.getActualInstance())
                .filter(instance -> name.equals(WritingApi.invoke(instance, "getName")))
                .map(instance -> WritingApi.invoke(instance, "getNamespace"))
                .toList();
    }

    /// A Ghidra category is not only ever a server namespace. `/windows_vs12_32/DWORD` comes out of
    /// one of Ghidra's own data-type archives, not out of this analysis, so reading that category as
    /// a namespace would miss the `DWORD` the analysis holds at the root and create a second one —
    /// on every edit, because the push is reactive.
    @Test
    public void aTypeInAGhidraArchiveCategoryResolvesToTheServerEntryAtTheRoot() throws Exception {
        var dword = new TypedefDataType(new CategoryPath("/windows_vs12_32"), "DWORD",
                new UnsignedIntegerDataType());
        var api = new WritingApi(List.of(
                serverType(7L, "", "DWORD", ServerDataType.Kind.TYPEDEF),
                serverType(8L, "", "uint", ServerDataType.Kind.BASE)));
        var service = new AnalysisDataTypesService(api);

        var ids = service.ensure(new AnalysisID(1), List.of(dword));

        assertFalse("the analysis already has this type, so nothing may be created",
                api.calls.contains("create"));
        assertEquals("and the Ghidra type resolves to it", Long.valueOf(7),
                ids.get(new TypeKey("windows_vs12_32", "DWORD", ServerDataType.Kind.TYPEDEF)));
    }

    /// The same type when the analysis does not have it yet: it is created once, at the root, and
    /// the next push resolves what the first one wrote rather than creating it again.
    @Test
    public void aTypeInAGhidraArchiveCategoryIsCreatedOnceAtTheRoot() throws Exception {
        var api = new WritingApi(List.of());
        var service = new AnalysisDataTypesService(api);
        var analysis = new AnalysisID(1);

        var first = service.ensure(analysis, List.of(
                new TypedefDataType(new CategoryPath("/windows_vs12_32"), "DWORD",
                        new UnsignedIntegerDataType())));

        assertEquals("created at the root, not under the Ghidra archive's category",
                List.of(""), createdNamespaces(api, "DWORD"));

        int createsAfterFirst = api.creates.size();
        var second = service.ensure(analysis, List.of(
                new TypedefDataType(new CategoryPath("/windows_vs12_32"), "DWORD",
                        new UnsignedIntegerDataType())));

        assertEquals("the second push resolves it instead", createsAfterFirst, api.creates.size());
        assertEquals("and lands on the same id",
                first.get(new TypeKey("windows_vs12_32", "DWORD", ServerDataType.Kind.TYPEDEF)),
                second.get(new TypeKey("windows_vs12_32", "DWORD", ServerDataType.Kind.TYPEDEF)));
    }

    /// The root is only ever fallen back to for a namespace the analysis holds no such type in. Two
    /// distinct types that share a name in different server namespaces are both in the catalogue
    /// under their own namespace, so both resolve there and neither is flattened onto the other.
    @Test
    public void sameNameInDifferentServerNamespacesStillResolvesIndependently() throws Exception {
        var fromLibA = new StructureDataType(new CategoryPath("/libA"), "Config", 0);
        fromLibA.add(new IntegerDataType(), "a", null);
        var fromLibB = new StructureDataType(new CategoryPath("/libB"), "Config", 0);
        fromLibB.add(new CharDataType(), "b", null);

        var api = new WritingApi(List.of(
                serverType(11L, "libA", "Config", ServerDataType.Kind.STRUCT),
                serverType(22L, "libB", "Config", ServerDataType.Kind.STRUCT),
                serverType(33L, "", "Config", ServerDataType.Kind.STRUCT),
                serverType(8L, "", "int", ServerDataType.Kind.BASE),
                serverType(9L, "", "char", ServerDataType.Kind.BASE)));
        var service = new AnalysisDataTypesService(api);

        var ids = service.ensure(new AnalysisID(1), List.of(fromLibA, fromLibB));

        assertFalse("both are already known", api.calls.contains("create"));
        assertEquals(Long.valueOf(11), ids.get(new TypeKey("libA", "Config", ServerDataType.Kind.STRUCT)));
        assertEquals(Long.valueOf(22), ids.get(new TypeKey("libB", "Config", ServerDataType.Kind.STRUCT)));

        // And each is written back to its own entry, still in its own namespace.
        var byId = api.updates.get(0).getDataTypes().stream()
                .map(entry -> (ai.reveng.model.UpdateStructDataType) entry.getActualInstance())
                .collect(java.util.stream.Collectors.toMap(
                        ai.reveng.model.UpdateStructDataType::getDataTypeId,
                        ai.reveng.model.UpdateStructDataType::getNamespace));
        assertEquals("libA", byId.get(11L));
        assertEquals("libB", byId.get(22L));
    }

    /// A namespace the analysis does have a type in is a server namespace, so it is kept — this is
    /// what makes a type the plugin pulled from the server resolve back to the entry it came from.
    @Test
    public void aNamespaceTheAnalysisAlreadyUsesIsKept() throws Exception {
        var file = new StructureDataType(new CategoryPath("/DWARF/stdio.h"), "FILE", 0);
        file.add(new IntegerDataType(), "fd", null);

        var api = new WritingApi(List.of(
                serverType(5L, "DWARF::stdio.h", "FILE", ServerDataType.Kind.STRUCT),
                serverType(8L, "", "int", ServerDataType.Kind.BASE)));
        var service = new AnalysisDataTypesService(api);

        var ids = service.ensure(new AnalysisID(1), List.of(file));

        assertFalse(api.calls.contains("create"));
        assertEquals(Long.valueOf(5),
                ids.get(new TypeKey("DWARF::stdio.h", "FILE", ServerDataType.Kind.STRUCT)));
        var updated = (ai.reveng.model.UpdateStructDataType)
                api.updates.get(0).getDataTypes().get(0).getActualInstance();
        assertEquals("the update must not move the entry out of its namespace",
                "DWARF::stdio.h", updated.getNamespace());
    }

    /// A local type the analysis has never seen is still created exactly once, and the second push
    /// resolves it — the reactive case, where a miss would duplicate on every edit.
    @Test
    public void aGenuinelyNewLocalTypeIsCreatedOnceAndOnlyOnce() throws Exception {
        var api = new WritingApi(List.of());
        var service = new AnalysisDataTypesService(api);
        var analysis = new AnalysisID(1);

        service.ensure(analysis, List.of(packetHeader()));
        service.ensure(analysis, List.of(packetHeader()));

        assertEquals("exactly one create of the struct, over both pushes",
                List.of(""), createdNamespaces(api, "packet_header"));
    }

    /// The write endpoints cap a request at 100 types, so a large closure has to be chunked.
    @Test
    public void chunksLargeCreateBatches() throws Exception {
        var api = new WritingApi(List.of());
        var service = new AnalysisDataTypesService(api);

        var container = new StructureDataType("Big", 0);
        for (int i = 0; i < 150; i++) {
            container.add(new StructureDataType("Member" + i, 4), "m" + i, null);
        }

        service.ensure(new AnalysisID(1), List.of(container));

        assertTrue("more than one create request", api.creates.size() > 1);
        api.creates.forEach(request ->
                assertTrue("no batch exceeds the endpoint limit", request.getDataTypes().size() <= 100));
    }
}

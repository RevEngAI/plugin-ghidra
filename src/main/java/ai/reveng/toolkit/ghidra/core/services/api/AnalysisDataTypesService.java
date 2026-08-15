package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ghidra.program.model.data.DataType;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/// Owns an analysis' `data_type_id` namespace.
///
/// Type ids are only meaningful inside the analysis that minted them, and the server hands them out
/// rather than accepting a name. Anything that needs to talk about a type — resolving a signature's
/// references, or later naming a type to write back — has to go through the analysis' catalogue,
/// which is what this builds and caches.
///
/// It is also the only thing that mints or mutates ids: {@link #ensure} takes Ghidra types and
/// hands back the analysis' id for each of them, creating what the analysis does not have yet.
/// Everything downstream — a function signature naming its parameter types, say — consumes those
/// ids and never invents one.
public final class AnalysisDataTypesService {

    /// `GET /v3/analyses/{analysis_id}/data-types` is paged; 500 is the largest page the endpoint
    /// serves, and a binary's whole type catalogue is routinely in the thousands.
    private static final long PAGE_SIZE = 500;

    /// Guards against an endless loop if the server ever stops advancing the offset.
    private static final int MAX_PAGES = 200;

    /// The create and update endpoints each cap a request at 100 types.
    private static final int WRITE_BATCH_SIZE = 100;

    private final TypedApiInterface api;
    private final Map<AnalysisID, Catalogue> cache = new ConcurrentHashMap<>();

    public AnalysisDataTypesService(TypedApiInterface api) {
        this.api = api;
    }

    /// Identifies a type the way a human does — by scope, name and kind — for the cases where an id
    /// is not known yet. Two types in one analysis never share all three.
    public record TypeKey(String namespace, String name, ServerDataType.Kind kind) {
        public static TypeKey of(ServerDataType type) {
            return new TypeKey(type.namespace() == null ? "" : type.namespace(), type.name(), type.kind());
        }
    }

    /// Every type of one analysis, indexed both ways.
    public record Catalogue(Map<Long, ServerDataType> byId, Map<TypeKey, Long> idByKey) {

        public static Catalogue of(Collection<ServerDataType> types) {
            Map<Long, ServerDataType> byId = new LinkedHashMap<>();
            Map<TypeKey, Long> idByKey = new LinkedHashMap<>();
            for (ServerDataType type : types) {
                if (byId.putIfAbsent(type.id(), type) == null) {
                    idByKey.putIfAbsent(TypeKey.of(type), type.id());
                }
            }
            return new Catalogue(Collections.unmodifiableMap(byId), Collections.unmodifiableMap(idByKey));
        }

        public static Catalogue empty() {
            return new Catalogue(Map.of(), Map.of());
        }

        /// The id of `(namespace, name, kind)`, or empty if this analysis has no such type.
        public Optional<Long> idOf(TypeKey key) {
            return Optional.ofNullable(idByKey.get(key));
        }

        public Optional<ServerDataType> get(long dataTypeId) {
            return Optional.ofNullable(byId.get(dataTypeId));
        }

        public Collection<ServerDataType> all() {
            return byId.values();
        }

        public int size() {
            return byId.size();
        }

        /// The catalogue with `types` folded in, the newer entry winning. Used to fold a write's
        /// response back in so the next resolve sees what was just created without re-paging.
        public Catalogue with(Collection<ServerDataType> types) {
            if (types.isEmpty()) {
                return this;
            }
            Map<Long, ServerDataType> mergedById = new LinkedHashMap<>(byId);
            Map<TypeKey, Long> mergedIdByKey = new LinkedHashMap<>(idByKey);
            for (ServerDataType type : types) {
                mergedById.put(type.id(), type);
                mergedIdByKey.put(TypeKey.of(type), type.id());
            }
            return new Catalogue(Collections.unmodifiableMap(mergedById),
                    Collections.unmodifiableMap(mergedIdByKey));
        }
    }

    /// Page the analysis' types in and cache the result.
    public Catalogue sync(AnalysisID analysisID) {
        List<ServerDataType> collected = new ArrayList<>();
        for (int page = 0; page < MAX_PAGES; page++) {
            List<ServerDataType> batch = api.listAnalysisDataTypes(analysisID, page * PAGE_SIZE, PAGE_SIZE);
            if (batch.isEmpty()) {
                break;
            }
            collected.addAll(batch);
            if (batch.size() < PAGE_SIZE) {
                break;
            }
        }
        Catalogue catalogue = Catalogue.of(collected);
        cache.put(analysisID, catalogue);
        return catalogue;
    }

    /// The cached catalogue, syncing first if this analysis has not been read yet.
    public Catalogue catalogue(AnalysisID analysisID) {
        Catalogue cached = cache.get(analysisID);
        return cached != null ? cached : sync(analysisID);
    }

    /// Resolve `(namespace, name, kind)` to the analysis' id for it.
    public Optional<Long> idOf(AnalysisID analysisID, TypeKey key) {
        return catalogue(analysisID).idOf(key);
    }

    public Optional<ServerDataType> get(AnalysisID analysisID, long dataTypeId) {
        return catalogue(analysisID).get(dataTypeId);
    }

    /// Make sure the analysis holds every type reachable from `roots`, and answer with the id of
    /// each one.
    ///
    /// Two properties matter here, and both are correctness rather than economy.
    ///
    /// **Resolve before create.** Every type in the closure is first looked up in the analysis'
    /// catalogue by `(namespace, name, kind)`; only the genuine gaps are created. A push is
    /// reactive and repeats on every edit, so a version that created unconditionally would fill the
    /// analysis with duplicates of the same type.
    ///
    /// **Create in two phases.** A `Create*` body carries no `data_type_id`, so nothing in a batch
    /// can refer to anything else in that same batch. The gaps are therefore created with empty
    /// definitions purely to obtain ids, and every definition — the ones just created and the ones
    /// that already existed — is then written in a second request, by which time every reference
    /// resolves. Kinds that carry no definition are finished after the first phase.
    ///
    /// Last write wins: the server no longer versions types for optimistic concurrency, so there is
    /// no conflict detection and no retry. Failures surface as {@link ApiException}.
    ///
    /// The returned map is keyed by the Ghidra-derived {@link GhidraDataTypeEncoder#keyOf} of every
    /// type in the closure, so a caller can look an id up with nothing but the Ghidra type in hand.
    public Map<TypeKey, Long> ensure(AnalysisID analysisID, Collection<DataType> roots) throws ApiException {
        List<DataType> closure = GhidraDataTypeEncoder.closure(roots);
        if (closure.isEmpty()) {
            return Map.of();
        }

        Catalogue catalogue = catalogue(analysisID);
        Map<TypeKey, Long> ids = new LinkedHashMap<>();
        Map<TypeKey, DataType> missing = new LinkedHashMap<>();
        for (DataType type : closure) {
            TypeKey key = GhidraDataTypeEncoder.keyOf(type);
            catalogue.idOf(key).ifPresentOrElse(
                    id -> ids.put(key, id),
                    () -> missing.putIfAbsent(key, type));
        }

        if (!missing.isEmpty()) {
            for (ServerDataType created : create(analysisID, missing)) {
                ids.putIfAbsent(TypeKey.of(created), created.id());
            }
        }

        List<ai.reveng.model.UpdateDataTypeEntry> updates = new ArrayList<>();
        for (DataType type : closure) {
            Long id = ids.get(GhidraDataTypeEncoder.keyOf(type));
            if (id != null) {
                GhidraDataTypeEncoder.updateEntry(type, id, ids::get).ifPresent(updates::add);
            }
        }
        update(analysisID, updates);

        return Map.copyOf(ids);
    }

    /// `POST /v3/analyses/{analysis_id}/data-types` for types the analysis does not have, chunked to
    /// the endpoint's batch limit. Returns the created types as the server stored them, ids
    /// included.
    private List<ServerDataType> create(AnalysisID analysisID, Map<TypeKey, DataType> types) throws ApiException {
        List<ai.reveng.model.CreateDataTypeEntry> entries = types.values().stream()
                .map(GhidraDataTypeEncoder::createEntry)
                .toList();
        List<ServerDataType> created = new ArrayList<>();
        for (int start = 0; start < entries.size(); start += WRITE_BATCH_SIZE) {
            var body = new ai.reveng.model.CreateAnalysisDataTypesInputBody();
            body.setDataTypes(entries.subList(start, Math.min(start + WRITE_BATCH_SIZE, entries.size())));
            created.addAll(api.createAnalysisDataTypes(analysisID, body));
        }
        record(analysisID, created);
        return created;
    }

    /// `PUT /v3/analyses/{analysis_id}/data-types`, chunked to the endpoint's batch limit.
    ///
    /// The endpoint replaces a stored type in full, so a caller must send a complete definition —
    /// {@link GhidraDataTypeEncoder#updateEntry} declines to build one it cannot fill.
    public List<ServerDataType> update(AnalysisID analysisID,
                                       List<ai.reveng.model.UpdateDataTypeEntry> updates) throws ApiException {
        if (updates.isEmpty()) {
            return List.of();
        }
        List<ServerDataType> updated = new ArrayList<>();
        for (int start = 0; start < updates.size(); start += WRITE_BATCH_SIZE) {
            var body = new ai.reveng.model.UpdateAnalysisDataTypesInputBody();
            body.setDataTypes(updates.subList(start, Math.min(start + WRITE_BATCH_SIZE, updates.size())));
            updated.addAll(api.updateAnalysisDataTypes(analysisID, body));
        }
        record(analysisID, updated);
        return updated;
    }

    /// Fold a write's response into the cached catalogue, so the next push resolves what this one
    /// created instead of creating it again.
    private void record(AnalysisID analysisID, Collection<ServerDataType> types) {
        if (types.isEmpty()) {
            return;
        }
        cache.compute(analysisID, (id, current) -> (current == null ? Catalogue.empty() : current).with(types));
    }

    /// Drop a cached catalogue, or all of them when `analysisID` is null.
    public void invalidate(@Nullable AnalysisID analysisID) {
        if (analysisID == null) {
            cache.clear();
        } else {
            cache.remove(analysisID);
        }
    }
}

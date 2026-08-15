package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;

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
public final class AnalysisDataTypesService {

    /// `GET /v3/analyses/{analysis_id}/data-types` is paged; 500 is the largest page the endpoint
    /// serves, and a binary's whole type catalogue is routinely in the thousands.
    private static final long PAGE_SIZE = 500;

    /// Guards against an endless loop if the server ever stops advancing the offset.
    private static final int MAX_PAGES = 200;

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

    /// Drop a cached catalogue, or all of them when `analysisID` is null.
    public void invalidate(@Nullable AnalysisID analysisID) {
        if (analysisID == null) {
            cache.clear();
        } else {
            cache.remove(analysisID);
        }
    }
}

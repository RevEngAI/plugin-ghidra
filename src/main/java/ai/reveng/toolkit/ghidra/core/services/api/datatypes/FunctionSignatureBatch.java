package ai.reveng.toolkit.ghidra.core.services.api.datatypes;

import ai.reveng.model.BatchFunctionSignatureEntry;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/// One `GET /v3/functions/signatures` response.
///
/// The endpoint accepts function ids across analyses, so the data types come back grouped by the
/// analysis that owns them: `data_type_id` is only unique within an analysis, and a signature's
/// `return_data_type_id` / parameter `data_type_id` are resolved against the group named by the
/// entry's own `analysis_id`.
///
/// @param items     one entry per requested function id the caller may see. `has_signature` says
///                  whether the server actually holds a signature for it.
/// @param dataTypes every type referenced by the entries above, keyed by owning analysis. Empty
///                  when the request did not ask for data types.
public record FunctionSignatureBatch(
        List<BatchFunctionSignatureEntry> items,
        Map<AnalysisID, List<ServerDataType>> dataTypes) {

    public static FunctionSignatureBatch empty() {
        return new FunctionSignatureBatch(List.of(), Map.of());
    }

    /// Combine two responses. Used to stitch the chunks of a batched request back together.
    public FunctionSignatureBatch merge(FunctionSignatureBatch other) {
        List<BatchFunctionSignatureEntry> mergedItems = new ArrayList<>(items);
        mergedItems.addAll(other.items);

        Map<AnalysisID, List<ServerDataType>> mergedTypes = new LinkedHashMap<>();
        dataTypes.forEach((analysis, types) -> mergedTypes.put(analysis, new ArrayList<>(types)));
        other.dataTypes.forEach((analysis, types) ->
                mergedTypes.computeIfAbsent(analysis, ignored -> new ArrayList<>()).addAll(types));

        return new FunctionSignatureBatch(mergedItems, mergedTypes);
    }

    public List<ServerDataType> dataTypesFor(AnalysisID analysisID) {
        return dataTypes.getOrDefault(analysisID, List.of());
    }
}

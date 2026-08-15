package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.BatchFunctionSignatureEntry;
import ai.reveng.model.FunctionSignatureVersion;
import ai.reveng.model.UpdateFunctionSignatureInputBody;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.FunctionSignatureBatch;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ghidra.util.Msg;

import java.util.List;
import java.util.Optional;

/// Reads function signatures, and the data types they reference, from `/v3/functions/signatures`.
///
/// The endpoint takes function ids from any number of analyses at once and answers with the
/// signatures plus, optionally, every type those signatures point at — grouped by the analysis that
/// owns the ids. That makes a whole-binary read one round trip per chunk instead of one per
/// function, and removes the old "generate types, then poll until ready" dance: the server derives
/// signatures when the analysis completes.
///
/// Writing goes the other way and is deliberately singular: {@link #put} is one request for one
/// function. It consumes `data_type_id`s and never creates them — a signature that names a type the
/// analysis does not have yet is the caller's problem to solve first, by going through
/// {@link AnalysisDataTypesService#ensure}, which owns that namespace.
public final class FunctionSignatureService {

    /// The function ids ride in the query string, so a whole-binary request overflows the request
    /// URI (HTTP 414) unless it is chunked.
    private static final int DATA_TYPES_BATCH_SIZE = 50;

    private final TypedApiInterface api;

    public FunctionSignatureService(TypedApiInterface api) {
        this.api = api;
    }

    /// One function's signature together with the types it references.
    public record Resolved(BatchFunctionSignatureEntry entry, List<ServerDataType> dataTypes) {}

    /// The signature of a single function, or empty when the server holds none for it.
    public Optional<Resolved> get(FunctionID functionID) {
        FunctionSignatureBatch batch = getMany(List.of(functionID));
        return batch.items().stream()
                .filter(entry -> Boolean.TRUE.equals(entry.getHasSignature()))
                .findFirst()
                .map(entry -> new Resolved(entry, batch.dataTypesFor(analysisOf(entry))));
    }

    /// Signatures for many functions, with their data types. Ids may span analyses.
    public FunctionSignatureBatch getMany(List<FunctionID> functionIDs) {
        return getMany(functionIDs, true);
    }

    /// As {@link #getMany(List)}, but `includeDataTypes` false when the caller only needs to know
    /// which functions have a signature at all — that answer is far cheaper without the type
    /// closure attached.
    public FunctionSignatureBatch getMany(List<FunctionID> functionIDs, boolean includeDataTypes) {
        if (functionIDs == null || functionIDs.isEmpty()) {
            return FunctionSignatureBatch.empty();
        }
        List<FunctionID> ids = functionIDs.stream().distinct().toList();
        FunctionSignatureBatch merged = FunctionSignatureBatch.empty();
        for (int start = 0; start < ids.size(); start += DATA_TYPES_BATCH_SIZE) {
            List<FunctionID> chunk = ids.subList(start, Math.min(start + DATA_TYPES_BATCH_SIZE, ids.size()));
            merged = merged.merge(api.listFunctionSignatures(chunk, includeDataTypes));
        }
        return merged;
    }

    /// Write one function's signature. True when the server accepted it.
    ///
    /// `PUT .../signature` edits an extracted signature and nothing else: a function the server has
    /// no signature for — `has_signature` false, which is the normal state of a thunk, an external
    /// function, or anything in an analysis where type extraction never ran — is answered with 404.
    /// That is not a failure worth telling the user about. The push is reactive on a short debounce,
    /// so a warning per keystroke on an unextracted function would be pure noise; it is logged at
    /// debug and reported as "not written".
    public boolean put(AnalysisID analysisID, FunctionID functionID,
                       UpdateFunctionSignatureInputBody signature) throws ApiException {
        try {
            api.updateFunctionSignature(analysisID, functionID, signature);
            return true;
        } catch (ApiException e) {
            if (e.getCode() == 404) {
                Msg.debug(FunctionSignatureService.class,
                        "Skipping signature push for function %d: the server holds no extracted signature for it"
                                .formatted(functionID.value()));
                return false;
            }
            throw e;
        }
    }

    /// The recorded versions of one function's signature, newest first as the server orders them.
    public List<FunctionSignatureVersion> history(AnalysisID analysisID, FunctionID functionID) {
        return api.getFunctionSignatureHistory(analysisID, functionID);
    }

    private static AnalysisID analysisOf(BatchFunctionSignatureEntry entry) {
        return new AnalysisID(Math.toIntExact(entry.getAnalysisId()));
    }
}

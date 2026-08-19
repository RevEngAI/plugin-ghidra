package ai.reveng.toolkit.ghidra.core.services.api;

import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.FunctionSignatureBatch;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;

import javax.annotation.Nullable;

import ai.reveng.invoker.ApiException;


/**
 * Service for interacting with the RevEngAi API
 * This is a generic Java Interface and should not use any Ghidra specific classes
 *
 * It aims to stick close to the API functions themselves.
 * E.g. if a feature is implemented via two API calls, it should be implemented as two methods here.
 * "Typed" refers to using special types for IDs like {@link AnalysisID} and {@link FunctionID}, rather than raw integers or strings.
 * Wrapping this feature into one conceptual method should then happen inside the {@link ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService}
 * This exists as an interface so tests can mock it out more easily.
 *
 */
public interface TypedApiInterface {

    /// Data type to represent the RevEng.AI API concept of a function ID
    record FunctionID(long value){}

    /// This is a special box type for an analysis ID
    /// It enforces that the integer is specifically an analysis ID,
    /// and it implies that the user has (at least read) access to this ID
    record AnalysisID(int id) {}
    // TODO: could add a box type for an analysis that the user has _write_ access to

    /// Data type for all reveng API responses or parameters that are a binary hash (as returned by the upload method)
    /// The existence of a BinaryHash implies that there is a binary with this hash on the server
    record BinaryHash(String sha256) {}

    default AnalysisID analyse(AnalysisOptionsBuilder options) throws ApiException {
        throw new UnsupportedOperationException("analyse not implemented yet");
    }

    default AnalysisStatus status(AnalysisID analysisID) throws ApiException {
        throw new UnsupportedOperationException("status not implemented yet");
    }

    default List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
        throw new UnsupportedOperationException("getFunctionInfo not implemented yet");
    }

    @Deprecated
    default List<FunctionInfo> getFunctionInfo(BinaryID binID) throws ApiException {
        return getFunctionInfo(getAnalysisIDfromBinaryID(binID));
    }

    @Deprecated
    default AnalysisStatus status(BinaryID binID) throws ApiException {
        throw new UnsupportedOperationException("status not implemented yet");
    };

    /**
     * https://docs.reveng.ai/#/Utility/get_search
     */
    @Deprecated
    default List<LegacyAnalysisResult> search(BinaryHash hash) {
        throw new UnsupportedOperationException("search not implemented yet");
    }


    default BinaryHash upload(Path binPath) throws FileNotFoundException, ai.reveng.invoker.ApiException {
        throw new UnsupportedOperationException("upload not implemented yet");
    }


    String getAnalysisLogs(AnalysisID analysisID);

    /// GET /v3/functions/signatures
    ///
    /// Signatures for the given functions, which may belong to different analyses, plus — when
    /// `includeDataTypes` is set — every data type those signatures reference, grouped by owning
    /// analysis. Callers should go through {@link FunctionSignatureService}, which chunks the ids.
    default FunctionSignatureBatch listFunctionSignatures(List<FunctionID> functionIDs, boolean includeDataTypes) {
        throw new UnsupportedOperationException("listFunctionSignatures not implemented yet");
    }

    /// GET /v3/analyses/{analysis_id}/data-types
    ///
    /// One page of an analysis' data types. Callers should go through
    /// {@link AnalysisDataTypesService}, which pages this into a catalogue.
    default List<ServerDataType> listAnalysisDataTypes(AnalysisID analysisID, long offset, long limit) {
        throw new UnsupportedOperationException("listAnalysisDataTypes not implemented yet");
    }

    /// GET /v3/analyses/{analysis_id}/functions/{function_id}/signature/history
    default List<FunctionSignatureVersion> getFunctionSignatureHistory(AnalysisID analysisID, FunctionID functionID) {
        throw new UnsupportedOperationException("getFunctionSignatureHistory not implemented yet");
    }

    @Deprecated
    default AnalysisID getAnalysisIDfromBinaryID(BinaryID binaryID) {
        throw new UnsupportedOperationException("getAnalysisIDfromBinaryID not implemented yet");
    }

    default AnalysisResult getInfoForAnalysis(AnalysisID id) {
        throw new UnsupportedOperationException("getInfoForAnalysis not implemented yet");
    }


    default boolean triggerAIDecompilationForFunctionID(FunctionID functionID) {
        throw new UnsupportedOperationException("triggerAIDecompilationForFunctionID not implemented yet");
    }

    default AIDecompilationStatus pollAIDecompileStatus(FunctionID functionID) {
        throw new UnsupportedOperationException("pollAIDecompileStatus not implemented yet");
    }

    default void triggerAIDecompilationInlineComments(FunctionID functionID) {
        throw new UnsupportedOperationException("triggerAIDecompilationInlineComments not implemented yet");
    }

    default void triggerAIDecompilationSummary(FunctionID functionID) {
        throw new UnsupportedOperationException("triggerAIDecompilationSummary not implemented yet");
    }

    /**
     * Tokenised view of an AI decompilation. The tokenised text mirrors the human-readable
     * decompilation but with renameable identifiers replaced by stable tokens, and carries the
     * value each token renders as, plus the caller's own overrides as a separate map, which is
     * how a displayed name is resolved back to the token to override.
     */
    default GetTokensResponse getAIDecompilationTokens(FunctionID functionID) throws ApiException {
        throw new UnsupportedOperationException("getAIDecompilationTokens not implemented yet");
    }

    /**
     * Override the display names of variables/types keyed by their tokens. The server re-renders
     * the decompilation with the overrides applied.
     */
    default UpsertOverridesData applyAIDecompilationOverrides(FunctionID functionID, java.util.Map<String, String> overrides) throws ApiException {
        throw new UnsupportedOperationException("applyAIDecompilationOverrides not implemented yet");
    }

    /**
     * Add or update the inline comment on a 1-indexed source line of the AI decompilation.
     */
    default void setAIDecompilationInlineComment(FunctionID functionID, long line, String comment) throws ApiException {
        throw new UnsupportedOperationException("setAIDecompilationInlineComment not implemented yet");
    }

    /**
     * Remove the inline comment on a 1-indexed source line of the AI decompilation.
     */
    default void deleteAIDecompilationInlineComment(FunctionID functionID, long line) throws ApiException {
        throw new UnsupportedOperationException("deleteAIDecompilationInlineComment not implemented yet");
    }

    /**
     * Canonicalise the given function names via the portal (PRO-3021). Returns a map from each input
     * name to its canonical form; names the server does not return are omitted.
     */
    default java.util.Map<String, String> canonicalizeFunctionNames(List<String> names) throws ApiException {
        throw new UnsupportedOperationException("canonicalizeFunctionNames not implemented yet");
    }

    /// POST /v3/analyses/{analysis_id}/data-types
    ///
    /// Create types the analysis does not have. The bodies carry no `data_type_id`; the server
    /// assigns one to each and returns the stored types. Callers should go through
    /// {@link AnalysisDataTypesService}, which resolves against the catalogue first and chunks the
    /// batch.
    default List<ServerDataType> createAnalysisDataTypes(AnalysisID analysisID,
                                                         CreateAnalysisDataTypesInputBody request) throws ApiException {
        throw new UnsupportedOperationException("createAnalysisDataTypes not implemented yet");
    }

    /// PUT /v3/analyses/{analysis_id}/data-types
    ///
    /// Replace stored types in full — a field left out of the request is cleared. Every body must
    /// name the `data_type_id` it replaces.
    default List<ServerDataType> updateAnalysisDataTypes(AnalysisID analysisID,
                                                         UpdateAnalysisDataTypesInputBody request) throws ApiException {
        throw new UnsupportedOperationException("updateAnalysisDataTypes not implemented yet");
    }

    /// PUT /v3/analyses/{analysis_id}/functions/{function_id}/signature
    ///
    /// Replace one function's parameters, return type and calling convention. Edit-only: a function
    /// the server has no extracted signature for is answered with 404. Callers should go through
    /// {@link FunctionSignatureService#put}, which treats that 404 as "nothing to edit".
    default void updateFunctionSignature(AnalysisID analysisID, FunctionID functionID,
                                         UpdateFunctionSignatureInputBody signature) throws ApiException {
        throw new UnsupportedOperationException("updateFunctionSignature not implemented yet");
    }

    void renameFunction(FunctionID id, String newName, String newNameMangled);

    default FunctionNameScore getNameScore(FunctionMatch match) {
        throw new UnsupportedOperationException("getNameScore not implemented yet");
    }
    default List<FunctionNameScore> getNameScores(List<FunctionMatch> matches, Boolean isDebug) {
        throw new UnsupportedOperationException("getNameScores not implemented yet");
    }

    default FunctionDetails getFunctionDetails(FunctionID id) {
        throw new UnsupportedOperationException("getFunctionInfo not implemented yet");
    }


    /// Progress of the server-side auto-unstrip pass, which runs after an analysis is marked complete.
    enum AutoUnstripStatus { UNINITIALISED, PENDING, RUNNING, COMPLETED, FAILED, UNKNOWN }

    /**
     * Current status of the auto-unstrip pass for an analysis (PRO-2976). Auto-unstrip runs after the
     * analysis is marked complete, so callers poll this to know when recovered names / data types are
     * ready to be synced (PLU-300).
     */
    default AutoUnstripStatus getAutoUnstripStatus(AnalysisID analysisID) throws ApiException {
        throw new UnsupportedOperationException("getAutoUnstripStatus not implemented yet");
    }

    default void aiDecompRating(FunctionID functionID, String rating, @Nullable String reason) throws ApiException {
        throw new UnsupportedOperationException("aiDecompRating not implemented yet");
    }

    default List<CollectionListItemBody> searchCollections(String partialCollectionName) throws ApiException {
        throw new UnsupportedOperationException("searchCollections not implemented yet");
    }

    default List<BinarySearchResult> searchBinaries(String partialCollectionName, String modelName) throws ApiException {
        throw new UnsupportedOperationException("searchBinaries not implemented yet");
    }

    default ai.reveng.model.Basic getAnalysisBasicInfo(AnalysisID analysisID) throws ApiException {
        throw new UnsupportedOperationException("getAnalysisBasicInfo not implemented yet");
    }

    default StartMatchingOutputBody startAnalysisFunctionMatching(AnalysisID analysisID, StartMatchingForAnalysisInputBody request) throws ApiException {
        throw new UnsupportedOperationException("startAnalysisFunctionMatching not implemented yet");
    }

    default GetMatchesStatusOutputBody getAnalysisFunctionMatchingStatus(AnalysisID analysisID) throws ApiException {
        throw new UnsupportedOperationException("getAnalysisFunctionMatchingStatus not implemented yet");
    }

    default GetMatchesOutputBody getAnalysisFunctionMatches(AnalysisID analysisID) throws ApiException {
        throw new UnsupportedOperationException("getAnalysisFunctionMatches not implemented yet");
    }

    default StartMatchingOutputBody startFunctionsMatching(StartMatchingForFunctionsInputBody request) throws ApiException {
        throw new UnsupportedOperationException("startFunctionsMatching not implemented yet");
    }

    default GetMatchesStatusOutputBody getFunctionsMatchingStatus(List<Long> functionIds) throws ApiException {
        throw new UnsupportedOperationException("getFunctionsMatchingStatus not implemented yet");
    }

    default GetMatchesOutputBody getFunctionsMatches(List<Long> functionIds) throws ApiException {
        throw new UnsupportedOperationException("getFunctionsMatches not implemented yet");
    }

    default void batchRenameFunctions(BatchRenameInputBody request) throws ApiException {
        throw new UnsupportedOperationException("batchRenameFunctions not implemented yet");
    }

    default List<String> getAssembly(FunctionID functionID) throws ApiException {
        throw new UnsupportedOperationException("getAssembly not implemented yet");
    }

    default ConfigResponse getConfig() throws ApiException {
        throw new UnsupportedOperationException("getConfig not implemented yet");
    }

    default User getMe() throws ApiException {
        throw new UnsupportedOperationException("getMe not implemented yet");
    }
}

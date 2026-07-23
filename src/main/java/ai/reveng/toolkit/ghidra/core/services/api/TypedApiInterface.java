package ai.reveng.toolkit.ghidra.core.services.api;

import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import ai.reveng.model.*;
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
    record FunctionID(long value){
        public Integer asInteger() {
            return Math.toIntExact(value);
        }
    }

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

    default DataTypeList generateFunctionDataTypes(AnalysisID analysisID, List<FunctionID> functionIDS) {
        throw new UnsupportedOperationException("generateFunctionDataTypes not implemented yet");
    }

    default DataTypeList getFunctionDataTypes(List<FunctionID> functionIDS) {
        throw new UnsupportedOperationException("getFunctionDataTypes not implemented yet");
    }

    default Optional<FunctionDataTypeStatus> getFunctionDataTypes(AnalysisID analysisID, FunctionID functionID) {
        throw new UnsupportedOperationException("getFunctionDataTypes not implemented yet");
    }

    default FunctionDataTypesList listFunctionDataTypesForAnalysis(AnalysisID analysisID) {
        return listFunctionDataTypesForAnalysis(analysisID, null);
    }

    default FunctionDataTypesList listFunctionDataTypesForAnalysis(AnalysisID analysisID, @Nullable List<FunctionID> ids) {
        throw new UnsupportedOperationException("listFunctionDataTypesForAnalysis not implemented yet");
    }

    default FunctionDataTypesList listFunctionDataTypesForFunctions(List<FunctionID> functionIDs) {
        throw new UnsupportedOperationException("listFunctionDataTypesForFunctions not implemented yet");
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
     * mapping used to resolve a displayed name back to the token to override.
     */
    default TokenisedData getAIDecompilationTokenised(FunctionID functionID) throws ApiException {
        throw new UnsupportedOperationException("getAIDecompilationTokenised not implemented yet");
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

    /// The server's data-type blob for a function together with its optimistic-concurrency version.
    record VersionedFunctionTypes(ai.reveng.model.V2FunctionInfo dataTypes, long version) {}

    /**
     * Fetch the current server-side data types for a function and the version to send back on update.
     * Empty if the server has no data types for the function yet.
     */
    default Optional<VersionedFunctionTypes> getFunctionDataTypesWithVersion(FunctionID functionID) throws ApiException {
        throw new UnsupportedOperationException("getFunctionDataTypesWithVersion not implemented yet");
    }

    /// Outcome of a single data-type push, mirroring the server status values.
    enum DataTypePushStatus { UPDATED, VERSION_CONFLICT, ERROR, UNKNOWN }

    /// A local data-type blob to push for a function, carrying the version it was based on.
    record FunctionDataTypeUpdate(FunctionID functionID, ai.reveng.model.FunctionInfo dataTypes, long version) {}

    /// Per-function outcome of a data-type push.
    record DataTypePushResult(FunctionID functionID, DataTypePushStatus status, @Nullable String error) {}

    /**
     * Push local data-type blobs back to the portal for the given analysis. Version conflicts are
     * reported per function so the caller can re-fetch and retry.
     */
    default List<DataTypePushResult> pushFunctionDataTypes(AnalysisID analysisID, List<FunctionDataTypeUpdate> updates) throws ApiException {
        throw new UnsupportedOperationException("pushFunctionDataTypes not implemented yet");
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

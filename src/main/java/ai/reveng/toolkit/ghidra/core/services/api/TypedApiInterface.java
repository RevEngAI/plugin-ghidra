package ai.reveng.toolkit.ghidra.core.services.api;

import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import ai.reveng.model.*;
import ai.reveng.model.AutoUnstripResponse;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
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

    record CollectionID(int id) {}

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


    /**
     * Special filters for the collection search endpoint
     * https://api.reveng.ai/v2/docs#tag/Collections/operation/list_collections_v2_collections_get
     */
    enum SearchFilter {
        official_only,
        user_only,
        team_only,
        public_only,
        hide_empty
    }

    default List<Collection> searchCollections(String searchTerm,
                                                     @Nullable List<SearchFilter> filter,
                                                     int limit,
                                                     int offset,
                                                     @Nullable CollectionResultOrder orderBy,
                                                     @Nullable OrderDirection order
    ) {
        throw new UnsupportedOperationException("searchCollections not implemented yet");
    }

    default List<AnalysisID> searchBinaries(
            String searchTerm
    ) {
        throw new UnsupportedOperationException("searchBinaries not implemented yet");
    }

    String getAnalysisLogs(AnalysisID analysisID);

    void authenticate() throws InvalidAPIInfoException;

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

    default GetAiDecompilationTask pollAIDecompileStatus(FunctionID functionID) {
        throw new UnsupportedOperationException("pollAIDecompileStatus not implemented yet");
    }

    void renameFunction(FunctionID id, String newName);

    default FunctionNameScore getNameScore(FunctionMatch match) {
        throw new UnsupportedOperationException("getNameScore not implemented yet");
    }
    default List<FunctionNameScore> getNameScores(List<FunctionMatch> matches, Boolean isDebug) {
        throw new UnsupportedOperationException("getNameScores not implemented yet");
    }

    default Collection getCollectionInfo(CollectionID id) {
        throw new UnsupportedOperationException("getCollectionInfo not implemented yet");
    };

    default FunctionDetails getFunctionDetails(FunctionID id) {
        throw new UnsupportedOperationException("getFunctionInfo not implemented yet");
    }

    ///
    /// Typed Box Placeholder for {@link AutoUnstripResponse}
    record TypedAutoUnstripResponse(
            AutoUnstripResponse autoUnstripResponse
    ) {
    }

    /// {@link MatchedFunctionSuggestion}
    record TypedAutoUnstripMatch(MatchedFunctionSuggestion suggestedFunction) { }


    default TypedAutoUnstripResponse autoUnstrip(AnalysisID analysisID) {
        throw new UnsupportedOperationException("autoUnstrip not implemented yet");
    }

    default TypedAutoUnstripResponse aiUnstrip(AnalysisID analysisID) {
        throw new UnsupportedOperationException("aiUnstrip not implemented yet");
    }

    default void aiDecompRating(FunctionID functionID, String rating, @Nullable String reason) throws ApiException {
        throw new UnsupportedOperationException("aiDecompRating not implemented yet");
    }

    default List<CollectionSearchResult> searchCollections(String partialCollectionName, String modelName) throws ApiException {
        throw new UnsupportedOperationException("searchCollections not implemented yet");
    }

    default List<BinarySearchResult> searchBinaries(String partialCollectionName, String modelName) throws ApiException {
        throw new UnsupportedOperationException("searchBinaries not implemented yet");
    }

    default ai.reveng.model.Basic getAnalysisBasicInfo(AnalysisID analysisID) throws ApiException {
        throw new UnsupportedOperationException("getAnalysisBasicInfo not implemented yet");
    }

    default FunctionMatchingResponse analysisFunctionMatching(AnalysisID analysisID, AnalysisFunctionMatchingRequest request) throws ApiException {
        throw new UnsupportedOperationException("analysisFunctionMatching not implemented yet");
    }

    default FunctionMatchingResponse functionFunctionMatching(FunctionMatchingRequest request) throws ApiException {
        throw new UnsupportedOperationException("functionFunctionMatching not implemented yet");
    }

    default void batchRenameFunctions(FunctionsListRename functionsList) throws ApiException {
        throw new UnsupportedOperationException("batchRenameFunctions not implemented yet");
    }

    default List<String> getAssembly(FunctionID functionID) throws ApiException {
        throw new UnsupportedOperationException("getAssembly not implemented yet");
    }

}


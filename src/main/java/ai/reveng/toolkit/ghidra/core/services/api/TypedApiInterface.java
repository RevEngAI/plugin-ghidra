package ai.reveng.toolkit.ghidra.core.services.api;

import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.AutoUnstripResponse;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;

import javax.annotation.Nullable;

import ai.reveng.invoker.ApiException;


/**
 * Service for interacting with the RevEngAi API
 * This is a generic Java Interface and should not use any Ghidra specific classes
 *
 * It aims to stick close to the API functions themselves.
 * E.g. if a feature is implemented via two API calls, it should be implemented as two methods here.
 *
 * Wrapping this feature into one conceptual method should then happen inside the {@link ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService}
 *
 *
 */
public interface TypedApiInterface {
    // Analysis
//    @Deprecated
//    BinaryID legacyAnalyse(AnalysisOptionsBuilder binHash) throws ApiException;

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

    default AutoUnstripResponse autoUnstrip(AnalysisID analysisID) {
        throw new UnsupportedOperationException("autoUnstrip not implemented yet");
    }

    default AutoUnstripResponse aiUnstrip(AnalysisID analysisID) {
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

    default FunctionMatchingBatchResponse analysisFunctionMatching(AnalysisID analysisID, AnalysisFunctionMatchingRequest request) throws ApiException {
        throw new UnsupportedOperationException("analysisFunctionMatching not implemented yet");
    }

    default FunctionMatchingBatchResponse functionFunctionMatching(FunctionMatchingRequest request) throws ApiException {
        throw new UnsupportedOperationException("functionFunctionMatching not implemented yet");
    }

    default void batchRenameFunctions(FunctionsListRename functionsList) throws ApiException {
        throw new UnsupportedOperationException("batchRenameFunctions not implemented yet");
    }
}


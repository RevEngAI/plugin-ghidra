package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.model.FunctionsDetailResponse;

/**
 * Record representing detailed function information from the RevEng.AI API
 */
public record FunctionDetails(
        FunctionID functionId,
        String mangledFunctionName,
        Long functionVaddr,
        Long functionSize,
        AnalysisID analysisId,
        BinaryID binaryId,
        String binaryName,
        BinaryHash sha256Hash,
        String demangledName

) {

    public static FunctionDetails fromServerResponse(FunctionsDetailResponse response) {
        return new FunctionDetails(
                new FunctionID(response.getFunctionId()),
                response.getFunctionNameMangled(),
                response.getFunctionVaddr(),
                response.getFunctionSize().longValue(),
                new AnalysisID(response.getAnalysisId()),
                new BinaryID(response.getBinaryId()),
                response.getBinaryName(),
                new BinaryHash(response.getSha256Hash()),
                response.getFunctionName()
        );
    }
}

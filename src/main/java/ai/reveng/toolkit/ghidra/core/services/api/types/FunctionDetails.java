package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.model.FunctionsDetailResponse;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;

/**
 * Record representing detailed function information from the RevEng.AI API
 */
public record FunctionDetails(
        TypedApiInterface.FunctionID functionId,
        String mangledFunctionName,
        Long functionVaddr,
        Long functionSize,
        TypedApiInterface.AnalysisID analysisId,
        String binaryName,
        TypedApiInterface.BinaryHash sha256Hash,
        String demangledName

) {

    public static FunctionDetails fromServerResponse(FunctionsDetailResponse response) {
        return new FunctionDetails(
                new TypedApiInterface.FunctionID(response.getFunctionId()),
                response.getFunctionNameMangled(),
                response.getFunctionVaddr(),
                response.getFunctionSize().longValue(),
                new TypedApiInterface.AnalysisID(response.getAnalysisId()),
                response.getBinaryName(),
                new TypedApiInterface.BinaryHash(response.getSha256Hash()),
                response.getFunctionName()
        );
    }
}

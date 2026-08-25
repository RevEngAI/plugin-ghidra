package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.model.FunctionDetailsOutputBody;
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
        String demangledName

) {

    public static FunctionDetails fromServerResponse(FunctionDetailsOutputBody response) {
        return new FunctionDetails(
                new TypedApiInterface.FunctionID(response.getFunctionId()),
                response.getMangledName(),
                response.getFunctionVaddr(),
                response.getFunctionSize(),
                new TypedApiInterface.AnalysisID(response.getAnalysisId().intValue()),
                response.getFunctionName()
        );
    }
}

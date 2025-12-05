package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.model.MatchedFunction;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching.AbstractFunctionMatchingDialog;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import org.json.JSONObject;

import javax.annotation.Nullable;
import java.math.BigDecimal;

/// The Typed Class to represent a FunctionMatch returned by the RevEng.AI API
/// At the very least it needs to contain the origin_function_id and nearest_neighbor_id
/// Other fields may be null depending on the context in which the FunctionMatch was returned
/// They can be derived from the ids via the API if needed
/// For representing the combination of a local Ghidra Function and its FunctionMatch, use {@link GhidraFunctionMatch}
public record FunctionMatch(
        TypedApiInterface.FunctionID origin_function_id,
        TypedApiInterface.FunctionID nearest_neighbor_id,
        String nearest_neighbor_function_name,
        String nearest_neighbor_mangled_function_name,
        String nearest_neighbor_binary_name,
        TypedApiInterface.BinaryHash nearest_neighbor_sha_256_hash,
        Boolean nearest_neighbor_debug,
        BigDecimal similarity,
        BigDecimal confidence

) {

    public static FunctionMatch fromMatchedFunctionAPIType(MatchedFunction matchedFunction, TypedApiInterface.FunctionID originFunctionID) {
        return new FunctionMatch(
                originFunctionID,
                new TypedApiInterface.FunctionID(matchedFunction.getFunctionId()),
                matchedFunction.getFunctionName(),
                matchedFunction.getMangledName(),
                matchedFunction.getBinaryName(),
                new TypedApiInterface.BinaryHash(matchedFunction.getSha256Hash()),
                matchedFunction.getDebug(),
                matchedFunction.getSimilarity(),
                matchedFunction.getConfidence()
        );
    }

    public String name(){
        return nearest_neighbor_function_name;
    }
}

package ai.reveng.toolkit.ghidra.core.services.api.types;


import ai.reveng.invoker.ApiException;
import ai.reveng.model.BaseResponseBasic;
import ai.reveng.model.Basic;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import org.json.JSONObject;

/// This is a remnant of an older class that contained the analysis result data directly.
/// Now it's a wrapper around the generated Basic class with some shim methods for convenience.
public record AnalysisResult(
        AnalysisID analysisID,
        Basic base_response_basic
) {
    public BinaryHash sha_256_hash() {
        return new BinaryHash(base_response_basic().getSha256Hash());
    }

    public String binary_name() {
        return base_response_basic.getBinaryName();
    }
}

package ai.reveng.toolkit.ghidra.core.services.api.types;


import ai.reveng.model.Basic;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;

/// This is a remnant of an older class that contained the analysis result data directly.
/// Now it's a wrapper around the generated Basic class with some shim methods for convenience.
public record AnalysisResult(
        TypedApiInterface.AnalysisID analysisID,
        Basic base_response_basic
) {
    public TypedApiInterface.BinaryHash sha_256_hash() {
        return new TypedApiInterface.BinaryHash(base_response_basic().getSha256Hash());
    }

    public String binary_name() {
        return base_response_basic.getBinaryName();
    }
}

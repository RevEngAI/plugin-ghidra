package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ghidra.program.model.listing.Function;

/**
 * Extension of a {@link FunctionMatch}
 * it contains the original FunctionMatch, but combines it with information relating to the original Ghidra Function
 *
 */
public record GhidraFunctionMatch(
        Function function,
        FunctionMatch functionMatch
) {
    // The following methods are just convenience methods to access the FunctionMatch fields
    // This simplifies using this class in a stream with method references
    public TypedApiInterface.FunctionID nearest_neighbor_id() {
        return functionMatch.nearest_neighbor_id();
    }
}

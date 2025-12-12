package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.FunctionDataTypeMessage;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;

import javax.annotation.Nullable;
import java.util.Optional;


/**
 * @param function      The local function that we searched for matches for
 * @param functionMatch A match that was found and returned by the RevEng.AI server
 * @param signature     The optional signature of the function match
 */
public record GhidraFunctionMatchWithSignature(
        Function function,
        FunctionMatch functionMatch,
        @Nullable FunctionDefinitionDataType signature
){}
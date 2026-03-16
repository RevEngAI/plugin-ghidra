package ai.reveng.toolkit.ghidra.binarysimilarity.cmds;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.framework.cmd.Command;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;


import static ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin.REVENG_AI_NAMESPACE;

/// The central command to apply a function match to a {@link Program}
/// It centralizes product design decisions about how to apply a match, like moving it to a namespace,
/// renaming it, applying the signature, etc.
/// It will apply the function signature if available, otherwise it will just rename the function
/// There are various considerations when ap
public class ApplyMatchCmd implements Command<Program> {

    private final GhidraRevengService.AnalysedProgram analyzedProgram;
    private final GhidraFunctionMatchWithSignature match;
    @Nullable private final GhidraRevengService service;
    private final Boolean includeBinaryNameInNameSpace;

    public ApplyMatchCmd(
            @Nullable GhidraRevengService service,
            @NotNull GhidraRevengService.AnalysedProgram program,
            @NotNull GhidraFunctionMatchWithSignature match,
            Boolean includeBinaryNameInNameSpace

    ) {
        super();
        this.analyzedProgram = program;
        this.match = match;
        this.service = service;
        this.includeBinaryNameInNameSpace = includeBinaryNameInNameSpace;
    }

    private boolean shouldApplyMatch() {
        var func = match.function();
        return func != null &&
                // Do not override user-defined function names
                func.getSymbol().getSource() != SourceType.USER_DEFINED &&
                GhidraRevengService.isRelevantForAnalysis(func) &&
                // Only accept valid names (no spaces)
                !match.functionMatch().nearest_neighbor_mangled_function_name().contains(" ") &&
                !match.functionMatch().nearest_neighbor_function_name().contains(" ")
                // Only rename if the function ID is known (boundaries matched)
                && analyzedProgram.getIDForFunction(func).map(id -> id.functionID() != match.functionMatch().origin_function_id()).orElse(false);
    }

    @Override
    public boolean applyTo(Program obj) {
        // Check that this is the same program
        if (obj != this.analyzedProgram.program()) {
            throw new IllegalArgumentException("This command can only be applied to the same program as the one provided in the constructor");
        }
        if (!shouldApplyMatch()) {
            return false;
        }

        var nameSpace = includeBinaryNameInNameSpace ? getLibraryNameSpaceForName(match.functionMatch().nearest_neighbor_binary_name()): getRevEngAINameSpace();
        var function = match.function();
        try {
            function.setParentNamespace(nameSpace);
        } catch (DuplicateNameException e) {
            throw new RuntimeException(e);
        } catch (InvalidInputException e) {
            throw new RuntimeException(e);
        } catch (CircularDependencyException e) {
            throw new RuntimeException(e);
        }

        this.analyzedProgram.setMangledNameForFunction(function, match.functionMatch().nearest_neighbor_mangled_function_name());

        var signature = match.signature();
        if (signature != null) {
            var cmd = new ApplyFunctionSignatureCmd(function.getEntryPoint(), signature, SourceType.USER_DEFINED);
            cmd.applyTo(analyzedProgram.program());
        }
        else {
            var renameCmd = new RenameLabelCmd(match.function().getSymbol(), match.functionMatch().name(), SourceType.USER_DEFINED);
            renameCmd.applyTo(analyzedProgram.program());
        }
        // If we have a service then push the name. If not then it was explicitly not provided, i.e. the caller
        // is responsible for pushing the names in batch
        if (service != null) {
            service.getApi().renameFunction(
                    match.functionMatch().origin_function_id(),
                    match.functionMatch().nearest_neighbor_function_name(),
                    match.functionMatch().nearest_neighbor_mangled_function_name()
                    );
        }


        return true;
    }

    public void applyWithTransaction() {
        var program = this.analyzedProgram.program();
        var tID = program.startTransaction("RevEng.AI: Apply Match");
        var status = applyTo(program);
        program.endTransaction(tID, status);
    }

    private Namespace getRevEngAINameSpace() {
        var program = this.analyzedProgram.program();
        Namespace revengMatchNamespace = null;
        try {
            revengMatchNamespace = program.getSymbolTable().getOrCreateNameSpace(
                    program.getGlobalNamespace(),
                    REVENG_AI_NAMESPACE,
                    SourceType.ANALYSIS
            );
        } catch (DuplicateNameException | InvalidInputException e) {
            throw new RuntimeException(e);
        }
        return revengMatchNamespace;
    }

    private Namespace getLibraryNameSpaceForName(String name) {
        var program = this.analyzedProgram.program();
        Namespace libraryNamespace = null;
        try {
            libraryNamespace = program.getSymbolTable().getOrCreateNameSpace(
                    getRevEngAINameSpace(),
                    name,
                    SourceType.USER_DEFINED);
        } catch (DuplicateNameException | InvalidInputException e) {
            throw new RuntimeException(e);
        }
        return libraryNamespace;
    }

    @Override
    public String getStatusMsg() {
        return "";
    }

    @Override
    public String getName() {
        return "";
    }
}

package ai.reveng.toolkit.ghidra.binarysimilarity.cmds;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.framework.cmd.Command;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
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
/// What it transfers is chosen by {@link Transfer}: the matched name, the matched signature (its data
/// types), or both. A signature is only transferred when the match has one.
/// There are various considerations when ap
public class ApplyMatchCmd implements Command<Program> {

    /// The parts of a match that can be transferred onto the local function, as offered in the portal
    public enum Transfer {
        NAME("Name"),
        SIGNATURE("Signature"),
        NAME_AND_SIGNATURE("Name and Signature");

        private final String label;

        Transfer(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }

        public boolean includesName() {
            return this != SIGNATURE;
        }

        public boolean includesSignature() {
            return this != NAME;
        }
    }

    private final GhidraRevengService.AnalysedProgram analyzedProgram;
    private final GhidraFunctionMatchWithSignature match;
    @Nullable private final GhidraRevengService service;
    private final Boolean includeBinaryNameInNameSpace;
    private final Transfer transfer;

    public ApplyMatchCmd(
            @Nullable GhidraRevengService service,
            @NotNull GhidraRevengService.AnalysedProgram program,
            @NotNull GhidraFunctionMatchWithSignature match,
            Boolean includeBinaryNameInNameSpace

    ) {
        this(service, program, match, includeBinaryNameInNameSpace, Transfer.NAME_AND_SIGNATURE);
    }

    public ApplyMatchCmd(
            @Nullable GhidraRevengService service,
            @NotNull GhidraRevengService.AnalysedProgram program,
            @NotNull GhidraFunctionMatchWithSignature match,
            Boolean includeBinaryNameInNameSpace,
            @NotNull Transfer transfer
    ) {
        super();
        this.analyzedProgram = program;
        this.match = match;
        this.service = service;
        this.includeBinaryNameInNameSpace = includeBinaryNameInNameSpace;
        this.transfer = transfer;
    }

    private boolean shouldApplyMatch() {
        var func = match.function();
        if (func == null ||
                // Exclude thunks and external functions
                func.isThunk() ||
                func.isExternal() ||
                // Only apply if the function ID is known (boundaries matched)
                analyzedProgram.getIDForFunction(func).isEmpty()) {
            return false;
        }
        if (transfer == Transfer.SIGNATURE) {
            // The name is left alone, so only a signature to apply matters
            return match.signature() != null;
        }
        // Do not override user-defined function names
        return func.getSymbol().getSource() != SourceType.USER_DEFINED &&
                // Only accept valid names (no spaces)
                !match.functionMatch().nearest_neighbor_mangled_function_name().contains(" ") &&
                !match.functionMatch().nearest_neighbor_function_name().contains(" ");
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

        var function = match.function();
        var signature = match.signature();
        if (transfer == Transfer.SIGNATURE) {
            // Keep the function's own name: only the prototype and its data types come across
            return applySignature(signature);
        }

        var nameSpace = includeBinaryNameInNameSpace ? getLibraryNameSpaceForName(match.functionMatch().nearest_neighbor_binary_name()): getRevEngAINameSpace();
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

        if (transfer.includesSignature() && signature != null) {
            // The name is set explicitly below: left to the signature command, it would only replace a default name
            applySignature(signature);
        }
        var renameCmd = new RenameLabelCmd(function.getSymbol(), match.functionMatch().name(), SourceType.USER_DEFINED);
        renameCmd.applyTo(analyzedProgram.program());
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

    /// Applies the prototype and its data types, leaving the function's name to the caller
    private boolean applySignature(FunctionDefinitionDataType signature) {
        var cmd = new ApplyFunctionSignatureCmd(match.function().getEntryPoint(), signature, SourceType.USER_DEFINED,
                false, false, DataTypeConflictHandler.DEFAULT_HANDLER, FunctionRenameOption.NO_CHANGE);
        return cmd.applyTo(analyzedProgram.program());
    }

    public void applyWithTransaction() {
        var program = this.analyzedProgram.program();
        var tID = program.startTransaction("RevEng.AI: Apply Match");
        boolean status = false;
        try {
            status = applyTo(program);
        } finally {
            program.endTransaction(tID, status);
        }
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

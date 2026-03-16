package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.SelectableItem;
import ai.reveng.toolkit.ghidra.core.AnalysisLogConsumer;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionBoundary;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler.AIDecompilationdWindow;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.MockApi;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.Collection;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.APIAuthenticationException;
import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.LongPropertyMap;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NoValueException;
import ghidra.util.task.TaskMonitor;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nullable;
import java.awt.*;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.*;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin.REVENG_AI_NAMESPACE;
import static ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage.OPTION_KEY_ANALYSIS_ID;


/**
 * Implements a Ghidra compatible interface on top of the RevEngAI REST API
 * The idea is that all other plugin and UI code can simply use this service to interact with the API
 * by directly providing Ghidra objects. This service then internally maps them to the API objects
 *
 * All methods are blocking, so they should be wrapped in Tasks if async behavior is needed
 *
 * This is used in the rest of the plugin(s) as a Ghidra Service, but doesn't have its interface fixed yet
 *
 * This will later be refactored into an Interface of all Ghidra functionality that the RevengService should provide
 * which can then be implemented based on different versions of the Web API
 *
 */
public class GhidraRevengService {
    private static final String REAI_FUNCTION_PROP_MAP = "RevEngAI_FunctionID_Map";
    private static final String REAI_FUNCTION_MANGLED_MAP = "RevEngAI_FunctionMangledNames_Map";
    private final Map<TypedApiInterface.AnalysisID, AnalysisStatus> statusCache = new HashMap<>();

    private TypedApiInterface api;
    private ApiInfo apiInfo;
    private final List<Collection> collections = new ArrayList<>();
    private final List<AnalysisResult> analysisIDFilter = new ArrayList<>();

    /// dedicated functions on the GhidraRevengService should be used instead to enforce assumptions via
    /// type level guarantees
//    @Deprecated
    public TypedApiInterface getApi() {
        return api;
    }

    public GhidraRevengService(ApiInfo apiInfo){
        this.apiInfo = apiInfo;
        this.api = new TypedApiImplementation(apiInfo);
    }

    public GhidraRevengService(TypedApiInterface mockApi){
        this.api = mockApi;
        this.apiInfo = new ApiInfo("http://localhost:8080", "http://localhost:8081", "mock");
    }

    public GhidraRevengService(){
        this.api = new MockApi();
    }

    public URI getServer() {
        return this.apiInfo.hostURI();
    }

    public ProgramWithID registerAnalysisForProgram(Program program, TypedApiInterface.AnalysisID analysisID) {
        return addAnalysisIDtoProgramOptions(program, analysisID);
    }

    /**
     * Registers an analysis for a program and stores a function filter for later use.
     * The filter will be applied when registerFinishedAnalysisForProgram is called.
     *
     * @param program The program to register
     * @param analysisID The analysis ID to associate
     * @param selectedFunctions The functions to include when mapping (null for all functions)
     * @return The program with associated analysis ID
     */
    public ProgramWithID registerAnalysisForProgram(Program program, TypedApiInterface.AnalysisID analysisID,
            @Nullable List<Function> selectedFunctions) {
        return addAnalysisIDtoProgramOptions(program, analysisID);
    }

    public AnalysedProgram registerFinishedAnalysisForProgram(ProgramWithID programWithID, TaskMonitor monitor) throws CancelledException {
        // Check if there's a pending function filter for this analysis
        return registerFinishedAnalysisForProgram(programWithID, null, monitor);
    }

    /**
     * Registers a finished analysis for a program, optionally filtering which functions get mapped.
     *
     * @param programWithID The program with associated analysis ID
     * @param selectedFunctions Optional list of functions to include. If null, all functions are included.
     * @param monitor Task monitor for cancellation
     * @return The analysed program with function ID mappings
     */
    public AnalysedProgram registerFinishedAnalysisForProgram(ProgramWithID programWithID,
            @Nullable List<Function> selectedFunctions, TaskMonitor monitor) throws CancelledException {
        var status = status(programWithID);
        if (!status.equals(AnalysisStatus.Complete)){
            throw new IllegalStateException("Analysis %s is not complete yet, current status: %s"
                    .formatted(programWithID.analysisID(), status));
        }
        statusCache.put(programWithID.analysisID, AnalysisStatus.Complete);

        // Convert selected functions to a set of entry point addresses for filtering
        Set<Address> functionFilter = null;
        if (selectedFunctions != null) {
            functionFilter = selectedFunctions.stream()
                    .map(Function::getEntryPoint)
                    .collect(Collectors.toSet());
        }

        var analysedProgram = associateFunctionInfo(programWithID, functionFilter, monitor);
        pullFunctionInfoFromAnalysis(analysedProgram, monitor);
        monitor.checkCancelled();
        return analysedProgram;
    }

    private ProgramWithID addAnalysisIDtoProgramOptions(Program program, TypedApiInterface.AnalysisID analysisID){
        var transactionId = program.startTransaction("Associate Binary ID with Program");
        program.getOptions(ReaiPluginPackage.REAI_OPTIONS_CATEGORY)
                .setLong(OPTION_KEY_ANALYSIS_ID, analysisID.id());
        program.endTransaction(transactionId, true);
        return new ProgramWithID(program, analysisID);
    }

    private Namespace getRevEngAINameSpace(Program program) {
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
    /**
     * Tries to find a BinaryID for a given program
     * If the program already has a BinaryID associated with it, it will return that
     * If we don't have a BinaryID it will return an empty Optional
     * @param program
     * @return
     */
    @Deprecated
    public Optional<BinaryID> getBinaryIDFor(Program program) {
        return getBinaryIDfromOptions(program);
    }

    @SuppressWarnings("deprecation") // Using deprecated method to support legacy BinaryID
    private Optional<TypedApiInterface.AnalysisID> getAnalysisIDFor(Program program){
        var optAnalysisID = getAnalysisIDFromOptions(program);
        if (optAnalysisID.isPresent()){
            return optAnalysisID;
        }
        // Fallback to getting it from the BinaryID, if one exists
        var legacyBinaryID = getBinaryIDFor(program);
        if (legacyBinaryID.isPresent()) {
            // We have a legacy binary ID, upgrade to AnalysisID
            var analysisID = api.getAnalysisIDfromBinaryID(legacyBinaryID.get());
            addAnalysisIDtoProgramOptions(program, analysisID);
            program.withTransaction("Remove legacy BinaryID from program options", () ->
                    program.getOptions(ReaiPluginPackage.REAI_OPTIONS_CATEGORY)
                    .setLong(ReaiPluginPackage.OPTION_KEY_BINID, ReaiPluginPackage.INVALID_BINARY_ID)
            );
            return Optional.of(analysisID);
        }
        return Optional.empty();
    }

    /// This is a helper to get the AnalysisID from the BinaryID, in the rare cases that this is required
    /// Currently the only known case is when opening the analysis on the portal in the browser
    private Optional<BinaryID> getBinaryIDFromAnalysisID(TypedApiInterface.AnalysisID analysisID) {
        try {
            var info = api.getAnalysisBasicInfo(analysisID);
            var results = api.search(new TypedApiInterface.BinaryHash(info.getSha256Hash()));
            var binaryId = results.stream().filter( r -> r.analysis_id().equals(analysisID))
                .findAny().map( r -> r.binary_id());
            return binaryId;

        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }

    private Optional<TypedApiInterface.AnalysisID> getAnalysisIDFromOptions(
            Program program
    ) {
        long bid = program.getOptions(
                ReaiPluginPackage.REAI_OPTIONS_CATEGORY).getLong(OPTION_KEY_ANALYSIS_ID,
                ReaiPluginPackage.INVALID_ANALYSIS_ID);
        if (bid == ReaiPluginPackage.INVALID_ANALYSIS_ID) {
            return Optional.empty();
        }
        var analysisID = new TypedApiInterface.AnalysisID((int) bid);
        if (!statusCache.containsKey(analysisID)) {
            // Check that it's really valid in the context of the currently configured API
            try {
                var status = api.status(analysisID);
                statusCache.put(analysisID, status);
            } catch (APIAuthenticationException | ApiException e) {
                Msg.showError(this, null, "Invalid Analysis ID",
                        ("The Analysis ID %s stored in the program options is invalid for the currently configured RevEng.AI server %s. "
                                + "This could be an intermittent error, or you switched the servers")
                                .formatted(analysisID, this.apiInfo.hostURI()), e);
                return Optional.empty();
            }
            // Now it's certain that it is a valid binary ID
        }

        return Optional.of(analysisID);
    }

    @Deprecated
    private Optional<BinaryID> getBinaryIDfromOptions(
            Program program
    ) {
        long bid = program.getOptions(
                ReaiPluginPackage.REAI_OPTIONS_CATEGORY).getLong(ReaiPluginPackage.OPTION_KEY_BINID,
                ReaiPluginPackage.INVALID_BINARY_ID);
        if (bid == ReaiPluginPackage.INVALID_BINARY_ID) {
            return Optional.empty();
        }
        var binID = new BinaryID((int) bid);
        // Check that it's really valid in the context of the currently configured API
        AnalysisStatus status;
        try {
            status = api.status(binID);
        } catch (APIAuthenticationException | ApiException e) {
            Msg.showError(this, null, "Invalid Binary ID",
                    ("The Binary ID %s stored in the program options is invalid for the currently configured RevEng.AI server %s. "
                            + "This could be an intermittent error, or you switched servers")
                            .formatted(binID, this.apiInfo.hostURI()), e);
            return Optional.empty();
        }
        var analysisID = api.getAnalysisIDfromBinaryID(binID);
        statusCache.put(analysisID, status);

        // Now it's certain that it is a valid binary ID

        return Optional.of(binID);
    }

    /// Loads the function info into a dedicated user property map.
    /// This method should only concern itself with associating the FunctionID with the Ghidra Function
    /// This property is immutable within an Analysis: The function ID will never change unless an entirely different
    /// analysis is associated with the program
    /// Other function information like the name and signature should be loaded in [#pullFunctionInfoFromAnalysis(AnalysedProgram ,TaskMonitor)]
    /// because this information can change on the server, and thus needs a dedicated method to refresh it
    private AnalysedProgram associateFunctionInfo(ProgramWithID knownProgram, @Nullable Set<Address> functionFilter, TaskMonitor monitor) throws CancelledException {
        var analysisID = knownProgram.analysisID();
        var program = knownProgram.program();
        List<FunctionInfo> functionInfo = null;
        functionInfo = api.getFunctionInfo(analysisID);

        monitor.checkCancelled();
        var transactionID = program.startTransaction("Associate Function Info");

        // Create the FunctionID map
        LongPropertyMap functionIDMap;
        try {
            functionIDMap = program.getUsrPropertyManager().createLongPropertyMap(REAI_FUNCTION_PROP_MAP);
        } catch (DuplicateNameException e) {
            program.endTransaction(transactionID, false);
            throw new RuntimeException("Previous function property map still exists",e);
        }

        // Create the function mangled name map
        try {
            program.getUsrPropertyManager().createStringPropertyMap(REAI_FUNCTION_MANGLED_MAP);
        } catch (DuplicateNameException e) {
            program.endTransaction(transactionID, false);
            throw new RuntimeException("Previous mangled name property map still exists",e);
        }

        LongPropertyMap finalFunctionIDMap = functionIDMap;

        int ghidraBoundariesMatchedFunction = 0;
        int skippedByFilter = 0;
        for (FunctionInfo info : functionInfo) {
            var oFunc = getFunctionFor(info, program);
            if (oFunc.isEmpty()) {
                Msg.error(this, "Function not found in Ghidra for info: %s".formatted(info));
                continue;
            }
            var func = oFunc.get();

            // Skip functions not in the filter (if filter is provided)
            if (functionFilter != null && !functionFilter.contains(func.getEntryPoint())) {
                skippedByFilter++;
                continue;
            }

            // There are two ways to think about the size of a function
            // They diverge for non-contiguous functions
            var funcSizeByAddressCount = func.getBody().getNumAddresses();
            var funcSizeByDistance = func.getBody().getMaxAddress().subtract(func.getEntryPoint()) + 1;

            // For unclear reasons the func size is off by one
            if (funcSizeByAddressCount - 1 != info.functionSize() && funcSizeByAddressCount != info.functionSize()) {
                Msg.warn(this, "Function size mismatch for function %s: %d vs %d".formatted(func.getName(), funcSizeByAddressCount, info.functionSize()));
                continue;
            }

            finalFunctionIDMap.add(func.getEntryPoint(), info.functionID().value());

            ghidraBoundariesMatchedFunction++;
        }


        program.endTransaction(transactionID, true);


        var analysedProgram = new AnalysedProgram(program, analysisID);
        AtomicInteger ghidraFunctionCount = new AtomicInteger();
        program.getFunctionManager().getFunctions(true).forEach(
                func -> {
                    if (isRelevantForAnalysis(func)){
                        ghidraFunctionCount.getAndIncrement();

                        if (analysedProgram.getIDForFunction(func).isEmpty()) {
                            Msg.info(this, "Function %s not found in RevEng.AI".formatted(func.getSymbol().getName(false)));
                        }
                    }
                }
        );
        // Print summary
        String filterInfo = functionFilter != null ? " (%d skipped by filter)".formatted(skippedByFilter) : "";
        Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Function loading summary",
                ("Found %d functions from RevEng.AI. Your local Ghidra instance has %d/%d matching function " +
                        "boundaries%s. For better results, please start a new analysis from this plugin.").formatted(
                        functionInfo.size(),
                        ghidraBoundariesMatchedFunction,
                        ghidraFunctionCount.get(),
                        filterInfo
                ));

        return analysedProgram;

    }


    public record RenameResult(Function func, String originalName, String newName) {
        public String virtualAddress() {
            return func.getEntryPoint().toString();
        }
    }
    /// Pull the server side information about the functions from a remote Analysis and update the local {@link Program}
    /// based on it
    /// This currently includes:
    /// * the name of the function
    /// * the type signature of the function
    ///
    /// It assumes that the initial load already happened, i.e. the functions have an associated FunctionID already.
    /// The initial association happens in {@link #associateFunctionInfo(ProgramWithID, Set, TaskMonitor)}
    ///
    public List<RenameResult> pullFunctionInfoFromAnalysis(AnalysedProgram analysedProgram, TaskMonitor monitor) {
        var transactionId = analysedProgram.program().startTransaction("RevEng.AI: Pull Function Info from Analysis");

        List<RenameResult> renameResults = new ArrayList<>();

        int failedRenames = 0;

        var revEngNamespace = getRevEngAINameSpace(analysedProgram.program());

        Map<TypedApiInterface.FunctionID, FunctionInfo> functionInfoMap = api.getFunctionInfo(analysedProgram.analysisID()).stream()
                .collect(
                        Collectors.toMap(
                                FunctionInfo::functionID,
                                fi -> fi
                        )
                );


        Map<TypedApiInterface.FunctionID, @NotNull FunctionDataTypesListItem> signatureMap = api.listFunctionDataTypesForAnalysis(analysedProgram.analysisID).getItems()
                .stream()
                .filter(item -> item.getStatus().equals("completed"))
                .filter(item -> item.getDataTypes().getFuncTypes() != null)
                .collect(
                Collectors.toMap(
                        item -> new TypedApiInterface.FunctionID(item.getFunctionId()),
                        fdtStatus -> fdtStatus
                )
        );

        for (Function function : analysedProgram.program().getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) {
                continue;
            }
            var ghidraMangledName = function.getSymbol().getName(false);
            if (!isRelevantForAnalysis(function)) {
                Msg.debug(this, "Skipping external/thunk function %s".formatted(ghidraMangledName));
                continue;
            }

            var fID = analysedProgram.getIDForFunction(function);
            if (fID.isEmpty()) {
                Msg.info(this, "Function %s has no associated FunctionID, skipping".formatted(function.getName()));
                continue;
            }

            // Get the current name on  the server side
//            FunctionDetails details = api.getFunctionDetails(fID.get().functionID);
            FunctionInfo details = functionInfoMap.get(fID.get().functionID);

            // Extract the mangled name from Ghidra
            var revEngMangledName = details.functionMangledName();
            var revEngDemangledName = details.functionName();

            // Skip invalid function mangled names
            if (revEngMangledName.contains(" ") || revEngDemangledName.contains(" ")) {
                Msg.warn(this, "Skipping renaming of function %s to invalid name %s [%s]".formatted(ghidraMangledName, revEngMangledName, revEngDemangledName));
                continue;
            }

            var sig = Optional.ofNullable(signatureMap.get(fID.get().functionID));
            // Get the type information on the server side
            Optional<FunctionDefinitionDataType> functionSignatureMessageOpt = sig
                    // Try getting the data types if they are available
                    // If they are available, try converting them to a Ghidra signature
                    // If the conversion fails, act like there is no signature available
                    .flatMap (item -> Optional.ofNullable(item.getDataTypes()))
                    .flatMap((functionDataTypeMessage -> {
                        try {
                            return getFunctionSignature(functionDataTypeMessage);
                        } catch (DataTypeDependencyException e) {
                            // Something went wrong loading the data type dependencies
                            // just skip applying the signature and treat it like none being available
                            Msg.error(this, "Could not get parse signature for function %s".formatted(function.getName()));
                            return Optional.empty();
                        }
                    }));


            analysedProgram.setMangledNameForFunction(function, revEngMangledName);

            /// Source types:
            /// DEFAULT: placeholder name automatically assigned by Ghidra when it doesn’t know the real name.
            /// ANALYSIS: A name/signature inferred by one of Ghidra’s analysis engines (or demangler) rather than simply “default.”
            /// IMPORTED: Information taken from an external source — symbols or signatures imported from a file or database.
            /// USER_DEFINED: A name or signature explicitly set by the analyst.
            /// See {@link ghidra.program.model.symbol.SourceType} for more details
            if (function.getSymbol().getSource() == SourceType.DEFAULT) {
                if (functionSignatureMessageOpt.isEmpty()) {
                    // We don't have signature information for this function, so we can only try renaming it
                    if (function.getSymbol().getSource() == SourceType.DEFAULT && !revEngMangledName.startsWith("FUN_")) {
                        // The local function has the default name, so we can rename it
                        // The following check should never fail because it is a default name,
                        // and we checked above that the server name is not a default name
                        // but just to be safe and make that assumption explicit we check it explicitly
                        if (!function.getSymbol().getName(false).equals(revEngDemangledName)) {
                            Msg.info(this, "Renaming function %s to %s [%s]".formatted(ghidraMangledName, revEngMangledName, revEngDemangledName));
                            try {
                                function.setParentNamespace(revEngNamespace);
                            } catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
                                throw new RuntimeException(e);
                            }
                            var success = new SetFunctionNameCmd(function.getEntryPoint(), revEngDemangledName, SourceType.ANALYSIS)
                                    .applyTo(analysedProgram.program());
                            if (success) {
                                renameResults.add(new RenameResult(
                                        function,
                                        ghidraMangledName,
                                        revEngDemangledName
                                ));
                            } else {
                                failedRenames++;
                                Msg.error(this, "Failed to rename function %s to %s [%s]".formatted(ghidraMangledName, revEngMangledName, revEngDemangledName));
                            }
                        }
                    }

                } else {
                    /// We could use {@link ghidra.program.model.listing.FunctionSignature#isEquivalentSignature(FunctionSignature)}
                    /// if we expect the server to have changing signatures at any point in time.
                    /// For now, we only apply signatures to functions that have the default signature
                    if (function.getSignatureSource() == SourceType.DEFAULT) {
                        var success = new ApplyFunctionSignatureCmd(
                                function.getEntryPoint(),
                                functionSignatureMessageOpt.get(),
                                SourceType.ANALYSIS
                        ).applyTo(analysedProgram.program(), monitor);
                        // For unclear reasons the signature source is not set by the command in Ghidra 11.2.x and lower
                        if (success) {
                            renameResults.add(new RenameResult(
                                    function,
                                    ghidraMangledName,
                                    revEngDemangledName
                            ));
                        } else {
                            Msg.error(this, "Failed to apply signature to function %s".formatted(function.getName()));
                            failedRenames++;
                        }
                    }
                }
            }


        }
        // Done iterating over all functions. If nothing changed, discard the transaction, to keep undo history clean
        analysedProgram.program().endTransaction(transactionId, !renameResults.isEmpty() && !monitor.isCancelled());
        if (failedRenames > 0){
            Msg.showError(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Function Update Summary",
                    ("Failed to update %d functions from RevEng.AI. Please check the error log for details.").formatted(
                            failedRenames
                    ));
        }
        return renameResults;
    }

    /**
     * Get the FunctionID for a Ghidra Function, if there is one
     * There are two cases where a function ID is missing:
     * 1. Either the whole program has not been analyzed
     * (because its bounds were not included when the analysis was triggered)
     *
     * @deprecated Use {@link AnalysedProgram#getIDForFunction(Function)} instead. It forces the caller to prove that they know that the {@link Program} is indeed known on the server and associated by having to provide a {@link AnalysedProgram} instance.
     */
    @Deprecated
    public Optional<TypedApiInterface.FunctionID> getFunctionIDFor(Function function){
        return getAnalysedProgram(function.getProgram())
                .flatMap(knownProgram -> knownProgram.getIDForFunction(function).map(fidWithStatus -> fidWithStatus.functionID));
    }

    /**
     * Get the Ghidra Function for a given FunctionInfo if there is one
     */
    private Optional<Function> getFunctionFor(FunctionInfo functionInfo, Program program){
        // These addresses used to be relative, but are now absolute again
        var defaultAddressSpace = program.getAddressFactory().getDefaultAddressSpace();
        var funcAddress = defaultAddressSpace.getAddress(functionInfo.functionVirtualAddress());
        var func = program.getFunctionManager().getFunctionAt(funcAddress);

        return Optional.ofNullable(func);
    }

    @Deprecated
    public List<LegacyAnalysisResult> searchForHash(TypedApiInterface.BinaryHash hash){
        return api.search(hash);
    }

    public void removeProgramAssociation(Program program){
        // Clear all function ID data
        program.getUsrPropertyManager().removePropertyMap(REAI_FUNCTION_PROP_MAP);
        program.getUsrPropertyManager().removePropertyMap(REAI_FUNCTION_MANGLED_MAP);
        var reaiOptions = program.getOptions(ReaiPluginPackage.REAI_OPTIONS_CATEGORY);
        //noinspection deprecation
        reaiOptions.setLong(ReaiPluginPackage.OPTION_KEY_BINID, ReaiPluginPackage.INVALID_BINARY_ID);
        reaiOptions.setLong(OPTION_KEY_ANALYSIS_ID, ReaiPluginPackage.INVALID_ANALYSIS_ID);
        // Clear the entire cache. Getting the correct ID is not worth the effort in terms of edge cases to handle
        // because this method should still work even if the analysis ID or binary ID that was associated is invalid
        statusCache.clear();

    }

    /// This method is private to the service, because it only concerns itself with how the service determines
    /// this internally
    /// Plugin code that wants to know if a program is known should use {@link #getAnalysedProgram(Program)} and check
    /// if the result is present
    private boolean isProgramAnalysed(Program program){
        return program.getUsrPropertyManager().getLongPropertyMap(REAI_FUNCTION_PROP_MAP) != null &&
                program.getUsrPropertyManager().getStringPropertyMap(REAI_FUNCTION_MANGLED_MAP) != null;
    }

    /**
     * Returns whether a function is relevant for sending to the RevEng.AI backend.
     * External and thunk functions are excluded because the backend cannot process them.
     */
    public static boolean isRelevantForAnalysis(Function function) {
        return !function.isExternal() && !function.isThunk();
    }

    public static List<FunctionBoundary> exportFunctionBoundaries(Program program){
        List<FunctionBoundary> result = new ArrayList<>();
        Address imageBase = program.getImageBase();
        program.getFunctionManager().getFunctions(true).forEach(
                function -> {
                    if (!isRelevantForAnalysis(function)) {
                        return;
                    }
                    var start = function.getEntryPoint();
                    var end = function.getBody().getMaxAddress();
                    result.add(new FunctionBoundary(function.getSymbol().getName(false), start.getOffset(), end.getOffset()));
                }
        );
        return result;
    }

    /**
     * Export function boundaries for a specific list of functions.
     *
     * @param program The program containing the functions
     * @param functions The list of functions to export
     * @return List of function boundaries for the specified functions
     */
    public static List<FunctionBoundary> exportFunctionBoundaries(Program program, List<Function> functions) {
        List<FunctionBoundary> result = new ArrayList<>();
        for (Function function : functions) {
            var start = function.getEntryPoint();
            var end = function.getBody().getMaxAddress();
            result.add(new FunctionBoundary(function.getSymbol().getName(false), start.getOffset(), end.getOffset()));
        }
        return result;
    }

    private TypedApiInterface.BinaryHash hashOfProgram(Program program) {
        // TODO: we break the guarantee that a BinaryHash implies that a file of this hash has already been uploaded
        return new TypedApiInterface.BinaryHash(program.getExecutableSHA256());
    }

    public TypedApiInterface.BinaryHash upload(Program program) {
        // TODO: Check if the program is already uploaded on the server
        // But this requires a dedicated API to do cleanly

        Path filePath;
        try {
            filePath = Path.of(program.getExecutablePath());
        } catch (InvalidPathException e) {
            // For windows the returned String isn't a valid input to Path.of
            //  because they look like "/C:/vfcompat.dll"
            // we have to drop the first "/" for the path to be valid
            filePath = Path.of(program.getExecutablePath().substring(1));
        }
        try {
            var hash = api.upload(filePath);
            if (hash.equals(hashOfProgram(program))){
                // TODO: Save the information that this program has been uploaded
//                program.getOptions(REAI_OPTIONS_CATEGORY).setBoolean(ReaiPluginPackage.OPTION_KEY_BINID, hash.value());
                return hash;
            } else {
                // This means the file on disk has
                throw new RuntimeException(
                        "Hash of uploaded file %s from path %s doesn't match the hash of the program loaded in Ghidra %s"
                                .formatted(hash, program.getExecutablePath(), hashOfProgram(program)));
            }
        } catch (FileNotFoundException | ApiException e) {
            throw new RuntimeException(e);
        }
    }

    public TypedApiInterface.BinaryHash upload(Path path) {
        try {
            return api.upload(path);
        } catch (FileNotFoundException | ApiException e) {
            throw new RuntimeException(e);
        }
    }

    @Deprecated
    public AnalysisStatus pollStatus(BinaryID bid) {
        try {
            return api.status(bid);
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }

    ///  Use this method if you just have an AnalysisID and it is not clear yet if it can be accessed
    public AnalysisStatus pollStatus(TypedApiInterface.AnalysisID id) throws ApiException {
        return api.status(id);
    }

    public AnalysisStatus status(ProgramWithID program) {
        try {
            return api.status(program.analysisID());
        } catch (ApiException e) {
            // This should never happen given that `ProgramWithID` guarantees a valid analysis ID
            throw new RuntimeException(e);
        }
    }



    public String decompileFunctionViaAI(FunctionWithID functionWithID, TaskMonitor monitor, AIDecompilationdWindow window) {
        monitor.setMaximum(100 * 50);
        // Check if there is an existing process already, because the trigger API will fail with 400 if there is
        var fID = functionWithID.functionID;
        var function = functionWithID.function;
        if (api.pollAIDecompileStatus(fID).getStatus().equals("uninitialised")){
            // Trigger the decompilation
            api.triggerAIDecompilationForFunctionID(fID);
        }

        String lastStatus;

        while (true) {
            if (monitor.isCancelled()) {
                return "Decompilation cancelled";
            }
            var status = api.pollAIDecompileStatus(fID);
            window.setDisplayedValuesBasedOnStatus(function, status);

            switch (status.getStatus()) {
                case "pending":
                case "uninitialised":
                case "queued":
                case "running":
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }
//                    monitor.incrementProgress(100);
                    break;
                case "success":
                    monitor.setProgress(monitor.getMaximum());
                    window.setDisplayedValuesBasedOnStatus(function, status);
                    return status.getDecompilation();
                case "error":
                    return "Decompilation failed: %s".formatted(status.getStatus());
                default:
                    throw new RuntimeException("Unknown status: %s".formatted(status.getStatus()));
            }



        }
    }

    ///  This method analyses a program by uploading it (if necessary), triggering an analysis, and _blocking_
    /// until the analysis is complete. This is for scripts and tests, and must not be used on the UI thread
    /// It does not upload the program, this must be done beforehand, and the hash must be associated via {@link AnalysisOptionsBuilder#hash(TypedApiInterface.BinaryHash)}
    public AnalysedProgram analyse(Program program, AnalysisOptionsBuilder analysisOptionsBuilder, TaskMonitor monitor) throws CancelledException, ApiException {
        // Check if we are on the swing thread
        var programWithBinaryID = startAnalysis(program, analysisOptionsBuilder);
        var finalStatus = waitForFinishedAnalysis(monitor, programWithBinaryID, null, null);
        // TODO: Check final status for errors, and do something appropriate on failure
        var analysedProgram = registerFinishedAnalysisForProgram(programWithBinaryID, monitor);
        if (getKnownProgram(program).isEmpty()){
            throw new IllegalStateException("Program is not known after finished analysis. Something seriously went wrong.");
        }
        return analysedProgram;
    }

    /// Get the {@link ProgramWithID} for a known program
    /// This only guarantees an associated analysis, not that it is finished
    public Optional<ProgramWithID> getKnownProgram(Program program) {
        var analysisID = getAnalysisIDFor(program);
        return analysisID.map(id -> new ProgramWithID(program, id));
    }

    /// Get the {@link AnalysedProgram} for a known and analysed program
    public Optional<AnalysedProgram> getAnalysedProgram(Program program) {
        var kProg = getKnownProgram(program);
        if (kProg.isEmpty()){
            return Optional.empty();
        }
        if (isProgramAnalysed(kProg.get().program())){
            return Optional.of(new AnalysedProgram(kProg.get().program(), kProg.get().analysisID()));
        }
        return Optional.empty();
    }

    /**
     * Create a {@link FunctionDefinitionDataType} from a @{@link FunctionInfoOutput} in isolation
     *
     * All the required dependency types will be stored in the DataTypeManager that is associated with this
     * FunctionDefinitionDataType
     *
     * @param functionDataTypeMessage The message containing the function signature, received from the API
     * @return Self-contained signature for the function
     */
    public static Optional<FunctionDefinitionDataType> getFunctionSignature(FunctionInfoOutput functionDataTypeMessage) throws DataTypeDependencyException {

        // Create Data Type Manager with all dependencies
        var d = FunctionDependencies.fromOpenAPI(functionDataTypeMessage.getFuncDeps());
        DataTypeManager tmpDtm = null;
        try {
            tmpDtm = loadDependencyDataTypes(d);
        } catch (EndlessTypeParsingException e) {
            Msg.error("getFunctionSignature", null, e);
            return Optional.empty();
        }
        DataTypeManager dtm = tmpDtm;

        if (functionDataTypeMessage.getFuncTypes() == null){
            return Optional.empty();
        }
        var funcName = functionDataTypeMessage.getFuncTypes().getName();
        FunctionDefinitionDataType f = new FunctionDefinitionDataType(funcName, dtm);

        try {
            f.setName(funcName);
        } catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }

        ParameterDefinitionImpl[] args = functionDataTypeMessage.getFuncTypes().getHeader().getArgs().values().stream().map(
                arg -> {
                    DataType ghidraType = null;
                    try {
                        var scopedName = TypePathAndName.fromString(arg.getType());
                        ghidraType = loadDataType(dtm, scopedName);
                    } catch (DataTypeDependencyException e) {
                        Msg.error(GhidraRevengService.class,
                                ("" +
                                        "Couldn't find type '%s' for param of %s").formatted(arg.getType(), funcName)
                        );
                        ghidraType = Undefined.getUndefinedDataType(arg.getSize());
                    }
                    // Add the type to the DataTypeManager
                    return new ParameterDefinitionImpl(arg.getName(), ghidraType, null);
                }).toArray(ParameterDefinitionImpl[]::new);

        f.setArguments(args);

        DataType returnType = null;
        returnType = loadDataType(dtm, TypePathAndName.fromString(functionDataTypeMessage.getFuncTypes().getHeader().getType()));
        f.setReturnType(returnType);


        return Optional.of(f);
    }

    public static class EndlessTypeParsingException extends Exception {

        public FunctionDependencies deps;
        public List<Typedef> remaining;
        private EndlessTypeParsingException(FunctionDependencies dependencies, List<Typedef> remainingTypes) {
            super("Endless type parsing detected for function dependencies: " + dependencies);
            deps = dependencies;
            remaining = remainingTypes;

        }
    }

    public static DataTypeManager loadDependencyDataTypes(FunctionDependencies dependencies) throws EndlessTypeParsingException{
        DataTypeManager dtm = new StandAloneDataTypeManager("transient");

        if (dependencies == null){
            return dtm;
        }
        DataTypeParser dataTypeParser = new DataTypeParser(
                dtm,
                null,
                null,
                DataTypeParser.AllowedDataTypes.ALL);

        // We do this in two passes:

        // First add all types as empty placeholders
        var transactionId = dtm.startTransaction("Load Dependencies");
        Arrays.stream(dependencies.structs()).forEach(
                struct -> {
//                        CategoryPath path = new CategoryPath(CategoryPath.ROOT, struct.name().split("/"));
                        var typePathAndName = TypePathAndName.fromString(struct.name());
                        StructureDataType structDataType = new StructureDataType(
                                typePathAndName.toCategoryPath(),
                                typePathAndName.name(),
                                struct.size(),
                                dtm);
                        dtm.addDataType(structDataType, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
                }
        );
        // The following would be a lot nicer of BinSync could guarantee us that all dependencies are sorted
        // As a workaround we just retry until all types are available
        // In some cases (specifically bugs in BinSync when dependencies are missing) this will loop forever by default
        // To work around _that_ we have a limit of 1000 retries
        Queue<Typedef> typeDefsToAdd = Arrays.stream(dependencies.typedefs()).collect(Collectors.toCollection(LinkedList::new));
        int retries = 0;
        while (!typeDefsToAdd.isEmpty()){
            if (retries > 1000){
                dtm.endTransaction(transactionId, false);
                dtm.close();
                throw new EndlessTypeParsingException(dependencies, typeDefsToAdd.stream().toList());
            }
            var typeDef = typeDefsToAdd.remove();
            var path = TypePathAndName.fromString(typeDef.name());
            DataType type;
            try {
                var scopedType = TypePathAndName.fromString(typeDef.type());
                type = dataTypeParser.parse(scopedType.name());
            } catch (InvalidDataTypeException e) {
                // The type wasn't available in the DataTypeManager yet, try again later
                typeDefsToAdd.add(typeDef);
                retries++;
                continue;
            } catch (CancelledException e) {
                throw new RuntimeException(e);
            }
            TypedefDataType typedefDataType = new TypedefDataType(path.toCategoryPath(), path.name(), type, null);
            dtm.addDataType(typedefDataType, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
        }

        // Now we have all necessary types, we can fill out the structs
        Arrays.stream(dependencies.structs()).forEach(
                struct -> {
                    var path = TypePathAndName.fromString(struct.name());
                    // Get struct type
                    var type = dtm.getDataType(path.toCategoryPath(), path.name());
                    if (type instanceof Structure structType) {
                        Arrays.stream(struct.members()).forEach(
                                binSyncStructMember -> {
                                    DataType fieldType = null;
                                    try {
                                        fieldType = loadDataType(dtm, TypePathAndName.fromString(binSyncStructMember.type()));
                                    } catch (DataTypeDependencyException e) {
                                        Msg.error(
                                                GhidraRevengService.class,
                                                "Couldn't find type '%s' for field of %s".formatted(binSyncStructMember.type(), struct.name())
                                        );
                                        fieldType = Undefined.getUndefinedDataType(binSyncStructMember.size());
                                    }
                                    structType.replaceAtOffset(
                                            binSyncStructMember.offset(),
                                            fieldType,
                                            binSyncStructMember.size(),
                                            binSyncStructMember.name(),
                                            null
                                    );
                                }
                        );
                    } else {
                        throw new RuntimeException("Struct type not found: %s".formatted(struct.name()));
                    }

                }
        );

        dtm.endTransaction(transactionId, true);
        return dtm;
    }

    private static DataType loadDataType(DataTypeManager dtm, TypePathAndName type) throws DataTypeDependencyException {
        DataTypeParser dataTypeParser = new DataTypeParser(
                dtm,
                null,
                null,
                DataTypeParser.AllowedDataTypes.ALL);
        DataType dataType;
        try {
            dataType = dataTypeParser.parse(type.name());
        } catch (InvalidDataTypeException e) {
            // The type wasn't available in the DataTypeManager, so we have to find it in the dependencies
            throw new DataTypeDependencyException("Data type not found in DataTypeManager: %s".formatted(type), e);
        } catch (CancelledException e) {
            throw new RuntimeException(e);
        }
        return dataType;
    }

    public String getAnalysisLog(TypedApiInterface.AnalysisID analysisID) {
        return api.getAnalysisLogs(analysisID);
    }

    /**
     * Get the "name score" confidence of a match via the new API.
     * The old kind of confidence is now called similarity
     *
     * @param functionMatch the match to get the confidence for
     * @return the confidence of the match
     */
    public BoxPlot getNameScoreForMatch(GhidraFunctionMatch functionMatch) {
        var functionNameScore = api.getNameScore(functionMatch.functionMatch());
        return functionNameScore.score();

    }

    public void openFunctionInPortal(TypedApiInterface.FunctionID functionID) {
        var details = api.getFunctionDetails(functionID);
        openPortal("analyses", String.format("%s?fn=%s", details.analysisId().id(), functionID.value()));
    }

    public void openCollectionInPortal(Collection collection) {
        openPortal("collections/", String.valueOf(collection.collectionID().id()));
    }

    public void openPortalFor(Collection c){
        openCollectionInPortal(c);
    }
    public void openPortalFor(TypedApiInterface.FunctionID f){
        openFunctionInPortal(f);
    }

    public void openPortalFor(FunctionWithID functionWithID) {
        openPortalFor(functionWithID.functionID);
    }

    public void openPortalFor(AnalysisResult analysisResult) {
        openPortalFor(analysisResult.analysisID());
    }

    public void openPortalFor(ProgramWithID programWithID) {
        openPortalFor(programWithID.analysisID());
    }

    public void openPortalFor(TypedApiInterface.AnalysisID analysisID) {
        openPortal("analyses", String.valueOf(analysisID.id()));
    }

    public void openPortal(String... subPath) {
        StringBuilder sb = new StringBuilder(apiInfo.portalURI().toString());
        for (String s : subPath) {
            if (!s.startsWith("?")){
                sb.append("/");
            }
            sb.append(s);
        }
        openURI(URI.create(sb.toString()));
    }

    private void openURI(URI uri){
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)
        ) {
            try {
                Desktop.getDesktop().browse(uri);
            } catch (IOException e) {
                Msg.showError(
                        this,
                        null,
                        "URI Opening Failed",
                        "Browsing to URI %s failed".formatted(uri),
                        e
                );
            }
        } else {
            Msg.showError(
                    this,
                    null,
                    "URI Opening unsupported",
                    "URI %s couldn't be opened because the environment doesn't support opening URLs".formatted(uri)
            );

        }
    }


    public void setActiveCollections(List<Collection> collections){
        Msg.info(this, "Setting active collections to %s".formatted(collections));
        this.collections.clear();
        this.collections.addAll(collections);
    }

    public List<Collection> getActiveCollections() {
        return Collections.unmodifiableList(this.collections);
    }

    public void setAnalysisIDMatchFilter(List<AnalysisResult> analysisIDS) {
        this.analysisIDFilter.clear();
        this.analysisIDFilter.addAll(analysisIDS);
    }

    public List<AnalysisResult> getActiveAnalysisIDsFilter() {
        return Collections.unmodifiableList(this.analysisIDFilter);
    }

    /**
     * @param tool   The UI tool for firing an event on status changes. Can be null
     * @return The final AnalysisStatus, should be either Complete or Error
     */
    public AnalysisStatus waitForFinishedAnalysis(
            TaskMonitor monitor,
            ProgramWithID programWithID,
            @Nullable AnalysisLogConsumer logger,
            @Nullable PluginTool tool

            ) throws CancelledException {
        monitor.setMessage("Checking analysis status");
        // Check the status of the analysis every 500ms
        // TODO: In the future this can be made smarter and e.g. wait longer if the analysis log hasn't changed
        AnalysisStatus lastStatus = null;
        while (true) {
            AnalysisStatus currentStatus = this.status(programWithID);
            if (currentStatus != AnalysisStatus.Queued) {
                // Analysis log endpoint only starts to return data after the analysis is processing
                String logs = this.getAnalysisLog(programWithID.analysisID());
                if (logger != null) {
                    logger.consumeLogs(logs, programWithID);
                }
                var logsLines = logs.lines().toList();
                var lastLine = logsLines.get(logsLines.size() - 1);
                monitor.setMessage(lastLine);
            }
            if (currentStatus != lastStatus) {
                lastStatus = currentStatus;
                if (tool != null){
                    tool.firePluginEvent(new RevEngAIAnalysisStatusChangedEvent(null, programWithID, currentStatus));
                }
            }

            if (lastStatus == AnalysisStatus.Complete || lastStatus == AnalysisStatus.Error) {
                // Show the UI message for the completion
                return lastStatus;
            }
            monitor.checkCancelled();
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                return lastStatus;
            }
        }
    }

    public ProgramWithID startAnalysis(Program program, AnalysisOptionsBuilder analysisOptionsBuilder) throws ApiException {
        var analysisID = api.analyse(analysisOptionsBuilder);

        return addAnalysisIDtoProgramOptions(program, analysisID);
    }

    public Map<GhidraFunctionMatch, BoxPlot> getNameScores(java.util.Collection<GhidraFunctionMatch> values) {
        // Get the confidence scores for each match in the input
        List<FunctionNameScore> r =  api.getNameScores(values.stream().map(GhidraFunctionMatch::functionMatch).toList(), false);
        // Collect to a Map from the FunctionID to the actual score
        Map<TypedApiInterface.FunctionID, BoxPlot> plots = r.stream().collect(Collectors.toMap(FunctionNameScore::functionID, FunctionNameScore::score));
        return values.stream().collect(Collectors.toMap(
                match -> match,
                match -> plots.get(match.functionMatch().origin_function_id())
        ));
    }

    /**
     * Collects the signatures for the matched functions, if they have already been computed (and finished)
     * @param values
     * @return
     */
    public Map<GhidraFunctionMatch, FunctionDefinitionDataType> getSignatures(java.util.Collection<GhidraFunctionMatch> values) {


        // Get all data type info for the neighbour functions
        var dataTypesList = this.api.listFunctionDataTypesForFunctions(
                values.stream().map(GhidraFunctionMatch::nearest_neighbor_id).toList()
        );
        // Create a map from FunctionID to FunctionInfoOutput for easy lookup, only for completed signatures
        Map<TypedApiInterface.FunctionID, @NotNull FunctionInfoOutput> signatureMap = dataTypesList.getItems().stream()
                // Only keep completed signatures
                .filter(FunctionDataTypesListItem::getCompleted)
                // Double check that there is a data type available
                .filter(functionDataTypesListItem -> functionDataTypesListItem.getDataTypes() != null)
                .collect(Collectors.toMap(
                        item -> new TypedApiInterface.FunctionID(item.getFunctionId()),
                        FunctionDataTypesListItem::getDataTypes
                ));

        Map<GhidraFunctionMatch, @NotNull FunctionInfoOutput> matchMap =  values.stream()
                .filter(match -> signatureMap.containsKey(match.functionMatch().nearest_neighbor_id()))
                .collect(Collectors.toMap(
                match -> match,
                match -> signatureMap.get(match.functionMatch().nearest_neighbor_id())
        ));

        // Now parse all signatures
        Map<GhidraFunctionMatch, FunctionDefinitionDataType> result = new HashMap<>();
        for (var entry : matchMap.entrySet()){
            try {
                var funcDefOpt = getFunctionSignature(entry.getValue());
                funcDefOpt.ifPresent(funcDef -> result.put(entry.getKey(), funcDef));
            } catch (DataTypeDependencyException e) {
                Msg.error(this, "Could not parse signature for function %s".formatted(entry.getKey().functionMatch()), e);
            }
        }
        return result;

    }

    public CompletableFuture<List<SelectableItem>> searchCollectionsWithIds(String query, String modelName) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Call the actual API endpoint
                List<CollectionSearchResult> results = api.searchCollections(query, modelName);

                // Convert to SelectableItem objects with both ID and name
                List<SelectableItem> selectableItems = results.stream()
                        .filter(result -> !result.getCollectionName().trim().isEmpty())
                        .map(result -> new SelectableItem(
                                result.getCollectionId(),
                                result.getCollectionName()
                        ))
                        .collect(Collectors.toList());

                Msg.info(this, "Found " + selectableItems.size() + " collections matching '" + query + "'");
                return selectableItems;

            } catch (Exception e) {
                Msg.error(this, "Error searching collections: " + e.getMessage(), e);
                return List.of();
            }
        });
    }

    public CompletableFuture<List<SelectableItem>> searchBinariesWithIds(String query, String modelName) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Call the actual API endpoint
                List<BinarySearchResult> results = api.searchBinaries(query, modelName);

                // Convert to SelectableItem objects with both ID and name
                List<SelectableItem> selectableItems = results.stream()
                        .filter(result -> !result.getBinaryName().trim().isEmpty())
                        .map(result -> new SelectableItem(
                                result.getAnalysisId(),
                                result.getBinaryName()
                        ))
                        .collect(Collectors.toList());

                Msg.info(this, "Found " + selectableItems.size() + " binaries matching '" + query + "'");
                return selectableItems;

            } catch (Exception e) {
                Msg.error(this, "Error searching binaries: " + e.getMessage(), e);
                return List.of();
            }
        });
    }

    public Basic getBasicDetailsForAnalysis(TypedApiInterface.AnalysisID analysisID) throws ApiException {
        return api.getAnalysisBasicInfo(analysisID);
    }

    public FunctionMatchingResponse getFunctionMatchingForAnalysis(TypedApiInterface.AnalysisID analysisID, AnalysisFunctionMatchingRequest request) throws ApiException {
        return api.analysisFunctionMatching(analysisID, request);
    }

    public FunctionMatchingResponse getFunctionMatchingForFunction(FunctionMatchingRequest request) throws ApiException {
        return api.functionFunctionMatching(request);
    }

    public void batchRenamingGhidraMatchesWithSignatures(List<GhidraFunctionMatchWithSignature> functionsList) throws ApiException {
        // Pushing types to the portal is not supported yet, so we just extract the function matches and call the other method
        batchRenameMatches(functionsList.stream()
                .map(GhidraFunctionMatchWithSignature::functionMatch)
                .toList());

    }

    public void batchRenameGhidraMatches(List<GhidraFunctionMatch> functionsList) throws ApiException {
        var matches = functionsList.stream()
                .map(GhidraFunctionMatch::functionMatch)
                .toList();
        batchRenameMatches(matches);
    }

    public void batchRenameMatches(List<FunctionMatch> functionsList) throws ApiException {
        var matches = functionsList.stream()
                .map(result -> {
                    var func = new FunctionRenameMap();
                    func.setFunctionId(result.origin_function_id().value());
                    func.setNewName(result.nearest_neighbor_function_name());
                    func.setNewMangledName(result.nearest_neighbor_mangled_function_name());
                    return func;
                })
                .toList();

        var functionsListRename = new FunctionsListRename();
        functionsListRename.setFunctions(matches);

        api.batchRenameFunctions(functionsListRename);
    }


    public TypedApiInterface.TypedAutoUnstripResponse autoUnstrip(AnalysedProgram program) throws ApiException {
        return api.autoUnstrip(program.analysisID);
    }


    /// Old Helper Datatype that encapsulates a Ghidra program with a binary ID and analysis ID
    /// This only guarantees that the program has an associated analysis, but not that the analysis is finished
    /// The id of this should also be stored in the program options, but this is currently not enforced yet to allow easier testing
    public record ProgramWithID(
            Program program,
            TypedApiInterface.AnalysisID analysisID
    ){}




    /// All functions that require a program to have a finished analysis on the portal can use this to encode this assumption into the type system
    /// This guarantees that Ghidra Functions that exist on the server can be mapped to Function IDs
    /// This rules out the two cases:
    /// * the program has no associated analysis on the server
    /// * the program has an associated analysis, but analysis hasn't finished yet
    public static class AnalysedProgram {

        private final Program program;
        private final TypedApiInterface.AnalysisID analysisID;


        /// The constructor is private to enforce that only the GhidraRevengService class
        /// can create instances of this class, ensuring the guarantees hold
        private AnalysedProgram(
                Program program,
                TypedApiInterface.AnalysisID analysisID
        ) {
            this.program = program;
            this.analysisID = analysisID;

        }

        public Program program() {
            return program;
        }

        public TypedApiInterface.AnalysisID analysisID() {
            return analysisID;
        }

        private LongPropertyMap getFunctionIDPropertyMap(AnalysedProgram program){
            var map = program.program().getUsrPropertyManager().getLongPropertyMap(REAI_FUNCTION_PROP_MAP);
            if (map == null){
                throw new IllegalStateException("Function ID property map not found for supposedly known program %s".formatted(program.program().getName()));
            }
            return map;
        }

        /// Only returns Optional.Empty if the function is not known on the server (e.g. because it's a thunk)
        public Optional<FunctionWithID> getIDForFunction(Function function) {
            if (function == null) {
                Msg.error(AnalysedProgram.class, "Function provided to getIDForFunction is null");
                return Optional.empty();
            }
            if (function.getProgram() != this.program){
                throw new IllegalArgumentException("Function %s does not belong to program %s".formatted(function, this.program.getName()));
            }
            LongPropertyMap functionIDMap = getFunctionIDPropertyMap(this);
            var rawId = functionIDMap.get(function.getEntryPoint());
            return Optional
                    .ofNullable(rawId)
                    .map(TypedApiInterface.FunctionID::new)
                    .map(
                            functionID -> new FunctionWithID(function, functionID)
                    );
        }

        /// Warning: Using this map means having to verify that the function ID has an associated function
        ///
        /// `getFunctionMap.get(functionID)` can return `null`
        public BiMap<TypedApiInterface.FunctionID, Function> getFunctionMap(){
            var propMap = getFunctionIDPropertyMap(this);

            BiMap<TypedApiInterface.FunctionID, Function> functionMap = HashBiMap.create();
            propMap.getPropertyIterator().forEachRemaining(
                    addr -> {
                        var func = program.getFunctionManager().getFunctionAt(addr);

                        try {
                            functionMap.put(new TypedApiInterface.FunctionID(propMap.getLong(addr)), func);
                        } catch (NoValueException e) {
                            // This should never happen, because we're iterating over the keys
                            throw new RuntimeException(e);
                        }
                    }
            );
            return functionMap;
        }


        public Optional<FunctionWithID> getFunctionForID(TypedApiInterface.FunctionID functionID) {
            throw new UnsupportedOperationException("Not implemented yet");
        }

        public void setMangledNameForFunction(Function function, String mangledName) {
            if (function.getProgram() != this.program){
                throw new IllegalArgumentException("Function %s does not belong to program %s".formatted(function, this.program.getName()));
            }
            StringPropertyMap mangledNameMap = this.program.getUsrPropertyManager().getStringPropertyMap(REAI_FUNCTION_MANGLED_MAP);
            if (mangledNameMap == null){
                throw new IllegalStateException("Mangled name property map not found for supposedly known program %s".formatted(this.program.getName()));
            }
            mangledNameMap.add(function.getEntryPoint(), mangledName);
        }

        public String getMangledNameForFunction(Function function) {
            if (function.getProgram() != this.program){
                throw new IllegalArgumentException("Function %s does not belong to program %s".formatted(function, this.program.getName()));
            }
            StringPropertyMap mangledNameMap = this.program.getUsrPropertyManager().getStringPropertyMap(REAI_FUNCTION_MANGLED_MAP);
            if (mangledNameMap == null){
                throw new IllegalStateException("Mangled name property map not found for supposedly known program %s".formatted(this.program.getName()));
            }
            return mangledNameMap.getString(function.getEntryPoint());
        }


    }

    /// Holding this object serves as the proof that a Function has an associated FunctionID
    public static record FunctionWithID(
            Function function,
            TypedApiInterface.FunctionID functionID
    ) {}
}

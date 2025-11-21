package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.SelectableItem;
import ai.reveng.toolkit.ghidra.core.AnalysisLogConsumer;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionBoundary;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler.AIDecompilationdWindow;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.MockApi;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.Collection;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.APIAuthenticationException;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Structure;
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
import ghidra.util.exception.NoValueException;
import ghidra.util.task.TaskMonitor;

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
    private Map<BinaryID, AnalysisStatus> statusCache = new HashMap<>();

    private TypedApiInterface api;
    private ApiInfo apiInfo;
    private final List<Collection> collections = new ArrayList<>();
    private final List<AnalysisResult> analysisIDFilter = new ArrayList<>();

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

    public void registerFinishedAnalysisForProgram(ProgramWithBinaryID programWithBinaryID, TaskMonitor monitor) throws ApiException {
        statusCache.put(programWithBinaryID.binaryID(), AnalysisStatus.Complete);

        // Add the binary to the program before loading the function info. Checking that a function is present requires
        // the binary ID to be present in the program options.
        addBinaryIDtoProgramOptions(programWithBinaryID.program(), programWithBinaryID.binaryID());

        associateFunctionInfo(programWithBinaryID.program(), programWithBinaryID.binaryID());
        pullFunctionInfoFromAnalysis(programWithBinaryID, monitor);
    }

    public void addBinaryIDtoProgramOptions(Program program, BinaryID binID){
        var transactionId = program.startTransaction("Associate Binary ID with Program");
        program.getOptions(ReaiPluginPackage.REAI_OPTIONS_CATEGORY)
                .setLong(ReaiPluginPackage.OPTION_KEY_BINID, binID.value());
        program.endTransaction(transactionId, true);
    }

    /**
     * Tries to find a BinaryID for a given program
     * If the program already has a BinaryID associated with it, it will return that
     * If we don't have a BinaryID it will return an empty Optional
     * @param program
     * @return
     */
    public Optional<BinaryID> getBinaryIDFor(Program program) {
        Optional<BinaryID> binID;
        try {
            binID = getBinaryIDfromOptions(program);
        } catch (InvalidBinaryID e) {
            Msg.error(this, "Invalid Binary ID found in program options: %s".formatted(e.getMessage()));
            return Optional.empty();
        }
        return binID;

    }

    public Optional<AnalysisID> getAnalysisIDFor(Program program){
        return getBinaryIDFor(program).map(binID -> api.getAnalysisIDfromBinaryID(binID));
    }


    public Optional<BinaryID> getBinaryIDfromOptions(
            Program program
    ) throws InvalidBinaryID {
        long bid = program.getOptions(
                ReaiPluginPackage.REAI_OPTIONS_CATEGORY).getLong(ReaiPluginPackage.OPTION_KEY_BINID,
                ReaiPluginPackage.INVALID_BINARY_ID);
        if (bid == ReaiPluginPackage.INVALID_BINARY_ID) {
            return Optional.empty();
        }
        var binID = new BinaryID((int) bid);
        if (!statusCache.containsKey(binID)) {
            // Check that it's really valid in the context of the currently configured API
            try {
                var status = api.status(binID);
                statusCache.put(binID, status);
            } catch (APIAuthenticationException | ApiException e) {
                throw new InvalidBinaryID(binID, this.apiInfo);
            }
            // Now it's certain that it is a valid binary ID
        }

        return Optional.of(binID);
    }

    /// Loads the function info into a dedicated user property map.
    /// This method should only concern itself with associating the FunctionID with the Ghidra Function
    /// This property is immutable within an Analysis: The function ID will never change unless an entirely different
    /// analysis is associated with the program
    /// Other function information like the name and signature should be loaded in [#pullFunctionInfoFromAnalysis(ProgramWithBinaryID,TaskMonitor)]
    /// because this information can change on the server, and thus needs a dedicated method to refresh it
    private void associateFunctionInfo(Program program, BinaryID binID) throws ApiException {
        List<FunctionInfo> functionInfo = api.getFunctionInfo(binID);
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
        for (FunctionInfo info : functionInfo) {
            var oFunc = getFunctionFor(info, program);
            if (oFunc.isEmpty()) {
                Msg.error(this, "Function not found in Ghidra for info: %s".formatted(info));
                continue;
            }
            var func = oFunc.get();
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

        AtomicInteger ghidraFunctionCount = new AtomicInteger();
        program.getFunctionManager().getFunctions(true).forEach(
                func -> {
                    if (!func.isExternal() && !func.isThunk()){
                        ghidraFunctionCount.getAndIncrement();

                        if (getFunctionIDFor(func).isEmpty()) {
                            Msg.info(this, "Function %s not found in RevEng.AI".formatted(func.getSymbol().getName(false)));
                        }
                    }
                }
        );
        program.endTransaction(transactionID, true);

        // Print summary
        Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Function loading summary",
            ("Found %d functions from RevEng.AI. Your local Ghidra instance has %d/%d matching function " +
                "boundaries. For better results, please start a new analysis from this plugin.").formatted(
                functionInfo.size(),
                ghidraBoundariesMatchedFunction,
                ghidraFunctionCount.get()
        ));
    }


    /// Pull the server side information about the functions from a remote Analysis and update the local {@link Program}
    /// based on it
    /// This currently includes:
    /// * the name of the function
    /// * the type signature of the function
    ///
    /// It assumes that the initial load already happened, i.e. the functions have an associated FunctionID already.
    /// The initial association happens in {@link #associateFunctionInfo(Program, BinaryID)}
    ///
    public void pullFunctionInfoFromAnalysis(ProgramWithBinaryID programWithBinaryID, TaskMonitor monitor) {
        var transactionId = programWithBinaryID.program().startTransaction("RevEng.AI: Pull Function Info from Analysis");

        StringPropertyMap mangledNameMap = programWithBinaryID.program()
                .getUsrPropertyManager()
                .getStringPropertyMap(REAI_FUNCTION_MANGLED_MAP);


        int ghidraRenamedFunctions;
        ghidraRenamedFunctions = 0;

        int failedRenames = 0;
        for (Function function : programWithBinaryID.program().getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) {
                continue;
            }
            var ghidraMangledName = function.getSymbol().getName(false);
            // Skip external and thunk functions because we don't support them
            if (function.isExternal() || function.isThunk()) {
                Msg.debug(this, "Skipping external/thunk function %s".formatted(ghidraMangledName));
                continue;
            }

            var fID = getFunctionIDFor(function);
            if (fID.isEmpty()) {
                Msg.info(this, "Function %s has no associated FunctionID, skipping".formatted(function.getName()));
                continue;
            }

            // Get the current name on  the server side
            FunctionDetails details = api.getFunctionDetails(fID.get());
            var serverMangledName = details.functionName();

            // Extract the mangled name from Ghidra
            var revEngMangledName = details.functionName();
            // TODO: This is currently just a placeholder until the server provides demangled names at this endpoint!
            var revEngDemangledName = details.demangledName();

            // Skip invalid function mangled names
            if (revEngMangledName.contains(" ") || revEngDemangledName.contains(" ")) {
                Msg.warn(this, "Skipping renaming of function %s to invalid name %s [%s]".formatted(ghidraMangledName, revEngMangledName, revEngDemangledName));
                continue;
            }


            // Get the type information on the server side
            Optional<FunctionDefinitionDataType> functionSignatureMessageOpt = api.getFunctionDataTypes(
                            programWithBinaryID.analysisID(),
                            fID.get()
                    )
                    // Try getting the data types if they are available
                    .flatMap(FunctionDataTypeStatus::data_types)
                    // If they are available, try converting them to a Ghidra signature
                    // If the conversion fails, act like there is no signature available
                    .flatMap((functionDataTypeMessage -> {
                        try {
                            return Optional.of(getFunctionSignature(functionDataTypeMessage));
                        } catch (DataTypeDependencyException e) {
                            // Something went wrong loading the data type dependencies
                            // just skip applying the signature and treat it like none being available
                            Msg.error(this, "Could not get parse signature for function %s".formatted(function.getName()));
                            return Optional.empty();
                        }
                    }));


            mangledNameMap.add(function.getEntryPoint(), serverMangledName);

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
                        if (!function.getSymbol().getName(false).equals(serverMangledName)) {
                            Msg.info(this, "Renaming function %s to %s [%s]".formatted(ghidraMangledName, revEngMangledName, revEngDemangledName));
                            var success = new SetFunctionNameCmd(function.getEntryPoint(), revEngDemangledName, SourceType.ANALYSIS)
                                    .applyTo(programWithBinaryID.program());
                            if (success) {
                                ghidraRenamedFunctions++;
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
                        ).applyTo(programWithBinaryID.program(), monitor);
                        if (success) {
                            ghidraRenamedFunctions++;
                        } else {
                            Msg.error(this, "Failed to apply signature to function %s".formatted(function.getName()));
                            failedRenames++;
                        }
                    }
                }
            }


        }
        // Done iterating over all functions. If nothing changed, discard the transaction, to keep undo history clean
        programWithBinaryID.program().endTransaction(transactionId, ghidraRenamedFunctions > 0);
        if (failedRenames > 0){
            Msg.showError(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Function Update Summary",
                    ("Failed to update %d functions from RevEng.AI. Please check the error log for details.").formatted(
                            failedRenames
                    ));
        }
    }

    /**
     * Get the FunctionID for a Ghidra Function, if there is one
     *
     * There are two cases where a function ID is missing:
     * 1. Either the whole program has not been analyzed
     * 2. Or the function was not found as part of the analysis on the server
     * (because its bounds were not included when the analysis was triggered)
     */
    public Optional<FunctionID> getFunctionIDFor(Function function){
        return getKnownProgram(function.getProgram())
                .flatMap(knownProgram -> getFunctionIDFor(knownProgram, function));
    }

    public Optional<FunctionID> getFunctionIDFor(ProgramWithBinaryID knownProgram, Function function){
        Optional<LongPropertyMap> functionIDMap = getFunctionIDPropertyMap(knownProgram);
        return functionIDMap
                .flatMap(map -> Optional.ofNullable(map.get(function.getEntryPoint())))
                .map(FunctionID::new);
    }

    private Optional<LongPropertyMap> getFunctionIDPropertyMap(ProgramWithBinaryID program){
        return Optional.ofNullable(program.program().getUsrPropertyManager().getLongPropertyMap(REAI_FUNCTION_PROP_MAP));
    }

    public Optional<StringPropertyMap> getFunctionMangledNamesMap(Program program) {
        return Optional.ofNullable(program.getUsrPropertyManager().getStringPropertyMap(REAI_FUNCTION_MANGLED_MAP));
    }

    public BiMap<FunctionID, Function> getFunctionMap(Program program){
        var propMap = program.getUsrPropertyManager().getLongPropertyMap(REAI_FUNCTION_PROP_MAP);
        BiMap<FunctionID, Function> functionMap = HashBiMap.create();
        propMap.getPropertyIterator().forEachRemaining(
                addr -> {
                    var func = program.getFunctionManager().getFunctionAt(addr);

                    try {
                        functionMap.put(new FunctionID(propMap.getLong(addr)), func);
                    } catch (NoValueException e) {
                        // This should never happen, because we're iterating over the keys
                        throw new RuntimeException(e);
                    }
                }
        );
        return functionMap;
    }

    /**
     * Get the Ghidra Function for a given FunctionInfo if there is one
     */
    public Optional<Function> getFunctionFor(FunctionInfo functionInfo, Program program){
        // These addresses used to be relative, but are now absolute again
        var defaultAddressSpace = program.getAddressFactory().getDefaultAddressSpace();
        var funcAddress = defaultAddressSpace.getAddress(functionInfo.functionVirtualAddress());
        var func = program.getFunctionManager().getFunctionAt(funcAddress);

        return Optional.ofNullable(func);
    }

    public List<LegacyAnalysisResult> searchForHash(BinaryHash hash){
        return api.search(hash);
    }

    public boolean isKnownProgram(Program program){
        var storedBinID = program.getOptions(ReaiPluginPackage.REAI_OPTIONS_CATEGORY).getLong(ReaiPluginPackage.OPTION_KEY_BINID, ReaiPluginPackage.INVALID_BINARY_ID);
        return storedBinID != ReaiPluginPackage.INVALID_BINARY_ID;
    }

    public void removeProgramAssociation(Program program){
        BinaryID binID;
        try {
            var maybebinID = getBinaryIDfromOptions(program);
            if (maybebinID.isEmpty()){
                Msg.warn(this, "No binary ID found for program, cannot remove association");
                return;
            }
            binID = maybebinID.get();
        } catch (InvalidBinaryID e) {
            // The program has an invalid binary ID, which can happen if the server was changed
            // This is a very good reason to remove the association, so we unpack the id from the error
            binID = e.getBinaryID();
        }
        // Clear all function ID data

        program.getUsrPropertyManager().removePropertyMap(REAI_FUNCTION_PROP_MAP);
        program.getUsrPropertyManager().removePropertyMap(REAI_FUNCTION_MANGLED_MAP);
        statusCache.remove(binID);
        program.getOptions(ReaiPluginPackage.REAI_OPTIONS_CATEGORY).setLong(ReaiPluginPackage.OPTION_KEY_BINID, ReaiPluginPackage.INVALID_BINARY_ID);
    }

    public boolean isProgramAnalysed(Program program){
        return program.getUsrPropertyManager().getLongPropertyMap(REAI_FUNCTION_PROP_MAP) != null &&
                program.getUsrPropertyManager().getStringPropertyMap(REAI_FUNCTION_MANGLED_MAP) != null;
    }

    public boolean isKnownFunction(Function function){
        return getFunctionIDFor(function).isPresent();
    }

    public static List<FunctionBoundary> exportFunctionBoundaries(Program program){
        List<FunctionBoundary> result = new ArrayList<>();
        Address imageBase = program.getImageBase();
        program.getFunctionManager().getFunctions(true).forEach(
                function -> {
                    var start = function.getEntryPoint();
                    var end = function.getBody().getMaxAddress();
                    result.add(new FunctionBoundary(function.getSymbol().getName(false), start.getOffset(), end.getOffset()));
                }
        );
        return result;
    }

    private BinaryHash hashOfProgram(Program program) {
        // TODO: we break the guarantee that a BinaryHash implies that a file of this hash has already been uploaded
        return new BinaryHash(program.getExecutableSHA256());
    }

    public BinaryHash upload(Program program) {
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

    public BinaryHash upload(Path path) {
        try {
            return api.upload(path);
        } catch (FileNotFoundException | ApiException e) {
            throw new RuntimeException(e);
        }
    }

    public AnalysisStatus pollStatus(BinaryID bid) {
        try {
            return api.status(bid);
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }

    public String decompileFunctionViaAI(Function function, TaskMonitor monitor, AIDecompilationdWindow window) {
        monitor.setMaximum(100 * 50);
        var fID = getFunctionIDFor(function)
                .orElseThrow(() -> new RuntimeException("Function has no associated FunctionID"));
        // Check if there is an existing process already, because the trigger API will fail with 400 if there is
        if (api.pollAIDecompileStatus(fID).status().equals("uninitialised")){
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

            switch (status.status()) {
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
                    return status.decompilation();
                case "error":
                    return "Decompilation failed: %s".formatted(status.decompilation());
                default:
                    throw new RuntimeException("Unknown status: %s".formatted(status.status()));
            }



        }
    }

    ///  This method analyses a program by uploading it (if necessary), triggering an analysis, and _blocking_
    /// until the analysis is complete. This is for scripts and tests, and must not be used on the UI thread
    public ProgramWithBinaryID analyse(Program program, AnalysisOptionsBuilder analysisOptionsBuilder, TaskMonitor monitor) throws CancelledException, ApiException {
        // Check if we are on the swing thread
        var programWithBinaryID = startAnalysis(program, analysisOptionsBuilder);
        var finalStatus = waitForFinishedAnalysis(monitor, programWithBinaryID, null, null);
        // TODO: Check final status for errors, and do something appropriate on failure
        registerFinishedAnalysisForProgram(programWithBinaryID, monitor);
        return programWithBinaryID;
    }

    public Optional<ProgramWithBinaryID> getKnownProgram(Program program) {
        return getBinaryIDFor(program).map(binID -> {
                    var analysisID = api.getAnalysisIDfromBinaryID(binID);
                    return new ProgramWithBinaryID(program, binID, analysisID);
                }
        );
    }

    public Optional<FunctionDataTypeMessage> getFunctionSignatureArtifact(ProgramWithBinaryID program, FunctionID functionID) {
        return api.getFunctionDataTypes(program.analysisID(), functionID).flatMap(FunctionDataTypeStatus::data_types);
    }

    /**
     * Create a {@link FunctionDefinitionDataType} from a @{@link FunctionDataTypeMessage} in isolation
     *
     * All the required dependency types should be stored in the DataTypeManager that is associated with this
     * FunctionDefinitionDataType
     *
     * @param functionDataTypeMessage The message containing the function signature, received from the API
     * @return Self-contained signature for the function
     */
    public static FunctionDefinitionDataType getFunctionSignature(FunctionDataTypeMessage functionDataTypeMessage) throws DataTypeDependencyException {

        // TODO: Do we need the program or data type manager?
        // Or can we just create a new one with all the necessary types and then they get merged?

        // Create Data Type Manager with all dependencies
        var dtm = loadDependencyDataTypes(functionDataTypeMessage.func_deps());

        FunctionDefinitionDataType f = new FunctionDefinitionDataType(functionDataTypeMessage.functionName(), dtm);

        try {
            f.setName(functionDataTypeMessage.functionName());
        } catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }

        ParameterDefinitionImpl[] args = Arrays.stream(functionDataTypeMessage.func_types().header().args()).map(
                arg -> {
                    DataType ghidraType = null;
                    try {
                        ghidraType = loadDataType(dtm, arg.type(), functionDataTypeMessage.func_deps());
                    } catch (DataTypeDependencyException e) {
                        Msg.error(GhidraRevengService.class,
                                "Couldn't find type '%s' for param of %s".formatted(arg.type(), functionDataTypeMessage.functionName())
                        );
                        ghidraType = Undefined.getUndefinedDataType(arg.size());
                    }
                    // Add the type to the DataTypeManager
                    return new ParameterDefinitionImpl(arg.name(), ghidraType, null);
                }).toArray(ParameterDefinitionImpl[]::new);

        f.setArguments(args);

        DataType returnType = null;
        returnType = loadDataType(dtm, functionDataTypeMessage.func_types().header().type(), functionDataTypeMessage.func_deps());
        f.setReturnType(returnType);


        return f;
    }

    public static DataTypeManager loadDependencyDataTypes(FunctionDependencies dependencies){
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
                throw new RuntimeException("Dependency loading failed: %s".formatted(typeDefsToAdd));
            }
            var typeDef = typeDefsToAdd.remove();
            var path = TypePathAndName.fromString(typeDef.name());
            DataType type;
            try {
                type = dataTypeParser.parse(typeDef.type());
            } catch (InvalidDataTypeException e) {
                // The type wasn't available in the DataTypeManager yet, try again later
                typeDefsToAdd.add(typeDef);
                retries++;
                continue;
            } catch (CancelledException e) {
                throw new RuntimeException(e);
            }
            TypedefDataType typedefDataType = new TypedefDataType(new CategoryPath(CategoryPath.ROOT, path.path()), path.name(), type, null);
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
                                        fieldType = loadDataType(dtm, binSyncStructMember.type(), dependencies);
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

    private static DataType loadDataType(DataTypeManager dtm, String name, FunctionDependencies dependencies) throws DataTypeDependencyException {
        DataTypeParser dataTypeParser = new DataTypeParser(
                dtm,
                null,
                null,
                DataTypeParser.AllowedDataTypes.ALL);
        DataType dataType;
        try {
            dataType = dataTypeParser.parse(name);
        } catch (InvalidDataTypeException e) {
            // The type wasn't available in the DataTypeManager, so we have to find it in the dependencies
            throw new DataTypeDependencyException("Data type not found in DataTypeManager: %s".formatted(name), e);
        } catch (CancelledException e) {
            throw new RuntimeException(e);
        }
        return dataType;
    }

    public String getAnalysisLog(AnalysisID analysisID) {
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

    public static final String PORTAL_FUNCTIONS = "function/";

    public void openFunctionInPortal(FunctionID functionID) {
        openPortal(PORTAL_FUNCTIONS, String.valueOf(functionID.value()));
    }

    public void openCollectionInPortal(Collection collection) {
        openPortal("collections/", String.valueOf(collection.collectionID().id()));
    }

    public void openPortalFor(Collection c){
        openCollectionInPortal(c);
    }
    public void openPortalFor(FunctionID f){
        openFunctionInPortal(f);
    }

    public void openPortalFor(AnalysisResult analysisResult) {
        openPortal("analyses", String.valueOf(analysisResult.analysisID().id()));
    }

    public void openPortalFor(LegacyAnalysisResult analysisResult) {
        openPortal("analyses", String.valueOf(analysisResult.binary_id().value()));
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
            ProgramWithBinaryID programWithID,
            @Nullable AnalysisLogConsumer logger,
            @Nullable PluginTool tool

            ) throws CancelledException {
        monitor.setMessage("Checking analysis status");
        // Check the status of the analysis every 500ms
        // TODO: In the future this can be made smarter and e.g. wait longer if the analysis log hasn't changed
        AnalysisStatus lastStatus = null;
        while (true) {
            AnalysisStatus currentStatus = this.api.status(programWithID.analysisID());
            if (currentStatus != AnalysisStatus.Queued) {
                // Analysis log endpoint only starts to return data after the analysis is processing
                String logs = this.getAnalysisLog(programWithID.analysisID());
                if (logger != null) {
                    logger.consumeLogs(logs);
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

    public ProgramWithBinaryID startAnalysis(Program program, AnalysisOptionsBuilder analysisOptionsBuilder) throws ApiException {
        var binaryID = api.analyse(analysisOptionsBuilder);
        AnalysisID analysisID = api.getAnalysisIDfromBinaryID(binaryID);
        addBinaryIDtoProgramOptions(program, binaryID);
        return new ProgramWithBinaryID(program, binaryID, analysisID);
    }

    public Map<GhidraFunctionMatch, BoxPlot> getNameScores(java.util.Collection<GhidraFunctionMatch> values) {
        // Get the confidence scores for each match in the input
        List<FunctionNameScore> r =  api.getNameScores(values.stream().map(GhidraFunctionMatch::functionMatch).toList(), false);
        // Collect to a Map from the FunctionID to the actual score
        Map<FunctionID, BoxPlot> plots = r.stream().collect(Collectors.toMap(FunctionNameScore::functionID, FunctionNameScore::score));
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
    public Map<GhidraFunctionMatch, FunctionDataTypeMessage> getSignatures(java.util.Collection<GhidraFunctionMatch> values) {

        DataTypeList dataTypesList = this.api.getFunctionDataTypes(values.stream().map(GhidraFunctionMatch::nearest_neighbor_id).toList());
        Map<FunctionID, FunctionDataTypeMessage> signatureMap = Arrays.stream(dataTypesList.dataTypes())
                .filter(FunctionDataTypeStatus::completed)
                .filter(status -> status.data_types().isPresent())
                .collect(Collectors.toMap(
                        FunctionDataTypeStatus::functionID,
                        status -> status.data_types().get()
                ));

        return values.stream()
                .filter(match -> signatureMap.containsKey(match.functionMatch().nearest_neighbor_id()))
                .collect(Collectors.toMap(
                match -> match,
                match -> signatureMap.get(match.functionMatch().nearest_neighbor_id())
        ));
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

    public Basic getBasicDetailsForAnalysis(AnalysisID analysisID) throws ApiException {
        return api.getAnalysisBasicInfo(analysisID);
    }

    public FunctionMatchingBatchResponse getFunctionMatchingForAnalysis(AnalysisID analysisID, AnalysisFunctionMatchingRequest request) throws ApiException {
        return api.analysisFunctionMatching(analysisID, request);
    }

    public FunctionMatchingBatchResponse getFunctionMatchingForFunction(FunctionMatchingRequest request) throws ApiException {
        return api.functionFunctionMatching(request);
    }

    public void batchRenameFunctions(FunctionsListRename functionsList) throws ApiException {
        api.batchRenameFunctions(functionsList);
    }
}

package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.SelectableItem;
import ai.reveng.toolkit.ghidra.core.AnalysisLogConsumer;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionBoundary;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.MockApi;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.FunctionSignatureBatch;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.LongPropertyMap;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.BrowserLoader;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NoValueException;
import ghidra.util.task.TaskMonitor;

import javax.annotation.Nullable;
import java.awt.*;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.*;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
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
    private static final String REVENGAI_FUNCTION_TAG = "REVENGAI_SYNCED";
    private static final String REVENG_BOOKMARK_TYPE = "RevEng.AI";
    private static final String REVENG_BOOKMARK_CATEGORY = "Analysed Function";
    private final Map<TypedApiInterface.AnalysisID, AnalysisStatus> statusCache = new HashMap<>();

    private TypedApiInterface api;
    private ApiInfo apiInfo;

    /// Set while the plugin is applying server-sourced changes locally (pull / analysis-sync), so the
    /// reactive listener does not echo those changes straight back to the portal. Mirrors the IDA
    /// plugin's {@code analysis_sync_service.is_worker_running()} guard.
    private final AtomicBoolean pushbackSuppressed = new AtomicBoolean(false);

    /// dedicated functions on the GhidraRevengService should be used instead to enforce assumptions via
    /// type level guarantees
//    @Deprecated
    public TypedApiInterface getApi() {
        return api;
    }

    private FunctionSignatureService signatureService;
    private AnalysisDataTypesService analysisDataTypesService;

    /// Reads function signatures and the data types they reference.
    public FunctionSignatureService signatures() {
        if (signatureService == null) {
            signatureService = new FunctionSignatureService(api);
        }
        return signatureService;
    }

    /// Reads an analysis' data-type catalogue, which owns its `data_type_id` namespace.
    public AnalysisDataTypesService analysisDataTypes() {
        if (analysisDataTypesService == null) {
            analysisDataTypesService = new AnalysisDataTypesService(api);
        }
        return analysisDataTypesService;
    }

    /// One decoder per analysis: a `data_type_id` only means something inside the analysis that
    /// minted it, so each group of types gets its own {@link DataTypeManager}.
    private static ServerDataTypeDecoder decoderFor(Map<TypedApiInterface.AnalysisID, ServerDataTypeDecoder> decoders,
                                                    FunctionSignatureBatch batch,
                                                    BatchFunctionSignatureEntry entry) {
        var analysisID = new TypedApiInterface.AnalysisID(Math.toIntExact(entry.getAnalysisId()));
        return decoders.computeIfAbsent(analysisID, id -> ServerDataTypeDecoder.decode(batch.dataTypesFor(id)));
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

    public AnalysedProgram registerFinishedAnalysisForProgram(ProgramWithID programWithID, TaskMonitor monitor) throws CancelledException {
        var status = status(programWithID);
        if (!status.equals(AnalysisStatus.Complete)){
            throw new IllegalStateException("Analysis %s is not complete yet, current status: %s"
                    .formatted(programWithID.analysisID(), status));
        }
        statusCache.put(programWithID.analysisID, AnalysisStatus.Complete);

        var analysedProgram = associateFunctionInfo(programWithID);
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
    private Optional<TypedApiInterface.AnalysisID> getAnalysisIDFor(Program program) {
        long bid = program.getOptions(
                ReaiPluginPackage.REAI_OPTIONS_CATEGORY).getLong(OPTION_KEY_ANALYSIS_ID,
                ReaiPluginPackage.INVALID_ANALYSIS_ID);
        if (bid == ReaiPluginPackage.INVALID_ANALYSIS_ID) {
            return Optional.empty();
        }
        return Optional.of(new TypedApiInterface.AnalysisID((int) bid));
    }

    /// Loads the function info into a dedicated user property map.
    /// This method should only concern itself with associating the FunctionID with the Ghidra Function
    /// This property is immutable within an Analysis: The function ID will never change unless an entirely different
    /// analysis is associated with the program
    /// Other function information like the name and signature should be loaded in [#pullFunctionInfoFromAnalysis(AnalysedProgram ,TaskMonitor)]
    /// because this information can change on the server, and thus needs a dedicated method to refresh it
    private AnalysedProgram associateFunctionInfo(ProgramWithID knownProgram) {
        var analysisID = knownProgram.analysisID();
        var program = knownProgram.program();
        List<FunctionInfo> functionInfo = null;
        functionInfo = api.getFunctionInfo(analysisID);
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

        BookmarkManager bookmarkManager = program.getBookmarkManager();

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
            markFunctionAsRevEng(bookmarkManager, func, info);

            ghidraBoundariesMatchedFunction++;
        }


        program.endTransaction(transactionID, true);


        var analysedProgram = new AnalysedProgram(program, analysisID);
        AtomicInteger ghidraFunctionCount = new AtomicInteger();
        program.getFunctionManager().getFunctions(true).forEach(
                func -> {
                    if (!func.isExternal() && !func.isThunk()){
                        ghidraFunctionCount.getAndIncrement();

                        if (analysedProgram.getIDForFunction(func).isEmpty()) {
                            Msg.info(this, "Function %s not found in RevEng.AI".formatted(func.getSymbol().getName(false)));
                        }
                    }
                }
        );
        // Print summary
        Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Function loading summary",
                ("Found %d functions from RevEng.AI. Your local Ghidra instance has %d/%d matching function " +
                        "boundaries. For better results, please start a new analysis from this plugin.").formatted(
                        functionInfo.size(),
                        ghidraBoundariesMatchedFunction,
                        ghidraFunctionCount.get()
                ));

        return analysedProgram;

    }

    private void markFunctionAsRevEng(BookmarkManager bookmarkManager, Function function, FunctionInfo info) {
        function.addTag(REVENGAI_FUNCTION_TAG);
        bookmarkManager.setBookmark(function.getEntryPoint(), REVENG_BOOKMARK_TYPE, REVENG_BOOKMARK_CATEGORY,
                "Function #" + info.functionID().value());
    }


    public record RenameResult(Function func, String originalName, String newName) {
    }

    /// Push a local function rename back to the portal. Returns the namespace-qualified name that was
    /// pushed, or empty if the function is not known on the server.
    public Optional<String> pushFunctionRename(AnalysedProgram analysedProgram, Function function) throws ApiException {
        var withId = analysedProgram.getIDForFunction(function);
        if (withId.isEmpty()) {
            return Optional.empty();
        }
        String qualifiedName = qualifiedServerName(function);
        var item = new BatchRenameItem();
        item.setFunctionId(withId.get().functionID().value());
        item.setNewName(qualifiedName);
        item.setNewMangledName(qualifiedName);
        var request = new BatchRenameInputBody();
        request.setFunctions(List.of(item));
        api.batchRenameFunctions(request);
        return Optional.of(qualifiedName);
    }

    /// The function name as the portal expects it: qualified with its namespace path (joined by
    /// {@code ::}), excluding the artificial RevEng.AI organisational namespace and the global
    /// namespace. Ghidra stores only the leaf label on the symbol, so the namespace must be
    /// re-attached when pushing a rename back — the portal's function names include the namespace.
    static String qualifiedServerName(Function function) {
        List<String> parts = new ArrayList<>();
        parts.add(function.getName());
        for (Namespace ns = function.getParentNamespace(); ns != null && !ns.isGlobal(); ns = ns.getParentNamespace()) {
            if (!REVENG_AI_NAMESPACE.equals(ns.getName())) {
                parts.add(0, ns.getName());
            }
        }
        return String.join(Namespace.DELIMITER, parts);
    }

    /// Push the local signature and variables of a function back to the portal.
    public boolean pushFunctionTypes(AnalysedProgram analysedProgram, Function function) throws ApiException {
        return pushFunctionTypes(analysedProgram, List.of(function)) > 0;
    }

    /// Push the local signatures of several functions, and answer with how many the server took.
    ///
    /// The two halves of the write path compose here, and only here. Data-type management is a
    /// batch affair — the union of everything the functions reach is resolved against the analysis'
    /// catalogue and created where it is missing, in one pass — while a signature is written one
    /// function at a time. Running the type pass once for the whole set is the point of keeping the
    /// two apart: the alternative re-resolves the same closure per function.
    public int pushFunctionTypes(AnalysedProgram analysedProgram, Collection<Function> functions) throws ApiException {
        Map<Function, TypedApiInterface.FunctionID> known = new LinkedHashMap<>();
        for (Function function : functions) {
            analysedProgram.getIDForFunction(function)
                    .ifPresent(withId -> known.put(function, withId.functionID()));
        }
        if (known.isEmpty()) {
            return 0;
        }

        List<DataType> roots = new ArrayList<>();
        known.keySet().forEach(function -> roots.addAll(GhidraDataTypeEncoder.reachableTypes(function)));
        var ids = analysisDataTypes().ensure(analysedProgram.analysisID(), roots);

        int pushed = 0;
        for (var entry : known.entrySet()) {
            var signature = GhidraDataTypeEncoder.signatureOf(entry.getKey(), ids);
            if (signatures().put(analysedProgram.analysisID(), entry.getValue(), signature)) {
                pushed++;
            }
        }
        return pushed;
    }

    /// Breakdown of a bidirectional analysis sync, shown to the user afterwards.
    public record SyncSummary(
            int matchedFunctions,
            int namesModifiedRemotely,
            int canonicalizedNames,
            int dedupedNames,
            int pushedNames,
            int pushedTypeSets
    ) {}

    private record PendingNamePush(TypedApiInterface.FunctionID functionID, String newName, String newMangledName) {}
    private record InvalidRemoteName(Function function, TypedApiInterface.FunctionID functionID, String remoteName) {}

    /// Reconcile local state with the remote analysis and push back local edits (PLU-322).
    ///
    /// Names: applies remote names locally where the local name is not user-defined, canonicalising
    /// names Ghidra rejects (via the portal canonify endpoint) and de-duplicating names already used
    /// this run; corrected names are pushed back to the portal. Types: pushes local types for matched
    /// functions whose remote types are absent or could not be applied. Mirrors the IDA plugin's
    /// {@code analysis_sync.py}.
    public SyncSummary syncAnalysisUpdates(AnalysedProgram analysedProgram, TaskMonitor monitor, ReaiLoggingService log) throws ApiException {
        pushbackSuppressed.set(true);
        try {
            return syncAnalysisUpdatesInternal(analysedProgram, monitor, log);
        } finally {
            pushbackSuppressed.set(false);
        }
    }

    private SyncSummary syncAnalysisUpdatesInternal(AnalysedProgram analysedProgram, TaskMonitor monitor, ReaiLoggingService log) throws ApiException {
        var program = analysedProgram.program();
        log.info("Starting bidirectional sync with the RevEng.AI portal");
        Map<TypedApiInterface.FunctionID, FunctionInfo> functionInfoMap = api.getFunctionInfo(analysedProgram.analysisID()).stream()
                .collect(Collectors.toMap(FunctionInfo::functionID, fi -> fi, (a, b) -> a));

        Set<String> appliedNames = new HashSet<>();
        List<PendingNamePush> namePushbacks = new ArrayList<>();
        List<InvalidRemoteName> needsCanonical = new ArrayList<>();
        int matched = 0;
        int namesModifiedRemotely = 0;
        int deduped = 0;
        int canonicalizedNames = 0;

        var transactionId = program.startTransaction("RevEng.AI: Sync Analysis Updates");
        boolean commit = false;
        try {
            // Creating the RevEng.AI namespace is a DB write, so it must happen inside the transaction.
            var revEngNamespace = getRevEngAINameSpace(program);
            for (Function function : program.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) {
                    break;
                }
                if (function.isExternal() || function.isThunk()) {
                    continue;
                }
                var withId = analysedProgram.getIDForFunction(function);
                if (withId.isEmpty()) {
                    continue;
                }
                matched++;
                var functionID = withId.get().functionID();
                var info = functionInfoMap.get(functionID);
                if (info == null) {
                    continue;
                }
                String remoteName = info.functionName();
                if (remoteName == null || remoteName.isBlank() || remoteName.equals(function.getName())) {
                    continue;
                }
                // Do not overwrite names the user has explicitly set locally.
                if (function.getSymbol().getSource() == SourceType.USER_DEFINED) {
                    continue;
                }
                if (isInvalidGhidraName(remoteName)) {
                    needsCanonical.add(new InvalidRemoteName(function, functionID, remoteName));
                    continue;
                }
                if (appliedNames.contains(remoteName)) {
                    String deduplicated = deduplicateName(remoteName, appliedNames);
                    if (applyRemoteName(program, function, revEngNamespace, deduplicated)) {
                        appliedNames.add(deduplicated);
                        deduped++;
                        namePushbacks.add(new PendingNamePush(functionID, deduplicated, function.getSymbol().getName(false)));
                        log.info("De-duplicated remote name \"%s\" -> \"%s\" at %s"
                                .formatted(remoteName, deduplicated, function.getEntryPoint()));
                    }
                } else if (applyRemoteName(program, function, revEngNamespace, remoteName)) {
                    appliedNames.add(remoteName);
                    namesModifiedRemotely++;
                    log.info("Applied remote name \"%s\" at %s".formatted(remoteName, function.getEntryPoint()));
                }
            }

            int canonicalized = 0;
            if (!needsCanonical.isEmpty() && !monitor.isCancelled()) {
                var canonicalMapping = api.canonicalizeFunctionNames(
                        needsCanonical.stream().map(InvalidRemoteName::remoteName).distinct().toList());
                for (InvalidRemoteName invalid : needsCanonical) {
                    String canonical = canonicalMapping.getOrDefault(invalid.remoteName(), invalid.remoteName());
                    if (isInvalidGhidraName(canonical)) {
                        continue;
                    }
                    String finalName = appliedNames.contains(canonical)
                            ? deduplicateName(canonical, appliedNames)
                            : canonical;
                    if (applyRemoteName(program, invalid.function(), revEngNamespace, finalName)) {
                        appliedNames.add(finalName);
                        canonicalized++;
                        namePushbacks.add(new PendingNamePush(
                                invalid.functionID(), finalName, invalid.function().getSymbol().getName(false)));
                        log.info("Canonicalized invalid remote name \"%s\" -> \"%s\" at %s"
                                .formatted(invalid.remoteName(), finalName, invalid.function().getEntryPoint()));
                    }
                }
            }
            commit = !namePushbacks.isEmpty() || namesModifiedRemotely > 0;
            canonicalizedNames = canonicalized;
        } finally {
            program.endTransaction(transactionId, commit && !monitor.isCancelled());
        }

        // Push back over the network only after the local transaction has closed, so we don't hold a
        // program lock across API calls.
        int pushedNames = pushNameBacks(namePushbacks);
        if (pushedNames > 0) {
            log.info("Pushed %d corrected function name(s) back to the RevEng.AI portal".formatted(pushedNames));
        }
        int pushedTypeSets = pushLocalTypesWhereRemoteMissing(analysedProgram, functionInfoMap.keySet(), monitor, log);

        log.info(("Sync complete: %d matched, %d name(s) applied, %d canonicalized, %d de-duplicated, "
                + "%d name(s) and %d type set(s) pushed back")
                .formatted(matched, namesModifiedRemotely, canonicalizedNames, deduped, pushedNames, pushedTypeSets));
        return new SyncSummary(matched, namesModifiedRemotely, canonicalizedNames, deduped, pushedNames, pushedTypeSets);
    }

    private int pushNameBacks(List<PendingNamePush> namePushbacks) throws ApiException {
        if (namePushbacks.isEmpty()) {
            return 0;
        }
        var items = namePushbacks.stream().map(push -> {
            var item = new BatchRenameItem();
            item.setFunctionId(push.functionID().value());
            item.setNewName(push.newName());
            item.setNewMangledName(push.newMangledName());
            return item;
        }).toList();
        var request = new BatchRenameInputBody();
        request.setFunctions(items);
        api.batchRenameFunctions(request);
        return namePushbacks.size();
    }

    /// Push local types for matched functions whose remote types are absent or could not be applied,
    /// back-propagating type information to the portal.
    private int pushLocalTypesWhereRemoteMissing(AnalysedProgram analysedProgram,
                                                 Set<TypedApiInterface.FunctionID> matchedIds,
                                                 TaskMonitor monitor,
                                                 ReaiLoggingService log) {
        // Only the matched functions are candidates, and only whether the server holds a signature
        // at all matters here, so ask for exactly those ids and skip the type closure.
        Set<TypedApiInterface.FunctionID> remotePresent = signatures()
                .getMany(List.copyOf(matchedIds), false)
                .items().stream()
                .filter(BatchFunctionSignatureEntry::getHasSignature)
                .map(item -> new TypedApiInterface.FunctionID(item.getFunctionId()))
                .collect(Collectors.toSet());

        var functionMap = analysedProgram.getFunctionMap();
        List<Function> candidates = new ArrayList<>();
        for (TypedApiInterface.FunctionID functionID : matchedIds) {
            if (monitor.isCancelled()) {
                break;
            }
            if (remotePresent.contains(functionID)) {
                continue;
            }
            var function = functionMap.get(functionID);
            // Only push functions that have real type information locally (analysis-inferred or user-set).
            if (function == null || function.isExternal() || function.isThunk()
                    || function.getSignatureSource() == SourceType.DEFAULT) {
                continue;
            }
            candidates.add(function);
        }
        if (candidates.isEmpty()) {
            return 0;
        }
        try {
            // One type pass over the union of every candidate's types, then a signature write each.
            int pushed = pushFunctionTypes(analysedProgram, candidates);
            log.info("Pushed local types for %d of %d functions the portal had none for"
                    .formatted(pushed, candidates.size()));
            return pushed;
        } catch (ApiException e) {
            Msg.warn(this, "Failed to push local types during sync", e);
            return 0;
        }
    }

    private boolean applyRemoteName(Program program, Function function, Namespace revEngNamespace, String name) {
        try {
            function.setParentNamespace(revEngNamespace);
        } catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
            Msg.warn(this, "Could not move %s into RevEng.AI namespace".formatted(function.getName()), e);
        }
        return new SetFunctionNameCmd(function.getEntryPoint(), name, SourceType.ANALYSIS).applyTo(program);
    }

    static String deduplicateName(String name, Set<String> used) {
        int suffix = 1;
        String candidate = name + "_" + suffix;
        while (used.contains(candidate)) {
            suffix++;
            candidate = name + "_" + suffix;
        }
        return candidate;
    }

    static boolean isInvalidGhidraName(String name) {
        if (name == null || name.isBlank()) {
            return true;
        }
        for (int i = 0; i < name.length(); i++) {
            if (SymbolUtilities.isInvalidChar(name.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    /// Pull the server side information about the functions from a remote Analysis and update the local {@link Program}
    /// based on it
    /// This currently includes:
    /// * the name of the function
    /// * the type signature of the function
    ///
    /// It assumes that the initial load already happened, i.e. the functions have an associated FunctionID already.
    /// The initial association happens in {@link #associateFunctionInfo(ProgramWithID)}
    ///
    public List<RenameResult> pullFunctionInfoFromAnalysis(AnalysedProgram analysedProgram, TaskMonitor monitor) {
        pushbackSuppressed.set(true);
        try {
            return pullFunctionInfoFromAnalysisInternal(analysedProgram, monitor);
        } finally {
            pushbackSuppressed.set(false);
        }
    }

    /// True while the plugin is applying server-sourced changes locally; the reactive listener uses
    /// this to avoid pushing those changes back to the portal.
    public boolean isPushbackSuppressed() {
        return pushbackSuppressed.get();
    }

    private List<RenameResult> pullFunctionInfoFromAnalysisInternal(AnalysedProgram analysedProgram, TaskMonitor monitor) {
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


        // /v3/functions/signatures is addressed by function id rather than by analysis, so ask for
        // the functions this analysis reported. The response carries the types those signatures
        // reference alongside them, which is what the decoders below are built from.
        var signatureBatch = signatures().getMany(List.copyOf(functionInfoMap.keySet()));
        Map<TypedApiInterface.AnalysisID, ServerDataTypeDecoder> decoders = new HashMap<>();
        Map<TypedApiInterface.FunctionID, BatchFunctionSignatureEntry> signatureMap = signatureBatch.items()
                .stream()
                .filter(BatchFunctionSignatureEntry::getHasSignature)
                .collect(
                Collectors.toMap(
                        item -> new TypedApiInterface.FunctionID(item.getFunctionId()),
                        item -> item,
                        (existing, replacement) -> existing
                )
        );

        for (Function function : analysedProgram.program().getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled()) {
                continue;
            }
            var ghidraMangledName = function.getSymbol().getName(false);
            // Skip external and thunk functions because we don't support them
            if (function.isExternal() || function.isThunk()) {
                Msg.debug(this, "Skipping external/thunk function %s".formatted(ghidraMangledName));
                continue;
            }

            var fID = analysedProgram.getIDForFunction(function);
            if (fID.isEmpty()) {
                Msg.info(this, "Function %s has no associated FunctionID, skipping".formatted(function.getName()));
                continue;
            }

            // Get the current name on  the server side
            FunctionInfo details = functionInfoMap.get(fID.get().functionID);

            // Extract the mangled name from Ghidra
            var revEngMangledName = details.functionMangledName();
            var revEngDemangledName = details.functionName();

            // Skip invalid function mangled names
            if (revEngMangledName.contains(" ") || revEngDemangledName.contains(" ")) {
                Msg.warn(this, "Skipping renaming of function %s to invalid name %s [%s]".formatted(ghidraMangledName, revEngMangledName, revEngDemangledName));
                continue;
            }

            // Get the type information on the server side. Every type the signature refers to is
            // resolved by id against its analysis' decoder, so there is nothing left to fail on.
            Optional<FunctionDefinitionDataType> functionSignatureMessageOpt =
                    Optional.ofNullable(signatureMap.get(fID.get().functionID))
                            .map(entry -> getFunctionSignature(entry, decoderFor(decoders, signatureBatch, entry)));


            analysedProgram.setMangledNameForFunction(function, revEngMangledName);

            /// Source types:
            /// DEFAULT: placeholder name automatically assigned by Ghidra when it doesn’t know the real name.
            /// ANALYSIS: A name/signature inferred by one of Ghidra’s analysis engines (or demangler) rather than simply “default.”
            /// IMPORTED: Information taken from an external source — symbols or signatures imported from a file or database.
            /// USER_DEFINED: A name or signature explicitly set by the analyst.
            /// See {@link ghidra.program.model.symbol.SourceType} for more details
            if (function.getSymbol().getSource() == SourceType.DEFAULT) {
                if (functionSignatureMessageOpt.isEmpty()) {
                    // We don't have signature information for this function, so we can only try renaming it.
                    // Skip server-side default names — Ghidra's own "FUN_" and IDA's "sub_" — so we never
                    // overwrite Ghidra's default placeholder with an IDA-style one.
                    if (function.getSymbol().getSource() == SourceType.DEFAULT
                            && !revEngMangledName.startsWith("FUN_") && !revEngMangledName.startsWith("sub_")) {
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
    public List<AnalysisRecordBody> searchForHash(TypedApiInterface.BinaryHash hash){
        return api.search(hash);
    }

    public void removeProgramAssociation(Program program){
        // Clear all function ID data
        program.getUsrPropertyManager().removePropertyMap(REAI_FUNCTION_PROP_MAP);
        program.getUsrPropertyManager().removePropertyMap(REAI_FUNCTION_MANGLED_MAP);

        var bookmarkManager = program.getBookmarkManager();
        if (bookmarkManager.getBookmarkType(REVENG_BOOKMARK_TYPE) != null) {
            bookmarkManager.removeBookmarks(REVENG_BOOKMARK_TYPE);
        }
        var revengTag = program.getFunctionManager().getFunctionTagManager().getFunctionTag(REVENGAI_FUNCTION_TAG);
        if (revengTag != null) {
            revengTag.delete();
        }
        var reaiOptions = program.getOptions(ReaiPluginPackage.REAI_OPTIONS_CATEGORY);
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

    public static List<FunctionBoundary> exportFunctionBoundaries(Program program){
        return exportFunctionBoundaries(program, function -> true);
    }

    public static List<FunctionBoundary> exportFunctionBoundaries(Program program, Predicate<Function> includePredicate){
        List<FunctionBoundary> result = new ArrayList<>();
        program.getFunctionManager().getFunctions(true).forEach(
                function -> {
                    var start = function.getEntryPoint();
                    var end = function.getBody().getMaxAddress();
                    result.add(new FunctionBoundary(
                            function.getSymbol().getName(false),
                            start.getOffset(),
                            end.getOffset(),
                            includePredicate.test(function)));
                }
        );
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

    /// Current status of the server-side auto-unstrip pass, which runs after the analysis is complete.
    public TypedApiInterface.AutoUnstripStatus getAutoUnstripStatus(TypedApiInterface.AnalysisID id) throws ApiException {
        return api.getAutoUnstripStatus(id);
    }

    public AnalysisStatus status(ProgramWithID program) {
        try {
            return api.status(program.analysisID());
        } catch (ApiException e) {
            // This should never happen given that `ProgramWithID` guarantees a valid analysis ID
            throw new RuntimeException(e);
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
     * Create a self-contained {@link FunctionDefinitionDataType} from a function's server signature.
     *
     * <p>Every type the signature refers to is named by a {@code data_type_id}, so the decoder that
     * holds this analysis' types resolves the return type and each parameter by lookup. The decoder's
     * {@link DataTypeManager} owns the dependencies, which is what makes the result standalone.
     *
     * @param entry   the signature as the server reports it
     * @param decoder the decoded types of the analysis that {@code entry} belongs to
     * @return Self-contained signature for the function
     */
    public static FunctionDefinitionDataType getFunctionSignature(BatchFunctionSignatureEntry entry,
                                                                  ServerDataTypeDecoder decoder) {
        return decoder.signature(entry.getFunctionName(), entry.getReturnDataTypeId(), entry.getParameters());
    }

    public String getAnalysisLog(TypedApiInterface.AnalysisID analysisID) {
        return api.getAnalysisLogs(analysisID);
    }

    public void openFunctionInPortal(TypedApiInterface.FunctionID functionID) {
        var details = api.getFunctionDetails(functionID);
        openFunctionInPortal(details.analysisId(), functionID);
    }

    /// Prefer this overload when the caller already knows the analysis the function belongs to:
    /// it builds the portal URL directly and avoids the getFunctionDetails call, which requires a
    /// permission the user may not have (returns 403) even when they can view the analysis.
    public void openFunctionInPortal(TypedApiInterface.AnalysisID analysisID, TypedApiInterface.FunctionID functionID) {
        openPortal("analyses", String.format("%s?view=functions&fn=%s", analysisID.id(), functionID.value()));
    }

    public void openPortalFor(TypedApiInterface.FunctionID f){
        openFunctionInPortal(f);
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
        // Ghidra's BrowserLoader is more reliable than java.awt.Desktop, which frequently
        // no-ops or is reported unsupported inside Ghidra's JVM.
        try {
            BrowserLoader.display(uri.toURL());
        } catch (MalformedURLException e) {
            Msg.showError(
                    this,
                    null,
                    "URI Opening Failed",
                    "Browsing to URI %s failed".formatted(uri),
                    e
            );
        }
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
            if (currentStatus != AnalysisStatus.Uploaded && currentStatus != AnalysisStatus.Queued) {
                // Analysis log endpoint only starts to return data after the analysis is processing
                String logs = this.getAnalysisLog(programWithID.analysisID());
                if (logger != null) {
                    logger.consumeLogs(logs, programWithID);
                }
                logs.lines().reduce((first, second) -> second).ifPresent(monitor::setMessage);
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

    /**
     * Collects the signatures for the matched functions, if they have already been computed (and finished)
     * @param values
     * @return
     */
    public Map<GhidraFunctionMatch, FunctionDefinitionDataType> getSignatures(java.util.Collection<GhidraFunctionMatch> values) {


        // Get all signature info for the neighbour functions. Several local functions can match the same
        // neighbour, so dedupe the ids before fetching to avoid requesting (and getting back) duplicates.
        // The neighbours can come from any number of analyses; the response groups their types per
        // analysis, which is why each signature is decoded against its own analysis' types.
        var batch = signatures().getMany(
                values.stream().map(GhidraFunctionMatch::nearest_neighbor_id).distinct().toList()
        );
        // Create a map from FunctionID to signature for easy lookup, only where the server has one.
        // The same neighbour can still appear more than once in the response, so keep the first.
        Map<TypedApiInterface.FunctionID, BatchFunctionSignatureEntry> signatureMap = batch.items().stream()
                .filter(BatchFunctionSignatureEntry::getHasSignature)
                .collect(Collectors.toMap(
                        item -> new TypedApiInterface.FunctionID(item.getFunctionId()),
                        item -> item,
                        (existing, replacement) -> existing
                ));

        Map<TypedApiInterface.AnalysisID, ServerDataTypeDecoder> decoders = new HashMap<>();
        Map<GhidraFunctionMatch, FunctionDefinitionDataType> result = new HashMap<>();
        for (GhidraFunctionMatch match : values) {
            var entry = signatureMap.get(match.functionMatch().nearest_neighbor_id());
            if (entry == null) {
                continue;
            }
            result.put(match, getFunctionSignature(entry, decoderFor(decoders, batch, entry)));
        }
        return result;

    }

    public CompletableFuture<List<SelectableItem>> searchCollectionsWithIds(String query) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Call the actual API endpoint
                List<CollectionListItemBody> results = api.searchCollections(query);

                // Convert to SelectableItem objects with both ID and name
                List<SelectableItem> selectableItems = results.stream()
                        .filter(result -> result.getCollectionName() != null && !result.getCollectionName().trim().isEmpty())
                        .map(result -> new SelectableItem(
                                result.getCollectionId().intValue(),
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

    public AnalysisBasicInfoOutputBody getBasicDetailsForAnalysis(TypedApiInterface.AnalysisID analysisID) throws ApiException {
        return api.getAnalysisBasicInfo(analysisID);
    }

    /// Whole-binary matching goes through the analysis-level endpoint, which takes the analysis id in the
    /// path and ships no function ids. That keeps the request body tiny and the GET query strings empty, so
    /// it sidesteps the WAF body-size (~8 KB) and query-string (~2 KB) limits that the /v3/functions/matches
    /// endpoints hit once a binary has enough functions to enumerate (HTTP 403 / 414).
    public StartMatchingOutputBody startAnalysisFunctionMatching(TypedApiInterface.AnalysisID analysisID, StartMatchingForAnalysisInputBody request) throws ApiException {
        return api.startAnalysisFunctionMatching(analysisID, request);
    }

    public GetMatchesStatusOutputBody getAnalysisFunctionMatchingStatus(TypedApiInterface.AnalysisID analysisID) throws ApiException {
        return api.getAnalysisFunctionMatchingStatus(analysisID);
    }

    public GetMatchesOutputBody getAnalysisFunctionMatches(TypedApiInterface.AnalysisID analysisID) throws ApiException {
        return api.getAnalysisFunctionMatches(analysisID);
    }

    public StartMatchingOutputBody startFunctionsMatching(StartMatchingForFunctionsInputBody request) throws ApiException {
        return api.startFunctionsMatching(request);
    }

    public GetMatchesStatusOutputBody getFunctionsMatchingStatus(List<Long> functionIds) throws ApiException {
        return api.getFunctionsMatchingStatus(functionIds);
    }

    public GetMatchesOutputBody getFunctionsMatches(List<Long> functionIds) throws ApiException {
        return api.getFunctionsMatches(functionIds);
    }

    public void batchRenamingGhidraMatchesWithSignatures(List<GhidraFunctionMatchWithSignature> functionsList) throws ApiException {
        // Pushing types to the portal is not supported yet, so we just extract the function matches and call the other method
        batchRenameMatches(functionsList.stream()
                .map(GhidraFunctionMatchWithSignature::functionMatch)
                .toList());

    }

    public void batchRenameMatches(List<FunctionMatch> functionsList) throws ApiException {
        var items = functionsList.stream()
                .map(result -> {
                    var item = new BatchRenameItem();
                    item.setFunctionId(result.origin_function_id().value());
                    item.setNewName(result.nearest_neighbor_function_name());
                    item.setNewMangledName(result.nearest_neighbor_mangled_function_name());
                    return item;
                })
                .toList();

        var request = new BatchRenameInputBody();
        request.setFunctions(items);
        api.batchRenameFunctions(request);
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
        public Map<TypedApiInterface.FunctionID, Function> getFunctionMap(){
            var propMap = getFunctionIDPropertyMap(this);

            Map<TypedApiInterface.FunctionID, Function> functionMap = new HashMap<>();
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
            LongPropertyMap functionIDMap = getFunctionIDPropertyMap(this);
            var addresses = functionIDMap.getPropertyIterator();
            while (addresses.hasNext()) {
                var address = addresses.next();
                try {
                    if (functionIDMap.getLong(address) == functionID.value()) {
                        var function = program.getFunctionManager().getFunctionAt(address);
                        if (function != null) {
                            return Optional.of(new FunctionWithID(function, functionID));
                        }
                    }
                } catch (NoValueException e) {
                    // Iterating over keys, so this should not happen; skip defensively.
                }
            }
            return Optional.empty();
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

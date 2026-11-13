package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiClient;
import ai.reveng.invoker.ApiException;
import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.SelectableItem;
import ai.reveng.toolkit.ghidra.core.AnalysisLogConsumer;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.ui.WebBrowser;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionBoundary;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.MockApi;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.services.sync.UnpushedEdits;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.FunctionSignatureBatch;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
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
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NoValueException;
import ghidra.util.task.TaskMonitor;

import javax.annotation.Nullable;
import java.awt.*;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
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

    private volatile TypedApiInterface api;
    private volatile ApiInfo apiInfo;

    /// The programs the plugin is writing server-sourced changes into right now, each with how many
    /// such writes overlap, so the reactive listener does not echo those changes straight back to the
    /// portal. See {@link #startServerTransaction}.
    private final Map<Program, Integer> applyingServerChanges = new ConcurrentHashMap<>();

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

    /// Points the running service at new credentials, as the setup wizard does when it finishes.
    /// Swapped in place rather than replaced, because every plugin holds the instance it was handed
    /// as a service. Returns false when nothing changed.
    public synchronized boolean reconfigure(ApiInfo newApiInfo) {
        if (newApiInfo.equals(apiInfo)) {
            return false;
        }
        this.api = new TypedApiImplementation(newApiInfo);
        this.apiInfo = newApiInfo;
        // Both wrap the old API, and analysis ids from the old host mean nothing on the new one.
        this.signatureService = null;
        this.analysisDataTypesService = null;
        statusCache.clear();
        return true;
    }

    /// The HTTP client behind the API, for SDK APIs that {@link TypedApiInterface} does not wrap.
    public ApiClient apiClient() {
        if (api instanceof TypedApiImplementation impl) {
            return impl.apiClient();
        }
        throw new IllegalStateException("The configured API is not backed by an HTTP client");
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

        // The function ids alone make the program count as analysed, though none of the portal's names or types
        // may have arrived. One transaction around the whole load is rolled back when any part of it fails, so the
        // program is left as it was, the load can be retried, and the undo history holds nothing to bring it back.
        var program = programWithID.program();
        // Fetched before the transaction opens, so a Detach during the request does not join it
        var functionInfo = api.getFunctionInfo(programWithID.analysisID());
        requireStillAttached(programWithID);
        var transactionId = program.startTransaction("RevEng.AI: Load analysis results");
        boolean loaded = false;
        FunctionAssociation association;
        try {
            association = associateFunctionInfo(programWithID, functionInfo);
            pullFunctionInfoFromAnalysis(association.analysedProgram(), monitor);
            monitor.checkCancelled();
            if (!isStillAttached(programWithID)) {
                // Detached during the pull. Its change to the options joined this transaction, so rolling back
                // would undo the Detach too. Remove the function ids instead, so the program is not taken to
                // be analysed by the analysis it has left.
                if (!program.isClosed()) {
                    clearFunctionAssociation(program);
                }
                loaded = true;
                throw new DetachedDuringLoadException(programWithID);
            }
            loaded = true;
        } finally {
            // A program closed during the load takes no more transactions, and must not hide why the load failed
            if (!program.isClosed()) {
                program.endTransaction(transactionId, loaded);
            }
        }
        Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Function loading summary", association.summary());
        return association.analysedProgram();
    }

    /// What {@link #associateFunctionInfo(ProgramWithID, List)} produced, with the summary to show once the
    /// rest of the load has succeeded too.
    private record FunctionAssociation(AnalysedProgram analysedProgram, String summary) {}

    /// The program was detached from the analysis, or attached to another one, while its results were loading.
    /// The program is left without that analysis' function ids.
    public static class DetachedDuringLoadException extends RuntimeException {
        public DetachedDuringLoadException(ProgramWithID programWithID) {
            super("%s was detached from analysis %d while its results were loading"
                    .formatted(programWithID.program().getName(), programWithID.analysisID().id()));
        }
    }

    private boolean isStillAttached(ProgramWithID programWithID) {
        return !programWithID.program().isClosed()
                && getKnownProgram(programWithID.program()).filter(programWithID::equals).isPresent();
    }

    private void requireStillAttached(ProgramWithID programWithID) {
        if (!isStillAttached(programWithID)) {
            throw new DetachedDuringLoadException(programWithID);
        }
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
    ///
    /// Any association already on the program is replaced, so an earlier load that stopped part way does
    /// not block this one.
    private FunctionAssociation associateFunctionInfo(ProgramWithID knownProgram, List<FunctionInfo> functionInfo) {
        var analysisID = knownProgram.analysisID();
        var program = knownProgram.program();
        var transactionID = program.startTransaction("Associate Function Info");
        clearFunctionAssociation(program);

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
        var summary = ("Found %d functions from RevEng.AI. Your local Ghidra instance has %d/%d matching function " +
                "boundaries. For better results, please start a new analysis from this plugin.").formatted(
                functionInfo.size(),
                ghidraBoundariesMatchedFunction,
                ghidraFunctionCount.get()
        );

        return new FunctionAssociation(analysedProgram, summary);

    }

    /// Put the synced tag back on a function at an address the analysis still maps to a server
    /// function, as after the function was deleted and created again. Does nothing otherwise.
    public void restoreSyncedTag(Function function) {
        var program = function.getProgram();
        var analysedProgram = getAnalysedProgram(program);
        if (analysedProgram.isEmpty() || analysedProgram.get().getIDForFunction(function).isEmpty()) {
            return;
        }
        boolean tagged = function.getTags().stream()
                .anyMatch(tag -> REVENGAI_FUNCTION_TAG.equals(tag.getName()));
        if (!tagged) {
            program.withTransaction("RevEng.AI: Tag re-created function",
                    () -> function.addTag(REVENGAI_FUNCTION_TAG));
        }
    }

    private void markFunctionAsRevEng(BookmarkManager bookmarkManager, Function function, FunctionInfo info) {
        function.addTag(REVENGAI_FUNCTION_TAG);
        bookmarkManager.setBookmark(function.getEntryPoint(), REVENG_BOOKMARK_TYPE, REVENG_BOOKMARK_CATEGORY,
                "Function #" + info.functionID().value());
    }


    public record RenameResult(Function func, String originalName, String newName) {
    }

    /// Push local function renames back to the portal in one request. Answers with the
    /// namespace-qualified name pushed for each function; functions not known on the server are left
    /// out, and when none is known nothing is sent.
    ///
    /// @throws IllegalStateException when the portal accepted the request but renamed fewer functions
    ///                               than were sent; it does not say which, so none counts as pushed
    public Map<Function, String> pushFunctionRenames(AnalysedProgram analysedProgram, Collection<Function> functions)
            throws ApiException {
        Map<Function, String> pushed = new LinkedHashMap<>();
        List<BatchRenameItem> items = new ArrayList<>();
        for (Function function : functions) {
            var withId = analysedProgram.getIDForFunction(function);
            if (withId.isEmpty()) {
                continue;
            }
            String qualifiedName = qualifiedServerName(function);
            var item = new BatchRenameItem();
            item.setFunctionId(withId.get().functionID().value());
            item.setNewName(qualifiedName);
            item.setNewMangledName(qualifiedName);
            items.add(item);
            pushed.put(function, qualifiedName);
        }
        if (items.isEmpty()) {
            return pushed;
        }
        var request = new BatchRenameInputBody();
        request.setFunctions(items);
        long renamed = api.batchRenameFunctions(request);
        if (renamed < items.size()) {
            throw new IllegalStateException("The portal renamed %d of the %d function(s) sent"
                    .formatted(renamed, items.size()));
        }
        return pushed;
    }

    /// The function name as the portal expects it: qualified with its namespace path (joined by
    /// {@code ::}), excluding the artificial RevEng.AI organisational namespace, the namespaces
    /// under it, and the global namespace. Ghidra stores only the leaf label on the symbol, so the
    /// namespace must be re-attached when pushing a rename back — the portal's function names
    /// include the namespace. Applying a match files the function under
    /// {@code RevEng.AI::<matched binary>}, and that binary name is not part of the function's name.
    static String qualifiedServerName(Function function) {
        List<String> parts = new ArrayList<>();
        parts.add(function.getName());
        for (Namespace ns = function.getParentNamespace(); ns != null && !ns.isGlobal(); ns = ns.getParentNamespace()) {
            if (REVENG_AI_NAMESPACE.equals(ns.getName())) {
                // Drop the namespaces collected so far: they are all inside RevEng.AI
                parts.subList(0, parts.size() - 1).clear();
            } else {
                parts.add(0, ns.getName());
            }
        }
        return String.join(Namespace.DELIMITER, parts);
    }

    /// What a push achieved for one function.
    ///
    /// The data types and the signature go up in separate requests, and the second one legitimately
    /// does nothing: the portal answers a signature write for a function it never extracted a
    /// signature for with a 404. Collapsing that into a boolean reported the whole push as failed
    /// and hid the types that *were* written, which makes a local type edit look like a no-op.
    public enum TypePushOutcome {
        /// The function is not part of the analysis, so nothing was sent.
        NOT_MATCHED,
        /// The data types were written; the portal holds no extracted signature to update.
        TYPES_ONLY,
        /// The data types and the function's signature were both written.
        SIGNATURE_WRITTEN
    }

    /// Push the local signature and variables of a function back to the portal.
    public TypePushOutcome pushFunctionTypes(AnalysedProgram analysedProgram, Function function) throws ApiException {
        if (analysedProgram.getIDForFunction(function).isEmpty()) {
            return TypePushOutcome.NOT_MATCHED;
        }
        // The function is known to the analysis, so the type pass below ran for it; only the
        // signature write can still decline.
        return pushFunctionTypes(analysedProgram, List.of(function)) > 0
                ? TypePushOutcome.SIGNATURE_WRITTEN
                : TypePushOutcome.TYPES_ONLY;
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
            int appliedSignatures,
            int canonicalizedNames,
            int dedupedNames,
            int pushedNames,
            int pushedTypeSets,
            int pushedLocalEdits,
            int failedLocalEdits,
            int nameConflicts,
            int signatureConflicts
    ) {}

    /// What sending the unpushed local edits achieved. Every edit that failed is still marked.
    ///
    /// @param pushed      the edits that reached the portal this time
    /// @param unsent      the edits that failed for a reason that may pass — see {@link PushFailure}
    /// @param unsentError why the last of those failed, or null when none did
    /// @param rejected    the edits the portal turned down, or that failed for good, one entry each
    public record LocalEditFlush(int pushed, int unsent, @Nullable Exception unsentError,
                                 List<RejectedEdit> rejected) {
        public int failed() {
            return unsent + rejected.size();
        }
    }

    /// @param edit  which edit, for the log: "rename of \"foo\" at 00401000"
    /// @param error why it failed
    public record RejectedEdit(String edit, Exception error) {
        public PushFailure failure() {
            return PushFailure.of(error);
        }
    }

    private record PendingNamePush(TypedApiInterface.FunctionID functionID, String newName, String newMangledName) {}
    private record InvalidRemoteName(Function function, TypedApiInterface.FunctionID functionID, String remoteName) {}

    /// Reconcile local state with the remote analysis and push back local edits (PLU-322).
    ///
    /// Names: applies remote names locally where the local name is not user-defined, canonicalising
    /// names Ghidra rejects (via the portal canonify endpoint) and de-duplicating names already used
    /// this run; corrected names are pushed back to the portal. Signatures: applies the portal's
    /// signature, and the data types it names, to every matched function whose local signature the
    /// analyst did not write by hand — see {@link #applyRemoteSignatures}. Types: pushes local types
    /// for matched functions whose remote types are absent or could not be applied. Mirrors the IDA
    /// plugin's {@code analysis_sync.py}.
    public SyncSummary syncAnalysisUpdates(AnalysedProgram analysedProgram, TaskMonitor monitor, ReaiLoggingService log) throws ApiException {
        var program = analysedProgram.program();
        log.info("Starting bidirectional sync with the RevEng.AI portal");
        // Before the remote names are read, so an edit that goes up now is not then reported as a
        // conflict with the portal's stale copy of it.
        var flush = pushUnpushedEdits(analysedProgram);
        if (flush.pushed() > 0) {
            log.info("Pushed %d local edit(s) that had not reached the RevEng.AI portal".formatted(flush.pushed()));
        }
        if (flush.unsent() > 0) {
            log.warn("Could not push %d local edit(s) to the RevEng.AI portal: %s"
                    .formatted(flush.unsent(), flush.unsentError()));
        }
        for (RejectedEdit rejected : flush.rejected()) {
            log.warn("The RevEng.AI portal did not take the %s: %s".formatted(rejected.edit(), rejected.error()));
        }
        Map<TypedApiInterface.FunctionID, FunctionInfo> functionInfoMap = api.getFunctionInfo(analysedProgram.analysisID()).stream()
                .collect(Collectors.toMap(FunctionInfo::functionID, fi -> fi, (a, b) -> a));

        Set<String> appliedNames = new HashSet<>();
        List<PendingNamePush> namePushbacks = new ArrayList<>();
        List<InvalidRemoteName> needsCanonical = new ArrayList<>();
        int matched = 0;
        int namesModifiedRemotely = 0;
        int deduped = 0;
        int canonicalizedNames = 0;
        int nameConflicts = 0;

        var transactionId = startServerTransaction(program, "RevEng.AI: Sync Analysis Updates");
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
                // Do not overwrite names the user has explicitly set locally. The portal holding a
                // different name for one means both sides renamed it, unless the local rename is
                // still waiting to go up.
                if (function.getSymbol().getSource() == SourceType.USER_DEFINED) {
                    if (!remoteName.equals(qualifiedServerName(function))
                            && !UnpushedEdits.isMarked(program, UnpushedEdits.Kind.NAME, function.getEntryPoint())) {
                        nameConflicts++;
                        log.warn("Name conflict at %s: \"%s\" locally, \"%s\" in the portal; kept the local name"
                                .formatted(function.getEntryPoint(), function.getName(), remoteName));
                    }
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
            endServerTransaction(program, transactionId, commit && !monitor.isCancelled());
        }

        // Push back over the network only after the local transaction has closed, so we don't hold a
        // program lock across API calls.
        int pushedNames = pushNameBacks(namePushbacks);
        if (pushedNames > 0) {
            log.info("Pushed %d corrected function name(s) back to the RevEng.AI portal".formatted(pushedNames));
        }
        // Pull before pushing, so the back-fill below sees the signatures this sync just applied and
        // does not send the local placeholder back up for a function the portal already described.
        var signatures = applyRemoteSignatures(analysedProgram, monitor, log);
        int appliedSignatures = signatures.applied();
        int pushedTypeSets = pushLocalTypesWhereRemoteMissing(analysedProgram, functionInfoMap.keySet(), monitor, log);

        log.info(("Sync complete: %d matched, %d name(s) applied, %d signature(s) applied, %d canonicalized, "
                + "%d de-duplicated, %d name(s) and %d type set(s) pushed back, %d unpushed local edit(s) "
                + "pushed and %d still failing, %d name and %d signature conflict(s)")
                .formatted(matched, namesModifiedRemotely, appliedSignatures, canonicalizedNames, deduped,
                        pushedNames, pushedTypeSets, flush.pushed(), flush.failed(), nameConflicts,
                        signatures.conflicts()));
        return new SyncSummary(matched, namesModifiedRemotely, appliedSignatures, canonicalizedNames, deduped,
                pushedNames, pushedTypeSets, flush.pushed(), flush.failed(), nameConflicts, signatures.conflicts());
    }

    /// Push the local edits whose reactive push failed or never ran — see {@link UnpushedEdits}. A
    /// function that is gone, or not part of the analysis, has nothing left to push and is unmarked.
    /// Failures are returned rather than logged, so a caller retrying in the background can report an
    /// outage once instead of once per attempt.
    ///
    /// The renames go up as one batch and the type edits through one type pass. When the portal
    /// turns a batch down, the edits are sent again one at a time, so a single edit it will never
    /// take does not keep the others from going up.
    public LocalEditFlush pushUnpushedEdits(AnalysedProgram analysedProgram) {
        var program = analysedProgram.program();
        var flush = new FlushTally();
        Map<Function, Address> renamed = markedFunctions(program, UnpushedEdits.Kind.NAME);
        sendIsolatingRejections(program, UnpushedEdits.Kind.NAME, renamed, flush,
                functions -> pushFunctionRenames(analysedProgram, functions).size(),
                function -> "rename of \"%s\" at %s".formatted(function.getName(), function.getEntryPoint()));

        Map<Function, Address> retyped = markedFunctions(program, UnpushedEdits.Kind.TYPES);
        // A function the analysis does not know has no types on the portal to update.
        retyped.keySet().removeIf(function -> {
            boolean unknown = analysedProgram.getIDForFunction(function).isEmpty();
            if (unknown) {
                UnpushedEdits.clear(program, UnpushedEdits.Kind.TYPES, function.getEntryPoint());
            }
            return unknown;
        });
        // A signature the portal has no extraction for is declined, but its types went up, which is
        // all this push can do.
        sendIsolatingRejections(program, UnpushedEdits.Kind.TYPES, retyped, flush,
                functions -> {
                    pushFunctionTypes(analysedProgram, functions);
                    return functions.size();
                },
                function -> "types of \"%s\" at %s".formatted(function.getName(), function.getEntryPoint()));
        return new LocalEditFlush(flush.pushed, flush.unsent, flush.unsentError, List.copyOf(flush.rejected));
    }

    private static final class FlushTally {
        int pushed;
        int unsent;
        Exception unsentError;
        final List<RejectedEdit> rejected = new ArrayList<>();
    }

    @FunctionalInterface
    private interface EditSender {
        /// Send the edits of these functions and answer with how many went up.
        int send(List<Function> functions) throws Exception;
    }

    /// The functions with a `kind` edit marked, each with the address it is marked at. A mark whose
    /// function is gone is cleared, since nothing is left to send.
    private static Map<Function, Address> markedFunctions(Program program, UnpushedEdits.Kind kind) {
        Map<Function, Address> marked = new LinkedHashMap<>();
        for (Address entryPoint : UnpushedEdits.marked(program, kind)) {
            var function = program.getFunctionManager().getFunctionAt(entryPoint);
            if (function == null) {
                UnpushedEdits.clear(program, kind, entryPoint);
            } else {
                marked.put(function, entryPoint);
            }
        }
        return marked;
    }

    /// Send `marked` as one batch and clear the marks of what went up. When the portal turns the
    /// batch down, send each edit on its own to find the ones it will not take. A failure that may
    /// pass leaves the rest for a later attempt instead, since sending them one by one would only
    /// fail the same way more often.
    private static void sendIsolatingRejections(Program program, UnpushedEdits.Kind kind,
                                                Map<Function, Address> marked, FlushTally flush,
                                                EditSender sender,
                                                java.util.function.Function<Function, String> describe) {
        if (marked.isEmpty()) {
            return;
        }
        List<Function> functions = List.copyOf(marked.keySet());
        try {
            flush.pushed += sender.send(functions);
            marked.values().forEach(entryPoint -> UnpushedEdits.clear(program, kind, entryPoint));
            return;
        } catch (Exception e) {
            if (PushFailure.of(e) != PushFailure.REJECTED || functions.size() == 1) {
                record(flush, functions, e, describe);
                return;
            }
        }
        for (Function function : functions) {
            try {
                flush.pushed += sender.send(List.of(function));
                UnpushedEdits.clear(program, kind, marked.get(function));
            } catch (Exception e) {
                record(flush, List.of(function), e, describe);
            }
        }
    }

    private static void record(FlushTally flush, List<Function> functions, Exception e,
                               java.util.function.Function<Function, String> describe) {
        if (PushFailure.of(e) == PushFailure.TRANSIENT) {
            flush.unsent += functions.size();
            flush.unsentError = e;
        } else {
            functions.forEach(function -> flush.rejected.add(new RejectedEdit(describe.apply(function), e)));
        }
    }

    /// Apply the signatures — and with them the data types they name — that the portal holds for this
    /// analysis' functions, and answer with how many landed.
    ///
    /// Names are deliberately left alone. {@link #syncAnalysisUpdates} owns that decision,
    /// including canonicalising names Ghidra rejects and de-duplicating the ones it has already
    /// applied this run, so the command is given {@link FunctionRenameOption#NO_CHANGE} and nothing
    /// here competes with it.
    ///
    /// A signature is applied unless the analyst wrote the local one by hand, or the server only has
    /// what it extracted itself and the local one is better-founded — see
    /// {@link #localSignatureOutranks}. A signature edited in the portal still replaces one Ghidra
    /// inferred. That is also what makes a second sync useful: an earlier pull stamps
    /// {@link SourceType#ANALYSIS}, so a "default only" guard would turn every pull after the first
    /// into a no-op.
    ///
    /// A hand-written local signature that differs from the portal's is counted as a conflict rather
    /// than applied, unless the local edit is still waiting to go up.
    private SignaturePull applyRemoteSignatures(AnalysedProgram analysedProgram, TaskMonitor monitor,
                                                ReaiLoggingService log) {
        var functionMap = analysedProgram.getFunctionMap();
        if (functionMap.isEmpty()) {
            return new SignaturePull(0, 0);
        }
        var batch = signatures().getMany(List.copyOf(functionMap.keySet()));
        Map<TypedApiInterface.AnalysisID, ServerDataTypeDecoder> decoders = new HashMap<>();
        var program = analysedProgram.program();
        int applied = 0;
        int conflicts = 0;
        var transactionId = startServerTransaction(program, "RevEng.AI: Apply Portal Signatures");
        try {
            for (BatchFunctionSignatureEntry entry : batch.items()) {
                if (monitor.isCancelled()) {
                    break;
                }
                if (!FunctionSignatureService.hasUsableSignature(entry)) {
                    continue;
                }
                var function = functionMap.get(new TypedApiInterface.FunctionID(entry.getFunctionId()));
                if (function == null || function.isExternal() || function.isThunk()
                        || localSignatureOutranks(function, entry)) {
                    continue;
                }
                var signature = getFunctionSignature(entry, decoderFor(decoders, batch, entry));
                if (function.getSignatureSource() == SourceType.USER_DEFINED) {
                    if (!matchesLocalSignature(function, signature)
                            && !UnpushedEdits.isMarked(program, UnpushedEdits.Kind.TYPES, function.getEntryPoint())) {
                        conflicts++;
                        log.warn("Signature conflict for \"%s\" at %s: the portal holds %s; kept the local signature"
                                .formatted(function.getName(), function.getEntryPoint(),
                                        signature.getPrototypeString()));
                    }
                    continue;
                }
                // The portal derives a signature for every function when the analysis completes, so
                // most of them match what is already on the function. Applying those regardless would
                // churn the type manager and fill the undo history on every sync.
                if (matchesLocalSignature(function, signature)) {
                    continue;
                }
                var application = applyRemoteSignature(program, function, signature, monitor,
                        FunctionRenameOption.NO_CHANGE);
                if (application.success()) {
                    applied++;
                    // The prototype is logged because it is the only place the analyst can see what
                    // the portal actually sent, as against what they edited there.
                    log.info("Applied the portal's signature for \"%s\" at %s: %s"
                            .formatted(function.getName(), function.getEntryPoint(),
                                    signature.getPrototypeString()));
                } else {
                    Msg.warn(this, "Failed to apply the portal's signature for %s: %s"
                            .formatted(function.getName(), application.status()));
                }
            }
        } finally {
            endServerTransaction(program, transactionId, applied > 0 && !monitor.isCancelled());
        }
        return new SignaturePull(applied, conflicts);
    }

    /// @param applied   portal signatures that landed locally
    /// @param conflicts hand-written local signatures the portal disagrees with
    private record SignaturePull(int applied, int conflicts) {}

    /// Whether the function's own signature beats one the server extracted itself. A SYSTEM signature
    /// is what server-side Ghidra worked out, so it adds nothing over a signature imported from debug
    /// info locally, or one local analysis inferred, and replacing either can only lose information.
    private static boolean localSignatureOutranks(Function function, BatchFunctionSignatureEntry entry) {
        var local = function.getSignatureSource();
        return entry.getSourceType() == BatchFunctionSignatureEntry.SourceTypeEnum.SYSTEM
                && (local == SourceType.IMPORTED || local == SourceType.ANALYSIS);
    }

    /// Apply one server-sourced signature to a function.
    ///
    /// The conflict handler is the load-bearing argument. Ghidra's default keeps the local type and
    /// files the incoming one beside it as `<name>.conflict`, so a type edited in the portal would
    /// gather a fresh copy locally on every pull; {@link DataTypeConflictHandler#REPLACE_HANDLER}
    /// updates the local type in place instead. The calling convention is preserved because a server
    /// signature carries none — see {@link ServerDataTypeDecoder#signature} — and applying an absent
    /// convention would discard whatever Ghidra had worked out.
    /// Whether the portal's signature is, in every respect this pull applies, what the function
    /// already has.
    ///
    /// {@link FunctionSignature#isEquivalentSignature} cannot answer that. It compares the function
    /// name and the calling convention as well, and this pull applies neither: the name belongs to
    /// the name reconciliation ({@link FunctionRenameOption#NO_CHANGE}) and a server signature
    /// carries no convention. Every function therefore differed on every sync, was re-applied, and
    /// was reported as applied for ever.
    ///
    /// A parameter the server does not name is not a difference. Ghidra names an unnamed parameter
    /// `param_N` when the signature is applied, so treating a missing server name as a difference
    /// would make the comparison oscillate and bring the same re-apply loop back.
    static boolean matchesLocalSignature(Function function, FunctionDefinitionDataType incoming) {
        if (!sameType(function.getReturnType(), incoming.getReturnType())) {
            return false;
        }
        var local = function.getParameters();
        var remote = incoming.getArguments();
        if (local.length != remote.length) {
            return false;
        }
        for (int i = 0; i < local.length; i++) {
            String remoteName = remote[i].getName();
            if (remoteName != null && !remoteName.isBlank() && !remoteName.equals(local[i].getName())) {
                return false;
            }
            if (!sameType(local[i].getDataType(), remote[i].getDataType())) {
                return false;
            }
        }
        return true;
    }

    /// Compared through {@link DataType#isEquivalent} rather than `DataTypeUtilities`, whose package
    /// moved between the Ghidra versions this extension is built against.
    private static boolean sameType(@Nullable DataType local, @Nullable DataType remote) {
        if (local == null || remote == null) {
            return local == remote;
        }
        return local.isEquivalent(remote);
    }

    /// @param success whether the signature landed
    /// @param status  the command's own account of why it did not, for the log
    private record SignatureApplication(boolean success, String status) {}

    private static SignatureApplication applyRemoteSignature(Program program, Function function,
                                                             FunctionDefinitionDataType signature,
                                                             TaskMonitor monitor,
                                                             FunctionRenameOption renameOption) {
        var command = new ApplyFunctionSignatureCmd(
                function.getEntryPoint(),
                signature,
                SourceType.ANALYSIS,
                true,
                false,
                DataTypeConflictHandler.REPLACE_HANDLER,
                renameOption
        );
        boolean success = command.applyTo(program, monitor);
        return new SignatureApplication(success, success ? "" : String.valueOf(command.getStatusMsg()));
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
        // The count the portal reports, not the number asked for: a rename it skipped did not happen.
        return Math.toIntExact(api.batchRenameFunctions(request));
    }

    /// Push local types for matched functions whose remote types are absent or could not be applied,
    /// back-propagating type information to the portal.
    private int pushLocalTypesWhereRemoteMissing(AnalysedProgram analysedProgram,
                                                 Set<TypedApiInterface.FunctionID> matchedIds,
                                                 TaskMonitor monitor,
                                                 ReaiLoggingService log) {
        // Only the matched functions are candidates, and only whether the server holds a usable
        // signature matters here, so ask for exactly those ids and skip the type closure. A placeholder
        // counts as missing: unlike a function with no signature at all, it is a stored row the
        // signature PUT accepts, so these are the functions a push can actually fill in.
        Set<TypedApiInterface.FunctionID> remotePresent = signatures()
                .getMany(List.copyOf(matchedIds), false)
                .items().stream()
                .filter(FunctionSignatureService::hasUsableSignature)
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

    /// Start a transaction that writes server-sourced changes into `program`, during which the reactive
    /// listener ignores that program's type and variable events. Close it with
    /// {@link #endServerTransaction}.
    ///
    /// The window is this one write, not the whole sync: a sync spends most of its time on network
    /// calls, and suppressing for all of it dropped every edit the analyst made meanwhile, in every
    /// open program. Ghidra delivers change events later, from a timer, so the window is bounded by
    /// flushing them: once before, so edits made up to now are delivered as the analyst's, and once
    /// after, so this write's own events are delivered while they are still recognisably ours.
    /// Function and variable renames are never suppressed — see
    /// {@link ai.reveng.toolkit.ghidra.core.services.sync.LocalEditSyncService}.
    private int startServerTransaction(Program program, String description) {
        deliverPendingEvents(program);
        applyingServerChanges.merge(program, 1, Integer::sum);
        try {
            return program.startTransaction(description);
        } catch (RuntimeException e) {
            releaseServerChanges(program);
            throw e;
        }
    }

    private void endServerTransaction(Program program, int transactionId, boolean commit) {
        try {
            program.endTransaction(transactionId, commit);
            deliverPendingEvents(program);
        } finally {
            releaseServerChanges(program);
        }
    }

    /// Deliver every change event `program` has queued, and wait until the listeners have seen them.
    ///
    /// {@link Program#flushEvents} alone does not wait. Ghidra's event timer runs on the Swing thread
    /// and takes the queued events and delivers them in one Swing task; when it has just taken them,
    /// a flush from another thread finds the queue empty and returns while they are still being
    /// delivered. Queuing an empty task behind it waits that delivery out.
    private static void deliverPendingEvents(Program program) {
        program.flushEvents();
        Swing.runNow(() -> {});
    }

    private void releaseServerChanges(Program program) {
        applyingServerChanges.computeIfPresent(program, (p, writes) -> writes > 1 ? writes - 1 : null);
    }

    /// True while the plugin is writing server-sourced changes into `program`; the reactive listener
    /// uses this to avoid pushing those changes back to the portal.
    public boolean isApplyingServerChanges(Program program) {
        return applyingServerChanges.containsKey(program);
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
    /// The initial association happens in {@link #associateFunctionInfo(ProgramWithID, List)}
    ///
    public List<RenameResult> pullFunctionInfoFromAnalysis(AnalysedProgram analysedProgram, TaskMonitor monitor) {
        var transactionId = startServerTransaction(analysedProgram.program(), "RevEng.AI: Pull Function Info from Analysis");

        List<RenameResult> renameResults = new ArrayList<>();

        int failedRenames = 0;
        try {

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
                    .filter(FunctionSignatureService::hasUsableSignature)
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
                if (details == null) {
                    Msg.warn(this, "No server info for function %s, skipping".formatted(function.getName()));
                    continue;
                }

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
                // A signature the local one outranks is treated as absent, so the function can still
                // take the portal's name below.
                Optional<FunctionDefinitionDataType> functionSignatureMessageOpt =
                        Optional.ofNullable(signatureMap.get(fID.get().functionID))
                                .filter(entry -> !localSignatureOutranks(function, entry))
                                .map(entry -> getFunctionSignature(entry, decoderFor(decoders, signatureBatch, entry)));


                analysedProgram.setMangledNameForFunction(function, revEngMangledName);

                /// Source types:
                /// DEFAULT: placeholder name automatically assigned by Ghidra when it doesn’t know the real name.
                /// ANALYSIS: A name/signature inferred by one of Ghidra’s analysis engines (or demangler) rather than simply “default.”
                /// IMPORTED: Information taken from an external source — symbols or signatures imported from a file or database.
                /// USER_DEFINED: A name or signature explicitly set by the analyst.
                /// See {@link ghidra.program.model.symbol.SourceType} for more details
                // The name and the signature are separate decisions. Gating the signature on the name
                // source hid every type the portal held for a function that was already named — by the
                // analyst, or by an earlier run of this same pull — and the signature apply is what
                // carries the data types down.
                if (functionSignatureMessageOpt.isEmpty()) {
                    // No signature to apply, so a rename is all that is left. Skip server-side default
                    // names — Ghidra's own "FUN_" and IDA's "sub_" — so we never overwrite Ghidra's
                    // default placeholder with an IDA-style one.
                    if (function.getSymbol().getSource() == SourceType.DEFAULT
                            && !revEngMangledName.startsWith("FUN_") && !revEngMangledName.startsWith("sub_")
                            && !function.getSymbol().getName(false).equals(revEngDemangledName)) {
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
                } else if (function.getSignatureSource() != SourceType.USER_DEFINED) {
                    // RENAME_IF_DEFAULT preserves the long-standing behaviour that applying a signature
                    // also names a function still carrying Ghidra's placeholder, and leaves every other
                    // name alone.
                    var application = applyRemoteSignature(analysedProgram.program(), function,
                            functionSignatureMessageOpt.get(), monitor, FunctionRenameOption.RENAME_IF_DEFAULT);
                    // For unclear reasons the signature source is not set by the command in Ghidra 11.2.x and lower
                    if (application.success()) {
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
        } finally {
            // Done iterating over all functions. A transaction that changed nothing leaves no undo entry, and
            // aborting it would abort the load it runs inside too, so it is discarded only when cancelled
            endServerTransaction(analysedProgram.program(), transactionId, !monitor.isCancelled());
        }
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
        clearFunctionAssociation(program);
        var reaiOptions = program.getOptions(ReaiPluginPackage.REAI_OPTIONS_CATEGORY);
        reaiOptions.setLong(OPTION_KEY_ANALYSIS_ID, ReaiPluginPackage.INVALID_ANALYSIS_ID);
        // Clear the entire cache. Getting the correct ID is not worth the effort in terms of edge cases to handle
        // because this method should still work even if the analysis ID or binary ID that was associated is invalid
        statusCache.clear();

    }

    /// Remove the function ids and the marks on the functions, but keep the analysis id, so the program is
    /// known but no longer analysed. Must run inside a transaction.
    private void clearFunctionAssociation(Program program) {
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
        // The SDK only reports an unreadable file as an opaque HTTP 0, so check up front.
        try (var ignored = Files.newInputStream(filePath)) {
        } catch (IOException e) {
            throw new RuntimeException(unreadableBinaryMessage(filePath, e), e);
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
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (ApiException e) {
            throw new RuntimeException(TypedApiImplementation.describeApiException(e), e);
        }
    }

    private static String unreadableBinaryMessage(Path path, IOException e) {
        String reason = e instanceof NoSuchFileException ? "file not found"
                : e instanceof FileSystemException fse && fse.getReason() != null ? fse.getReason()
                : e.getMessage();
        String message = "Cannot read %s (%s).".formatted(path, reason);
        if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.MAC_OS_X
                && !(e instanceof NoSuchFileException)) {
            message += "\n\nmacOS may be blocking Ghidra from this folder. Grant access in System Settings → "
                    + "Privacy & Security → Files and Folders, or move the file elsewhere and re-import it.";
        }
        return message;
    }

    public TypedApiInterface.BinaryHash upload(Path path) {
        try {
            return api.upload(path);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (ApiException e) {
            throw new RuntimeException(TypedApiImplementation.describeApiException(e), e);
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
            throw new RuntimeException(TypedApiImplementation.describeApiException(e), e);
        }
    }



    ///  This method analyses a program by uploading it (if necessary), triggering an analysis, and _blocking_
    /// until the analysis is complete. This is for scripts and tests, and must not be used on the UI thread
    /// It does not upload the program, this must be done beforehand, and the hash must be associated via {@link AnalysisOptionsBuilder#hash(TypedApiInterface.BinaryHash)}
    public AnalysedProgram analyse(Program program, AnalysisOptionsBuilder analysisOptionsBuilder, TaskMonitor monitor) throws CancelledException, ApiException {
        // Check if we are on the swing thread
        var programWithBinaryID = startAnalysis(program, analysisOptionsBuilder);
        var waited = waitForAnalysis(monitor, programWithBinaryID, null, null);
        if (waited.ending() != StatusPoller.Ending.DONE) {
            throw new IllegalStateException("Analysis %s did not finish (%s, last status: %s)"
                    .formatted(programWithBinaryID.analysisID().id(), waited.ending(), waited.status()));
        }
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

    public void openFunctionInPortal(ServiceProvider serviceProvider, TypedApiInterface.FunctionID functionID) {
        var details = api.getFunctionDetails(functionID);
        openFunctionInPortal(serviceProvider, details.analysisId(), functionID);
    }

    /// Prefer this overload when the caller already knows the analysis the function belongs to:
    /// it builds the portal URL directly and avoids the getFunctionDetails call, which requires a
    /// permission the user may not have (returns 403) even when they can view the analysis.
    public void openFunctionInPortal(ServiceProvider serviceProvider,
                                     TypedApiInterface.AnalysisID analysisID,
                                     TypedApiInterface.FunctionID functionID) {
        openPortal(serviceProvider, "analyses",
                String.format("%s?view=functions&fn=%s", analysisID.id(), functionID.value()));
    }

    public void openPortalFor(ServiceProvider serviceProvider, TypedApiInterface.FunctionID f){
        openFunctionInPortal(serviceProvider, f);
    }

    public void openPortalFor(ServiceProvider serviceProvider, ProgramWithID programWithID) {
        openPortalFor(serviceProvider, programWithID.analysisID());
    }

    public void openPortalFor(ServiceProvider serviceProvider, TypedApiInterface.AnalysisID analysisID) {
        openPortal(serviceProvider, "analyses", String.valueOf(analysisID.id()));
    }

    public void openPortal(ServiceProvider serviceProvider, String... subPath) {
        StringBuilder sb = new StringBuilder(apiInfo.portalURI().toString());
        for (String s : subPath) {
            if (!s.startsWith("?")){
                sb.append("/");
            }
            sb.append(s);
        }
        WebBrowser.open(URI.create(sb.toString()));
    }


    /**
     * @param tool   The UI tool for firing an event on status changes. Can be null
     * @return The final AnalysisStatus: Complete or Error when the analysis finished, Unknown when the
     *     server reported a status the plugin does not recognise, or the last status seen when the wait
     *     reached its time limit or was interrupted
     */
    public AnalysisStatus waitForFinishedAnalysis(
            TaskMonitor monitor,
            ProgramWithID programWithID,
            @Nullable AnalysisLogConsumer logger,
            @Nullable PluginTool tool

            ) throws CancelledException {
        return waitForAnalysis(monitor, programWithID, logger, tool).status();
    }

    /// Like {@link #waitForFinishedAnalysis}, but also says why the wait ended, so the caller can tell
    /// the user when it stopped without the analysis finishing.
    ///
    /// @throws CancelledException the monitor was cancelled
    public StatusPoller.Result<AnalysisStatus> waitForAnalysis(
            TaskMonitor monitor,
            ProgramWithID programWithID,
            @Nullable AnalysisLogConsumer logger,
            @Nullable PluginTool tool
    ) throws CancelledException {
        monitor.setMessage("Checking analysis status");
        var poller = new StatusPoller<AnalysisStatus>(
                Duration.ofMillis(pollIntervalMs), Duration.ofMillis(maxPollIntervalMs), Duration.ofMillis(maxAnalysisWaitMs))
                .retrying(e -> {
                    if (e instanceof ApiException api && isTransient(api)) {
                        Msg.warn(this, "Transient error polling analysis status, retrying", e);
                        return true;
                    }
                    return false;
                }, MAX_POLL_ATTEMPTS, Duration.ofMillis(maxPollBackoffMs));
        AnalysisStatus[] lastStatus = {null};
        StatusPoller.Result<AnalysisStatus> result;
        try {
            result = poller.poll(
                    () -> api.status(programWithID.analysisID()),
                    currentStatus -> {
                        if (currentStatus != AnalysisStatus.Uploaded && currentStatus != AnalysisStatus.Queued) {
                            // Analysis log endpoint only starts to return data after the analysis is processing
                            try {
                                String logs = this.getAnalysisLog(programWithID.analysisID());
                                if (logger != null) {
                                    logger.consumeLogs(logs, programWithID);
                                }
                                logs.lines().reduce((first, second) -> second).ifPresent(monitor::setMessage);
                            } catch (RuntimeException e) {
                                // Logs are cosmetic; a failed fetch must not end the wait
                                Msg.warn(this, "Failed to fetch analysis logs", e);
                            }
                        }
                        if (currentStatus != lastStatus[0]) {
                            lastStatus[0] = currentStatus;
                            if (tool != null) {
                                tool.firePluginEvent(new RevEngAIAnalysisStatusChangedEvent(null, programWithID, currentStatus));
                            }
                        }
                        return switch (currentStatus) {
                            case Complete, Error -> StatusPoller.Verdict.DONE;
                            case Uploaded, Queued, Processing -> StatusPoller.Verdict.WAIT;
                            case Unknown -> StatusPoller.Verdict.UNRECOGNISED;
                        };
                    },
                    monitor::isCancelled);
        } catch (ApiException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new StatusPoller.Result<>(StatusPoller.Ending.CANCELLED, lastStatus[0], Duration.ZERO);
        }
        if (result.ending() == StatusPoller.Ending.CANCELLED) {
            monitor.checkCancelled();
        }
        if (result.ending() == StatusPoller.Ending.TIMED_OUT) {
            Msg.warn(this, "Stopped waiting for analysis %s after %s; last status: %s"
                    .formatted(programWithID.analysisID().id(), StatusPoller.describe(result.waited()), result.status()));
        }
        return result;
    }

    /// First wait between status polls; it grows while the status stays the same
    private long pollIntervalMs = 500;
    /// Longest wait between status polls while the analysis is running normally
    private long maxPollIntervalMs = 5_000;
    /// Longest wait between status polls while the status endpoint keeps failing transiently
    private long maxPollBackoffMs = 30_000;
    /// How long to wait for an analysis before giving up; it keeps running on the server
    private long maxAnalysisWaitMs = Duration.ofHours(3).toMillis();
    private static final int MAX_POLL_ATTEMPTS = 10;

    /// 5xx, or no response at all (code 0: connection or timeout failure)
    private static boolean isTransient(ApiException e) {
        return e.getCode() == 0 || e.getCode() >= 500;
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
                .filter(FunctionSignatureService::hasUsableSignature)
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

    public CompletableFuture<List<SelectableItem>> searchUsersWithIds(String query) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                List<SelectableItem> selectableItems = api.searchUsers(query).stream()
                        .filter(result -> result.getUsername() != null && !result.getUsername().trim().isEmpty())
                        .map(result -> new SelectableItem(
                                Math.toIntExact(result.getUserId()),
                                result.getUsername()
                        ))
                        .collect(Collectors.toList());

                Msg.info(this, "Found " + selectableItems.size() + " users matching '" + query + "'");
                return selectableItems;

            } catch (Exception e) {
                Msg.error(this, "Error searching users: " + e.getMessage(), e);
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

package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.api.*;
import ai.reveng.model.*;
import ai.reveng.model.ConfigResponse;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.FunctionSignatureBatch;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataTypeReader;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.util.Msg;
import resources.ResourceManager;

import javax.annotation.Nullable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

import ai.reveng.invoker.Configuration;
import ai.reveng.invoker.JSON;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ai.reveng.invoker.auth.ApiKeyAuth;
import ai.reveng.invoker.ApiException;

import static ai.reveng.toolkit.ghidra.core.services.api.LoggingInterceptor.*;

/// The main implementation of the RevEng HTTP API, on top of the generated SDK client
/// Design notes:
/// - every method should correspond to a single API endpoint
/// - every method should simply execute the request and return the response
///      - i.e. no smart checks relying on other API calls to check if e.g. a binary has already been uploaded
public class TypedApiImplementation implements TypedApiInterface {
    /// /v3/analyses caps page_size at 50 and pages forward with an opaque token.
    private static final long ANALYSIS_LIST_PAGE_SIZE = 50;

    /// Omitting analysis_scope makes the server default to PRIVATE only.
    private static final List<String> ALL_ANALYSIS_SCOPES = List.of("PRIVATE", "TEAM", "PUBLIC");

    private final AnalysesCoreApi analysisCoreApi;
    private final ConfigApi configApi;
    private final SearchApi searchApi;
    private final CollectionsApi collectionsApi;
    private final FunctionsCoreApi functionsCoreApi;
    private final FunctionsRenamingHistoryApi functionsRenamingHistoryApi;
    private final FunctionsAiDecompilationApi functionsAiDecompilationApi;
    private final DataTypesApi dataTypesApi;
    private final IamUsersApi iamUsersApi;

    private final Map<AnalysisID, AnalysisBasicInfoOutputBody> analysisBasicInfoCache = new HashMap<>();

    public TypedApiImplementation(String baseUrl, String apiKey) {
        var apiClient = Configuration.getDefaultApiClient();
        apiClient.setBasePath(baseUrl);

        String pluginVersion = "unknown";
        try {
            // This file comes from the release.yml running in the CI
            var inputStream = ResourceManager.getResourceAsStream("reai_ghidra_plugin_version.txt");
            if (inputStream != null) {
                pluginVersion = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).trim();
                inputStream.close();
            }
        } catch (IOException e) {
            // ignore — fall back to "unknown"
        }
        // Looks like:
        // Ghidra/11.3.2-PUBLIC (LINUX(Linux) X86_64(amd64)) RevEng.AI_Plugin/v0.15
        var userAgent = "%s/%s-%s (%s) RevEng.AI_Plugin/%s".formatted(Application.getName(), Application.getApplicationVersion(), Platform.CURRENT_PLATFORM, Application.getApplicationReleaseName(), pluginVersion);

        apiClient.setUserAgent(userAgent);
        apiClient.addDefaultHeader("X-RevEng-Application", userAgent);

        // Use a custom HTTP client to add Ghidra specific logging
        // Set withResponseBody to true if debugging issues with the API to see the full response body
        apiClient.setHttpClient(apiClient.getHttpClient().newBuilder().addInterceptor(ghidraLogger(false)).build());

        apiClient.setConnectTimeout(5000);
        apiClient.setReadTimeout(15000);
        apiClient.setWriteTimeout(15000);

        ApiKeyAuth APIKey = (ApiKeyAuth) apiClient.getAuthentication("APIKey");
        APIKey.setApiKey(apiKey);

        this.analysisCoreApi = new AnalysesCoreApi(apiClient);
        this.searchApi = new SearchApi(apiClient);
        this.collectionsApi = new CollectionsApi(apiClient);
        this.functionsCoreApi = new FunctionsCoreApi(apiClient);
        this.functionsRenamingHistoryApi = new FunctionsRenamingHistoryApi(apiClient);
        this.functionsAiDecompilationApi = new FunctionsAiDecompilationApi(apiClient);
        this.dataTypesApi = new DataTypesApi(apiClient);
        this.configApi = new ConfigApi(apiClient);
        this.iamUsersApi = new IamUsersApi(apiClient);
    }


    public TypedApiImplementation(ApiInfo info){
        this(info.hostURI().toString(), info.apiKey());
    }

    public BinaryHash upload(Path binPath) throws FileNotFoundException, ApiException {
        File bin = binPath.toFile();

        if (!bin.exists())
            throw new FileNotFoundException("Binary to upload does not exist");

        var result = this.analysisCoreApi.uploadFile(UploadFileType.fromValue("BINARY"), bin, null, true);

        return new BinaryHash(result.getData().getSha256Hash());
    }

    /// GET /v3/analyses, filtered to one binary hash and paged to exhaustion.
    ///
    /// All three analysis scopes are requested explicitly because the endpoint narrows to PRIVATE
    /// when the parameter is absent.
    @Deprecated
    public List<AnalysisRecordBody> search(BinaryHash hash) {
        List<AnalysisRecordBody> results = new ArrayList<>();
        String pageToken = null;
        try {
            while (true) {
                ListAnalysesOutputBody page = analysisCoreApi.v3ListAnalyses(
                        null, ALL_ANALYSIS_SCOPES, null, null, null, hash.sha256(),
                        ANALYSIS_LIST_PAGE_SIZE, pageToken, null, null);
                var records = page.getResults();
                if (records == null || records.isEmpty()) {
                    break;
                }
                results.addAll(records);
                pageToken = page.getNextPageToken();
                if (pageToken == null || pageToken.isBlank()) {
                    break;
                }
            }
        } catch (ApiException e) {
            throw new RuntimeException(describeApiException(e), e);
        }
        return results;
    }

    @Override
    public AnalysisID analyse(AnalysisOptionsBuilder options) throws ApiException {
        var analysisRequest = options.toAnalysisCreateRequest();
        var result = this.analysisCoreApi.createAnalysis(analysisRequest, null);
        return new AnalysisID(result.getData().getAnalysisId());
    }

    @Override
    public AnalysisStatus status(AnalysisID analysisID) throws ApiException {
        var status = analysisCoreApi.getAnalysisStatus(analysisID.id());
        return AnalysisStatus.fromApiValue(status.getData().getAnalysisStatus());
    }

    /**
     * The endpoint is paginated by offset and limit, and reports the unpaginated population size as
     * {@code total_count}, so paging walks the offset forward until that many entries have arrived.
     * The offset advances by the number of entries actually returned rather than by the requested
     * limit, so a server-side cap below {@code limit} neither skips nor repeats entries.
     */
    @Override
    public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
        long limit = 1000;
        List<FunctionInfo> functions = new ArrayList<>();
        long offset = 0;
        while (true) {
            ListAnalysisFunctionsOutputBody response;
            try {
                response = this.functionsCoreApi.listAnalysisFunctions((long) analysisID.id(), offset, limit);
            } catch (ApiException e) {
                throw new RuntimeException("Could not find analysis with ID: " + analysisID.id(), e);
            }

            var page = response.getFunctions();
            if (page == null || page.isEmpty()) {
                break;
            }

            page.stream().map(f -> (
                    new FunctionInfo(
                            new FunctionID(f.getFunctionId()),
                            f.getFunctionName(),
                            // The mangled name is optional here; an unmangled symbol carries none,
                            // and callers rely on this field being populated.
                            f.getMangledName() != null ? f.getMangledName() : f.getFunctionName(),
                            f.getFunctionVaddr(),
                            Math.toIntExact(f.getFunctionSize())
                    )
            )).forEach(functions::add);

            offset += page.size();
            Long totalCount = response.getTotalCount();
            if (totalCount == null || offset >= totalCount) {
                break;
            }
        }

        return functions;
    }

    /// GET /v3/analyses/{analysis_id}/logs
    ///
    /// v3 answers with structured entries where v2 answered with one preformatted blob, so the lines
    /// are rendered here into the single string the log view and the progress monitor consume.
    @Override
    public String getAnalysisLogs(AnalysisID analysisID) {
        List<AnalysisLogEntry> entries;
        try {
            entries = analysisCoreApi.v3GetAnalysisLogs((long) analysisID.id()).getEntries();
        } catch (ApiException e) {
            throw new RuntimeException(describeApiException(e), e);
        }
        if (entries == null || entries.isEmpty()) {
            return "";
        }
        return entries.stream()
                .map(TypedApiImplementation::renderLogEntry)
                .collect(Collectors.joining("\n"));
    }

    private static String renderLogEntry(AnalysisLogEntry entry) {
        StringBuilder line = new StringBuilder();
        if (entry.getTimestamp() != null) {
            line.append(entry.getTimestamp()).append(' ');
        }
        if (entry.getLevel() != null) {
            line.append(entry.getLevel().getValue()).append(' ');
        }
        if (entry.getSource() != null && !entry.getSource().isBlank()) {
            line.append('[').append(entry.getSource()).append("] ");
        }
        if (entry.getText() != null) {
            line.append(entry.getText());
        }
        return line.toString();
    }

    /// GET /v3/functions/signatures
    ///
    /// Read through the generated call rather than the generated response model: the response
    /// embeds `DataTypeEntry`, whose generated deserialiser picks a variant by counting matching
    /// fields instead of reading the `kind` discriminator, and every variant carries the same
    /// required fields. The call still builds the request — path, query, auth — exactly as the SDK
    /// would; only the body is read by {@link ServerDataTypeReader}.
    @Override
    public FunctionSignatureBatch listFunctionSignatures(List<FunctionID> functionIDs, boolean includeDataTypes) {
        try {
            var call = dataTypesApi.v3ListFunctionSignaturesCall(
                    functionIDs.stream().map(FunctionID::value).toList(), includeDataTypes, null);
            JsonObject body = executeForJsonObject(call, "list function signatures");

            List<BatchFunctionSignatureEntry> items = new ArrayList<>();
            JsonArray rawItems = body.getAsJsonArray("items");
            if (rawItems != null) {
                for (JsonElement item : rawItems) {
                    items.add(JSON.getGson().fromJson(item, BatchFunctionSignatureEntry.class));
                }
            }

            Map<AnalysisID, List<ServerDataType>> dataTypes = new LinkedHashMap<>();
            JsonArray groups = body.getAsJsonArray("data_types");
            if (groups != null) {
                for (JsonElement group : groups) {
                    if (!group.isJsonObject()) {
                        continue;
                    }
                    JsonElement analysisId = group.getAsJsonObject().get("analysis_id");
                    if (analysisId == null || analysisId.isJsonNull()) {
                        continue;
                    }
                    dataTypes.computeIfAbsent(new AnalysisID(analysisId.getAsInt()), ignored -> new ArrayList<>())
                            .addAll(ServerDataTypeReader.readEntries(group, "items"));
                }
            }
            return new FunctionSignatureBatch(items, dataTypes);
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }

    /// GET /v3/analyses/{analysis_id}/data-types
    ///
    /// Read through the generated call for the same reason as
    /// {@link #listFunctionSignatures(List, boolean)}.
    @Override
    public List<ServerDataType> listAnalysisDataTypes(AnalysisID analysisID, long offset, long limit) {
        try {
            var call = dataTypesApi.v3ListAnalysisDataTypesCall(
                    (long) analysisID.id(), offset, limit, null, null, null, null, null, null, null);
            return ServerDataTypeReader.readEntries(
                    executeForJsonObject(call, "list analysis data types"), "items");
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }

    /// POST /v3/analyses/{analysis_id}/data-types
    ///
    /// Written through the generated call for the same reason the reads are: the 201 body embeds
    /// `DataTypeEntry`. The request body is a generated model, which serialises correctly — only
    /// the deserialiser is unusable.
    @Override
    public List<ServerDataType> createAnalysisDataTypes(AnalysisID analysisID,
                                                        CreateAnalysisDataTypesInputBody request) throws ApiException {
        var call = dataTypesApi.v3CreateAnalysisDataTypesCall((long) analysisID.id(), request, null);
        return ServerDataTypeReader.readEntries(
                executeForJsonObject(call, "create analysis data types"), "data_types");
    }

    /// PUT /v3/analyses/{analysis_id}/data-types
    @Override
    public List<ServerDataType> updateAnalysisDataTypes(AnalysisID analysisID,
                                                        UpdateAnalysisDataTypesInputBody request) throws ApiException {
        var call = dataTypesApi.v3UpdateAnalysisDataTypesCall((long) analysisID.id(), request, null);
        return ServerDataTypeReader.readEntries(
                executeForJsonObject(call, "update analysis data types"), "data_types");
    }

    /// PUT /v3/analyses/{analysis_id}/functions/{function_id}/signature
    ///
    /// The response holds no `DataTypeEntry`, so the generated model reads it fine — and going
    /// through it keeps the status code on the {@link ApiException}, which is how a function
    /// without an extracted signature is told apart from a real failure.
    @Override
    public void updateFunctionSignature(AnalysisID analysisID, FunctionID functionID,
                                        UpdateFunctionSignatureInputBody signature) throws ApiException {
        dataTypesApi.v3UpdateFunctionSignature((long) analysisID.id(), functionID.value(), signature);
    }

    /// GET /v3/analyses/{analysis_id}/functions/{function_id}/signature/history
    ///
    /// The history body holds no `DataTypeEntry`, so the generated model reads it fine.
    @Override
    public List<FunctionSignatureVersion> getFunctionSignatureHistory(AnalysisID analysisID, FunctionID functionID) {
        try {
            var versions = dataTypesApi
                    .v3GetFunctionSignatureHistory((long) analysisID.id(), functionID.value())
                    .getVersions();
            return versions == null ? List.of() : versions;
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }

    private static JsonObject executeForJsonObject(okhttp3.Call call, String what) throws ApiException {
        try (okhttp3.Response response = call.execute()) {
            okhttp3.ResponseBody responseBody = response.body();
            String text = responseBody == null ? "" : responseBody.string();
            if (!response.isSuccessful()) {
                throw new ApiException(response.code(), "Failed to %s: HTTP %d".formatted(what, response.code()));
            }
            JsonElement parsed = JsonParser.parseString(text);
            if (!parsed.isJsonObject()) {
                throw new ApiException("Failed to %s: response was not a JSON object".formatted(what));
            }
            return parsed.getAsJsonObject();
        } catch (IOException e) {
            throw new ApiException(e);
        }
    }

    @Override
    public boolean triggerAIDecompilationForFunctionID(FunctionID functionID) {
        try {
            // POST /v3/functions/{function_id}/ai-decompilation
            // The context_aware flag was removed from the API with no replacement; temperature is
            // left null so the server applies its own default.
            var result = functionsAiDecompilationApi.createAiDecompilation(functionID.value(), null);
            return Boolean.TRUE.equals(result.getStatus());
        } catch (ApiException e) {
            throw new RuntimeException("Failed to trigger AI decompilation", e);
        }
    }

    @Override
    public AIDecompilationStatus pollAIDecompileStatus(FunctionID functionID) {
        try {
            // GET /v3/functions/{function_id}/ai-decompilation
            DecompilationData data = functionsAiDecompilationApi.getAiDecompilation(functionID.value());
            String summary = null;
            // TODO: no v3 endpoint currently returns a predicted function name. It used to ride on
            // the removed /ai-decompilation/tokenised response; neither /token-values nor
            // /line-attributions carries it, so the predicted-name panel stays hidden until the API
            // offers it again.
            String predictedFunctionName = null;
            WorkflowProgress.StatusEnum summaryStatus = null;
            WorkflowProgress.StatusEnum inlineCommentsStatus = null;
            List<AIDecompilationStatus.InlineCommentEntry> inlineComments = List.of();
            WorkflowProgress decompilationProgress = null;
            if (data.getStatus() != DecompilationData.StatusEnum.COMPLETED
                    && data.getStatus() != DecompilationData.StatusEnum.FAILED) {
                try {
                    // GET /v3/functions/{function_id}/ai-decompilation/status — step/messages for the progress view
                    decompilationProgress = functionsAiDecompilationApi.getAiDecompilationStatus(functionID.value());
                } catch (ApiException | RuntimeException e) {
                    Msg.info(this, "Could not fetch decompilation progress for function " + functionID.value() + ": " + e.getMessage());
                }
            }
            if (data.getStatus() == DecompilationData.StatusEnum.COMPLETED) {
                try {
                    // GET /v3/functions/{function_id}/ai-decompilation/summary/status
                    WorkflowProgress summaryProgress = functionsAiDecompilationApi.getAiDecompilationSummaryStatus(functionID.value());
                    summaryStatus = summaryProgress.getStatus();
                } catch (ApiException | RuntimeException e) {
                    Msg.info(this, "Could not fetch summary status for function " + functionID.value() + ": " + e.getMessage());
                }
                try {
                    // GET /v3/functions/{function_id}/ai-decompilation/summary
                    SummaryData summaryData = functionsAiDecompilationApi.getAiDecompilationSummary(functionID.value());
                    summary = summaryData.getAiSummary() != null ? summaryData.getAiSummary() : summaryData.getSummary();
                } catch (ApiException e) {
                    Msg.info(this, "Decompilation completed but summary not yet available for function " + functionID.value());
                }
                try {
                    // GET /v3/functions/{function_id}/ai-decompilation/inline-comments/status
                    WorkflowProgress commentsProgress = functionsAiDecompilationApi.getAiDecompilationInlineCommentsStatus(functionID.value());
                    inlineCommentsStatus = commentsProgress.getStatus();
                } catch (ApiException | RuntimeException e) {
                    Msg.info(this, "Could not fetch inline comments status for function " + functionID.value() + ": " + e.getMessage());
                }
                if (inlineCommentsStatus == WorkflowProgress.StatusEnum.COMPLETED) {
                    try {
                        // GET /v3/functions/{function_id}/ai-decompilation/inline-comments
                        CommentsData commentsData = functionsAiDecompilationApi.getAiDecompilationInlineComments(functionID.value());
                        var rawComments = commentsData.getInlineComments();
                        if (rawComments != null) {
                            inlineComments = rawComments.stream()
                                    .filter(c -> c.getLine() != null && c.getComment() != null)
                                    .map(c -> new AIDecompilationStatus.InlineCommentEntry(c.getLine(), c.getComment()))
                                    .toList();
                        }
                    } catch (ApiException | RuntimeException e) {
                        Msg.info(this, "Could not fetch inline comments for function " + functionID.value() + ": " + e.getMessage());
                    }
                }
            }
            return new AIDecompilationStatus(
                    data.getStatus(),
                    data.getDecompilation(),
                    summary,
                    predictedFunctionName,
                    summaryStatus,
                    inlineCommentsStatus,
                    inlineComments,
                    decompilationProgress);
        } catch (ApiException e) {
            if (e.getCode() == 404) {
                return new AIDecompilationStatus(
                        DecompilationData.StatusEnum.UNINITIALISED,
                        null, null, null, null, null, List.of(), null);
            }
            throw new RuntimeException("Failed to poll AI decompilation status", e);
        }
    }

    @Override
    public void triggerAIDecompilationInlineComments(FunctionID functionID) {
        try {
            // POST /v3/functions/{function_id}/ai-decompilation/inline-comments
            functionsAiDecompilationApi.regenerateAiDecompilationInlineComments(functionID.value());
        } catch (ApiException e) {
            throw new RuntimeException("Failed to trigger AI decompilation inline comments: " + describeApiException(e), e);
        }
    }

    @Override
    public void triggerAIDecompilationSummary(FunctionID functionID) {
        try {
            // POST /v3/functions/{function_id}/ai-decompilation/summary
            functionsAiDecompilationApi.regenerateAiDecompilationSummary(functionID.value());
        } catch (ApiException e) {
            throw new RuntimeException("Failed to trigger AI decompilation summary: " + describeApiException(e), e);
        }
    }

    @Override
    public GetTokensResponse getAIDecompilationTokens(FunctionID functionID) throws ApiException {
        // GET /v3/functions/{function_id}/ai-decompilation/tokens
        return functionsAiDecompilationApi.v3GetAiDecompilationTokens(functionID.value());
    }

    @Override
    public UpsertOverridesData applyAIDecompilationOverrides(FunctionID functionID, java.util.Map<String, String> overrides) throws ApiException {
        // PUT /v3/functions/{function_id}/ai-decompilation/overrides
        var wrapped = new java.util.LinkedHashMap<String, Token>();
        overrides.forEach((token, value) -> wrapped.put(token, new Token().value(value)));
        var body = new UpsertOverridesInputBody().overrides(wrapped);
        return functionsAiDecompilationApi.v3UpsertAiDecompilationOverrides(functionID.value(), body);
    }

    @Override
    public void setAIDecompilationInlineComment(FunctionID functionID, long line, String comment) throws ApiException {
        // PATCH /v3/functions/{function_id}/ai-decompilation/inline-comments
        var body = new PatchCommentBody().comment(comment).line(line);
        functionsAiDecompilationApi.patchAiDecompilationInlineComment(functionID.value(), body);
    }

    @Override
    public void deleteAIDecompilationInlineComment(FunctionID functionID, long line) throws ApiException {
        // DELETE /v3/functions/{function_id}/ai-decompilation/inline-comments/{line}
        functionsAiDecompilationApi.deleteAiDecompilationInlineComment(functionID.value(), line);
    }

    private static String describeApiException(ApiException e) {
        // The SDK's ApiException carries the HTTP status and response body separately from the message;
        // surface both so callers logging only getMessage() can still diagnose server-side failures.
        return "HTTP " + e.getCode() + " — " + (e.getResponseBody() != null ? e.getResponseBody() : e.getMessage());
    }

    /// POST /v3/functions/rename, with a one-item body: v3 has no per-function rename route.
    /// The endpoint answers 200 with the number of functions it renamed, so a count of zero is
    /// raised rather than passed off to the caller as a successful rename.
    @Override
    public void renameFunction(FunctionID id, String newName, String newNameMangled) {
        var item = new BatchRenameItem();
        item.setFunctionId(id.value());
        item.setNewName(newName);
        item.setNewMangledName(newNameMangled);
        var request = new BatchRenameInputBody();
        request.setFunctions(List.of(item));
        BatchRenameOutputBody response;
        try {
            response = functionsRenamingHistoryApi.batchRenameFunctions(request);
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
        Long renamedCount = response == null ? null : response.getRenamedCount();
        if (renamedCount == null || renamedCount < 1) {
            throw new RuntimeException("Server did not rename function " + id.value() + " to " + newName
                    + " (renamed_count: " + renamedCount + ")");
        }
    }

    @Override
    public FunctionDetails getFunctionDetails(FunctionID id) {
        try {
            return FunctionDetails.fromServerResponse(functionsCoreApi.getFunctionDetails_0(id.value()));
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public AutoUnstripStatus getAutoUnstripStatus(AnalysisID analysisID) throws ApiException {
        var body = analysisCoreApi.v3GetAnalysisAutoUnstripStatus((long) analysisID.id());
        if (body == null || body.getStatus() == null) {
            return AutoUnstripStatus.UNKNOWN;
        }
        return switch (body.getStatus()) {
            case UNINITIALISED -> AutoUnstripStatus.UNINITIALISED;
            case PENDING -> AutoUnstripStatus.PENDING;
            case RUNNING -> AutoUnstripStatus.RUNNING;
            case COMPLETED -> AutoUnstripStatus.COMPLETED;
            case FAILED -> AutoUnstripStatus.FAILED;
            default -> AutoUnstripStatus.UNKNOWN;
        };
    }

    @Override
    public void aiDecompRating(FunctionID functionID, String rating, @Nullable String reason) throws ApiException {
        var request = new UpsertAiDecomplationRatingRequest();
        request.setRating(AiDecompilationRating.fromValue(rating));
        if (reason != null) {
            request.setReason(reason);
        }

        functionsAiDecompilationApi.upsertAiDecompilationRating(functionID.value(), request);
    }

    @Override
    public List<CollectionListItemBody> searchCollections(String partialCollectionName) throws ApiException {
        // The v3 list-collections endpoint does not filter by model; scope is handled server-side.
        var results = this.collectionsApi
                .v3ListCollections(partialCollectionName, null, 10L, 0L, null, null)
                .getResults();
        return results != null ? results : List.of();
    }

    @Override
    public List<BinarySearchResult> searchBinaries(String partialBinaryName, String modelName) throws ApiException {
        return this.searchApi.searchBinaries(1, 10, partialBinaryName, null, null, modelName, null, null, null).getData().getResults();
    }

    @Override
    public AnalysisBasicInfoOutputBody getAnalysisBasicInfo(AnalysisID analysisID) throws ApiException {
        AnalysisBasicInfoOutputBody cachedResult = analysisBasicInfoCache.get(analysisID);
        if (cachedResult != null) {
            Msg.info(this, "Returning cached analysis basic info for analysis ID: " + analysisID.id());
            return cachedResult;
        }

        Msg.info(this, "Fetching analysis basic info from API for analysis ID: " + analysisID.id());
        AnalysisBasicInfoOutputBody result = this.analysisCoreApi.getAnalysisBasicInfo_0((long) analysisID.id());

        analysisBasicInfoCache.put(analysisID, result);

        return result;
    }

    @Override
    public StartMatchingOutputBody startAnalysisFunctionMatching(AnalysisID analysisID, StartMatchingForAnalysisInputBody request) throws ApiException {
        return this.analysisCoreApi.startAnalysisFunctionMatching((long) analysisID.id(), request);
    }

    @Override
    public GetMatchesStatusOutputBody getAnalysisFunctionMatchingStatus(AnalysisID analysisID) throws ApiException {
        return this.analysisCoreApi.getAnalysisFunctionMatchingStatus((long) analysisID.id(), null);
    }

    @Override
    public GetMatchesOutputBody getAnalysisFunctionMatches(AnalysisID analysisID) throws ApiException {
        return this.analysisCoreApi.getAnalysisFunctionMatches((long) analysisID.id(), null);
    }

    @Override
    public StartMatchingOutputBody startFunctionsMatching(StartMatchingForFunctionsInputBody request) throws ApiException {
        return this.functionsCoreApi.startFunctionsMatching(request);
    }

    @Override
    public GetMatchesStatusOutputBody getFunctionsMatchingStatus(List<Long> functionIds) throws ApiException {
        return this.functionsCoreApi.getFunctionsMatchingStatus(null, functionIds);
    }

    @Override
    public GetMatchesOutputBody getFunctionsMatches(List<Long> functionIds) throws ApiException {
        return this.functionsCoreApi.getFunctionsMatches(null, functionIds);
    }

    @Override
    public void batchRenameFunctions(BatchRenameInputBody request) throws ApiException {
        this.functionsRenamingHistoryApi.batchRenameFunctions(request);
    }

    /// GET /v3/functions/{function_id}/blocks
    ///
    /// Returns the function's assembly in address order, or an empty list when the function carries
    /// no stored disassembly: v3 reports that as a 200 whose block fields are simply absent, where
    /// the deprecated v2 endpoint answered 404. A 404 from v3 means the function itself could not be
    /// reached, and a 409 that the analysis is not ready yet; both stay on the {@link ApiException}
    /// so the caller can tell them apart by status code.
    @Override
    public List<String> getAssembly(FunctionID id) {
        try {
            DisassemblyOutputBody disassembly = this.functionsCoreApi.getFunctionBlocks_0(id.value());
            return DisassemblyBlocksReader.readAssembly(disassembly.getBasicBlocks());
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public java.util.Map<String, String> canonicalizeFunctionNames(List<String> names) throws ApiException {
        var body = new CanonicalizeNamesInputBody().names(names);
        var response = functionsCoreApi.v3CanonicalizeFunctionNames(body);
        var mapping = new java.util.HashMap<String, String>();
        if (response.getResults() != null) {
            for (var result : response.getResults()) {
                if (result.getName() != null && result.getCanonicalName() != null) {
                    mapping.put(result.getName(), result.getCanonicalName());
                }
            }
        }
        return mapping;
    }

    // TODO: getFunctionDataTypesWithVersion / pushFunctionDataTypes / mapPushStatus were removed
    // here. They pushed a whole v2 data-type blob per function under optimistic concurrency, and
    // neither those endpoints nor their models exist in the v3 API. The replacement writes types
    // and signatures separately — POST/PATCH /v3/analyses/{analysis_id}/data-types to mint or
    // update a type and get its data_type_id back, then PUT the signature that refers to it — and
    // lands in a follow-up.

    @Override
    public ConfigResponse getConfig() {
        try {
            return this.configApi.getConfig().getData();
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public User getMe() {
        try {
            return this.iamUsersApi.getMe();
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }
}

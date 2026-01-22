package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.api.*;
import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.Collection;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.LegacyCollection;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.APIAuthenticationException;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.APIConflictException;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.util.Msg;
import org.json.JSONArray;
import org.json.JSONObject;
import resources.ResourceManager;

import javax.annotation.Nullable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;

import ai.reveng.invoker.Configuration;
import ai.reveng.invoker.auth.ApiKeyAuth;
import ai.reveng.invoker.ApiException;

import static ai.reveng.toolkit.ghidra.core.services.api.LoggingInterceptor.*;
import static ai.reveng.toolkit.ghidra.core.services.api.Utils.mapJSONArray;
import static java.net.http.HttpClient.Version.HTTP_1_1;

/// The main implementation of the RevEng HTTP API
/// It partially relies on the old manual implementation, but should be migrated to the OpenAPI generated client over time
/// Design notes:
/// - every method should correspond to a single API endpoint
/// - every method should simply execute the request and return the response
///      - i.e. no smart checks relying on other API calls to check if e.g. a binary has already been uploaded
public class TypedApiImplementation implements TypedApiInterface {
    private final HttpClient httpClient;
    private final String baseUrl;
    Map<String, String> headers;

    private final AnalysesCoreApi analysisCoreApi;
    private final AuthenticationUsersApi authenticationUsersApi;
    private final AnalysesResultsMetadataApi analysesResultsMetadataApi;
    private final SearchApi searchApi;
    private final FunctionsCoreApi functionsCoreApi;
    private final FunctionsRenamingHistoryApi functionsRenamingHistoryApi;
    private final FunctionsAiDecompilationApi functionsAiDecompilationApi;
    private final FunctionsDataTypesApi functionsDataTypesApi;

    // Cache for binary ID to analysis ID mappings
    @Deprecated
    private final Map<BinaryID, AnalysisID> binaryToAnalysisCache = new HashMap<>();

    // Cache for analysis basic info to avoid repeated API calls
    private final Map<AnalysisID, ai.reveng.model.Basic> analysisBasicInfoCache = new HashMap<>();

    public TypedApiImplementation(String baseUrl, String apiKey) {
        var apiClient = Configuration.getDefaultApiClient();
        apiClient.setBasePath(baseUrl);

        String pluginVersion = "unknown";
        try {
            // This file comes from the release.yml running in the CI
            var inputStream = ResourceManager.getResourceAsStream("reai_ghidra_plugin_version.txt");
            pluginVersion = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).trim();
            inputStream.close();
        } catch (IOException e) {

        }
        // Looks like:
        // Ghidra/11.3.2-PUBLIC (LINUX(Linux) X86_64(amd64)) RevEng.AI_Plugin/v0.15
        var userAgent = "%s/%s-%s (%s) RevEng.AI_Plugin/%s".formatted(Application.getName(), Application.getApplicationVersion(), Platform.CURRENT_PLATFORM, Application.getApplicationReleaseName(), pluginVersion);

        apiClient.setUserAgent(userAgent);
        apiClient.addDefaultHeader("X-RevEng-Application", userAgent);

        // Use a custom HTTP client to add Ghidra specific logging
        // Set withResponseBody to true if debugging issues with the API to see the full response body
        apiClient.setHttpClient(apiClient.getHttpClient().newBuilder().addInterceptor(ghidraLogger(false)).build());

        ApiKeyAuth APIKey = (ApiKeyAuth) apiClient.getAuthentication("APIKey");
        APIKey.setApiKey(apiKey);

        this.analysisCoreApi = new AnalysesCoreApi(apiClient);
        this.authenticationUsersApi = new AuthenticationUsersApi(apiClient);
        this.analysesResultsMetadataApi = new AnalysesResultsMetadataApi(apiClient);
        this.searchApi = new SearchApi(apiClient);
        this.functionsCoreApi = new FunctionsCoreApi(apiClient);
        this.functionsRenamingHistoryApi = new FunctionsRenamingHistoryApi(apiClient);
        this.functionsAiDecompilationApi = new FunctionsAiDecompilationApi(apiClient);
        this.functionsDataTypesApi = new FunctionsDataTypesApi(apiClient);

        this.baseUrl = baseUrl + "/";
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .version(HTTP_1_1) // by default the client would attempt HTTP2.0 which leads to weird issues
                .build();
        headers = new HashMap<>();
        headers.put("Authorization", apiKey);
        headers.put("User-Agent", userAgent);
        headers.put("X-RevEng-Application", userAgent);

        // TODO: Actually implement support for some encodings and then accept them
//        headers.put("Accept-Encoding", "gzip, deflate, br");
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

    /*
    Allows you to search for specific analyses and collections.
    The query parameter follows a non standard formatting using key-pair comma seperated values.
    he base query is formatted as follows: /search?search=sha_256_hash:<hash>,binary_name:<binary_name>,tags=<tag>,collection_name:<collection_name>.
    Not all parameters are required, for example /search?search=sha_256_hash:<hash> only searches for binaries and collection with hashes like <hash>.

     */
    @Deprecated
    public List<LegacyAnalysisResult> search(BinaryHash hash) {
        Map<String, String> params = new HashMap<>();
        params.put("sha256_hash", hash.sha256());

        JSONObject json = sendRequest(
                requestBuilderForEndpoint("analyses", "list",  queryParams(params))
                        .GET()
                        .header("Content-Type", "application/json" )
                        .build());

        return mapJSONArray(json.getJSONObject("data").getJSONArray("results"), LegacyAnalysisResult::fromJSONObject);
    }

    private V2Response sendVersion2Request(HttpRequest request){
        return V2Response.fromJSONObject(sendRequest(request));
    }

    private JSONObject sendRequest(HttpRequest request) throws APIAuthenticationException {
        Msg.info(this, "Sending request to: " + request.uri());
        HttpResponse<String> response = null;

        var retryAttempts = 3;
        while (response == null && retryAttempts > 0) {
            try {
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            } catch (HttpTimeoutException timeout) {
                // Sometimes the API hangs, and works again shortly after, so we just try again
                Msg.info(this, "Timed out waiting for response from: " + request.uri());
                Msg.info(this, "Trying again: " + request.uri());
                retryAttempts--;
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }

        switch (response.statusCode()){
            case 200:
            case 201:
                Msg.info(this, "Request to %s succeeded with status code: %s".formatted(request.uri(), response.statusCode()));
                return new JSONObject(response.body());
            case 404:
                return new JSONObject(response.body());
            case 401:
                throw new APIAuthenticationException(response.body());
            case 409:
                throw new APIConflictException(response.body());
            default:
                var errorMsg = "Request to %s failed with status code: %s and message: %s".formatted(request.uri(), response.statusCode(), response.body());
                Msg.showError(this, null, "Request failed with status code: " + response.statusCode(), errorMsg);
                throw new RuntimeException(errorMsg);
        }
    }

    @Override
    public AnalysisID analyse(AnalysisOptionsBuilder options) throws ApiException {
        var analysisRequest = options.toAnalysisCreateRequest();
        var result = this.analysisCoreApi.createAnalysis(analysisRequest, null);
        return new AnalysisID(result.getData().getAnalysisId());
    }

    @Deprecated
    @Override
    public AnalysisStatus status(BinaryID binaryID) throws ApiException {
        var analysisID = this.getAnalysisIDfromBinaryID(binaryID);

        var status = this.analysisCoreApi.getAnalysisStatus(analysisID.id());

        return AnalysisStatus.valueOf(status.getData().getAnalysisStatus());
    }

    @Override
    public AnalysisStatus status(AnalysisID analysisID) throws ApiException {
        var status = analysisCoreApi.getAnalysisStatus(analysisID.id());
        return AnalysisStatus.valueOf(status.getData().getAnalysisStatus());
    }

    @Override
    public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {

        BaseResponseAnalysisFunctions response = null;
        try {
            response = this.analysesResultsMetadataApi.getFunctionsList(analysisID.id(), null, null, null);
        } catch (ApiException e) {
            throw new RuntimeException("Could not find analysis with ID: " + analysisID.id(), e);
        }

        return response.getData().getFunctions().stream().map(f -> (
                new FunctionInfo(
                        new FunctionID(f.getFunctionId()),
                        f.getFunctionName(),
                        f.getFunctionMangledName(),
                        f.getFunctionVaddr(),
                        f.getFunctionSize()
                )
        )).toList();
    }

    private String queryParams(Map<String, String> params){
        return "?" + params.entrySet().stream()
                .filter(e -> e.getValue() != null)
                .map(e -> e.getKey() + "=" + e.getValue())
                .reduce((a, b) -> a + "&" + b)
                .orElse("");
    }
    /**
     * <a href="https://api.reveng.ai/v2/docs#tag/Collections/operation/list_collections_v2_collections_get">...</a>
     *
     * Parameters are passed via query parameters
     * @param searchTerm
     * @return
     */
    @Override
    public List<Collection> searchCollections(String searchTerm,
                                                    @Nullable List<SearchFilter> filter,
                                                    int limit,
                                                    int offset,
                                                    @Nullable CollectionResultOrder orderBy,
                                                    @Nullable OrderDirection order
    ){
        Map<String, String> params = new HashMap<>();
        params.put("search_term", searchTerm);
        params.put("limit", String.valueOf(limit));
        params.put("offset", String.valueOf(offset));
        if (filter != null){
            params.put("filter", filter.stream().map(SearchFilter::name).reduce( (a, b) -> a + "," + b).orElse(null));
        }
        if (orderBy != null){
            params.put("order_by", orderBy.name());
        }
        if (order != null){
            params.put("order", order.name());
        }
        params.put("limit", String.valueOf(limit));

        var request = requestBuilderForEndpoint("collections", queryParams(params))
                .timeout(Duration.ofSeconds(10))
                .method("GET", HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();
        var response = sendVersion2Request(request);
        var resultAsLegacyCollections =  mapJSONArray(response.getJsonData().getJSONArray("results"), LegacyCollection::fromJSONObject);
        return resultAsLegacyCollections.stream().map( legacyCollection -> this.getCollectionInfo(legacyCollection.collectionID())).toList();
    }

    /**
     * <a href="https://api.reveng.ai/v2/docs#tag/Platform-Search/operation/search_binaries_v2_search_binaries_get">Binaries Search</a>
     * @param searchTerm
     * @return
     */
    @Override
    public List<AnalysisID> searchBinaries(String searchTerm) {
        Map<String, String> params = new HashMap<>();
        params.put("partial_name", searchTerm);
        params.put("page_size", "20");
//        params.put("page", String.valueOf(offset));

        var request = requestBuilderForEndpoint("search", "binaries", queryParams(params))
                .timeout(Duration.ofSeconds(10))
                .method("GET", HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();

        var response = sendVersion2Request(request);
        var resultIDs =  mapJSONArray(response.getJsonData().getJSONArray("results"), entry -> ((JSONObject) entry).getInt("analysis_id"))
                .stream().map(AnalysisID::new).toList();
        return resultIDs;
    }

    @Override
    public String getAnalysisLogs(AnalysisID analysisID) {
        var request = requestBuilderForEndpoint("analyses", String.valueOf(analysisID.id()), "logs")
                .build();
        JSONObject response = sendVersion2Request(request).getJsonData();
        return response.getString("logs");
    }

    private HttpRequest.Builder requestBuilderForEndpoint(String... endpointPaths){
        URI uri;
        String apiVersionPath = "v2";
        String endpoint = String.join("/", endpointPaths).replace("/?", "?").replace("?/", "?");

        try {
            uri = new URI(baseUrl + apiVersionPath + "/" + endpoint);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        var requestBuilder = HttpRequest.newBuilder(uri);
        headers.forEach(requestBuilder::header);
        requestBuilder.timeout(Duration.ofSeconds(20));
        return requestBuilder;
    }

    /**
     * <a href="https://api.reveng.ai/v2/docs#tag/Analysis-Management/operation/get_analysis_id_v2_analyses_lookup__binary_id__get">...</a>
     *
     * The mapping never changes so we can cache it to avoid repeated requests.
     *
     * @param binaryID the binary id to look up
     * @return the analysis id
     */
    @Override
    @Deprecated
    public AnalysisID getAnalysisIDfromBinaryID(BinaryID binaryID){
        // Check cache first
        AnalysisID cachedResult = binaryToAnalysisCache.get(binaryID);
        if (cachedResult != null) {
            return cachedResult;
        }

        // If not in cache, make HTTP request
        JSONObject response = sendRequest(requestBuilderForEndpoint("analyses/lookup/" + binaryID.value())
                .GET()
                .build());

        AnalysisID analysisID = new AnalysisID(response.getInt("analysis_id"));

        // Cache the result
        binaryToAnalysisCache.put(binaryID, analysisID);

        return analysisID;
    }

    /**
     * Triggers the generation of function data types for a provided list of functions
     * <a href="https://api.reveng.ai/v2/docs#tag/Function-Overview/operation/generate_function_datatypes_v2_analyses__analysis_id__info_functions_data_types_post">...</a>
     * https://api.reveng.ai/v2/analyses/{analysis_id}/info/functions/data_types
     * @param functionIDS
     * @return
     */
    @Override
    public DataTypeList generateFunctionDataTypes(AnalysisID analysisID, List<FunctionID> functionIDS) throws APIConflictException{
        JSONObject params = new JSONObject();
        params.put("function_ids", functionIDS.stream().map(FunctionID::value).toList());

        var request = requestBuilderForEndpoint("analyses/%s/info/functions/data_types".formatted(analysisID.id()))
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();

        var response = sendVersion2Request(request);
        return DataTypeList.fromJson(response.getJsonData().getJSONObject("data_types_list"));
    }

    @Override
    public DataTypeList getFunctionDataTypes(List<FunctionID> functionIDS) {
        String queryString = functionIDS.stream().map( f -> "function_ids=" + f.value() ).reduce((a, b) -> a + "&" + b).orElseThrow();
        var request = requestBuilderForEndpoint("functions", "data_types?", queryString)
                .GET()
                .header("Content-Type", "application/json" )
                .build();
        var response = sendVersion2Request(request);
        return DataTypeList.fromJson(response.getJsonData());
    }

    public FunctionDataTypesList listFunctionDataTypesForAnalysis(AnalysisID id, List<FunctionID> ids) {
        try {
            List<Integer> functionIds = null;
            if (ids == null) {
                functionIds = null;
            } else {
                functionIds = ids.stream().map(FunctionID::value).map(Long::intValue).toList();
            }
            var r = functionsDataTypesApi.listFunctionDataTypesForAnalysis(id.id(), functionIds);
            var data = r.getData();
            return data;
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public FunctionDataTypesList listFunctionDataTypesForFunctions(List<FunctionID> functionIDs) {
        try {
            var r = functionsDataTypesApi.listFunctionDataTypesForFunctions(functionIDs.stream().map(FunctionID::value).map(Long::intValue).toList());
            var data = r.getData();
            return data;
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<FunctionDataTypeStatus> getFunctionDataTypes(AnalysisID analysisID, FunctionID functionID) {
        // https://api.reveng.ai/v2/analyses/{analysis_id}/info/functions/{function_id}/data_types
        var request = requestBuilderForEndpoint("analyses/%s/info/functions/%s/data_types".formatted(analysisID.id(), functionID.value()))
                .GET()
                .header("Content-Type", "application/json" )
                .build();
        var response = sendVersion2Request(request);
        if (response.errors() == null){
            return Optional.of(FunctionDataTypeStatus.fromJson(response.getJsonData()));
        } else {
            return Optional.empty();
        }
    }

    @Override
    public void authenticate() throws InvalidAPIInfoException {
        try {
            this.authenticationUsersApi.getRequesterUserInfo();
        } catch (ApiException e) {
            throw new InvalidAPIInfoException("Invalid API key", e);
        }
    }

    @Override
    public boolean triggerAIDecompilationForFunctionID(FunctionID functionID) {
        JSONObject params = new JSONObject().put("function_id", functionID.value());
        HttpRequest request = requestBuilderForEndpoint("ai-decompilation")
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();
        return sendVersion2Request(request).status();
    }

    @Override
    public AIDecompilationStatus pollAIDecompileStatus(FunctionID functionID) {

        HttpRequest request = requestBuilderForEndpoint("ai-decompilation/" + functionID.value(), "?summarise=true")
                .GET()
                .build();
        return AIDecompilationStatus.fromJSONObject(sendVersion2Request(request).getJsonData());

    }

    /**
     * https://api.reveng.ai/v2/docs#tag/Functions-overview/operation/rename_function_id_v2_functions_rename__function_id__post
     * @param id
     * @param newName
     */
    @Override
    public void renameFunction(FunctionID id, String newName) {
        JSONObject params = new JSONObject();
        params.put("new_name", newName);

        HttpRequest request = requestBuilderForEndpoint("functions", "rename", String.valueOf(id.value()))
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .build();
        sendRequest(request);
    }

    @Override
    public FunctionNameScore getNameScore(FunctionMatch match) {
        return getNameScores(List.of(match), false).get(0);
    }

    /**
     * <a href="https://api.reveng.ai/v2/docs#tag/Collections/operation/get_collection_v2_collections__collection_id__get">Collection Info</a>
     *
     * @param id
     * @return
     */
    @Override
    public Collection getCollectionInfo(CollectionID id) {
        var request = requestBuilderForEndpoint("collections", String.valueOf(id.id()))
                .GET()
                .build();
        var response = sendVersion2Request(request);
        return Collection.fromJSONObject(response.getJsonData());
    }

    /**
     * https://api.reveng.ai/v2/docs#tag/Confidence-Scores/operation/function_threat_score_v2_confidence_functions_threat_score_post
     */
    @Override
    public List<FunctionNameScore> getNameScores(List<FunctionMatch> matches, Boolean isDebug) {
        JSONObject params = new JSONObject();
        params.put("is_debug", isDebug);
        var functions = new ArrayList<JSONObject>();
        for (var match : matches){
            functions.add(new JSONObject()
                    // The id of the original function that matches were searched for
                    .put("function_id", match.origin_function_id().value())
                    // The name of the nearest neighbor function for which we want the score
                    .put("function_name_mangled", match.nearest_neighbor_function_name()));
        }
        params.put("functions", functions);

        HttpRequest request = requestBuilderForEndpoint("confidence", "functions", "name_score")
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();
        JSONArray responseData = (JSONArray) sendVersion2Request(request).data();
        return mapJSONArray(responseData, FunctionNameScore::fromJSONObject);
    }

    /**
     *
     * @param id
     * @return
     */
    @Override
    public AnalysisResult getInfoForAnalysis(AnalysisID id) {
        try {
            var response = analysisCoreApi.getAnalysisBasicInfo(id.id());
            var data = response.getData();
            if (data == null) {
                throw new RuntimeException("Unexpected null data for analysis ID: " + id.id());
            }
            return new AnalysisResult(
                    id,
                    data
            );
        } catch (ApiException e) {
            throw new IllegalArgumentException("Could not find analysis with ID: " + id.id());
        }
    }

    /**
     * https://api.reveng.ai/redoc#tag/Functions-overview/operation/function_detail_v2_functions__function_id__get
     * @param id
     * @return
     */
    @Override
    public FunctionDetails getFunctionDetails(FunctionID id) {
        BaseResponseFunctionsDetailResponse dets = null;
        try {
            dets = functionsCoreApi.getFunctionDetails((int) id.value());
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
        return FunctionDetails.fromServerResponse(dets.getData());

    }

    @Override
    public TypedAutoUnstripResponse autoUnstrip(AnalysisID analysisID) {
        try {
            return new TypedAutoUnstripResponse(functionsCoreApi.autoUnstrip(analysisID.id(), new AutoUnstripRequest()));
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public TypedAutoUnstripResponse aiUnstrip(AnalysisID analysisID) {
        try {
            return new TypedAutoUnstripResponse(functionsCoreApi.aiUnstrip(analysisID.id(), new AiUnstripRequest()));
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
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
    public List<CollectionSearchResult> searchCollections(String partialCollectionName, String modelName) throws ApiException {
        return this.searchApi.searchCollections(1, 10, partialCollectionName, null, null, null, modelName, List.of(Filters.HIDE_EMPTY), null, null).getData().getResults();
    }

    @Override
    public List<BinarySearchResult> searchBinaries(String partialBinaryName, String modelName) throws ApiException {
        return this.searchApi.searchBinaries(1, 10, partialBinaryName, null, null, modelName, null).getData().getResults();
    }

    @Override
    public ai.reveng.model.Basic getAnalysisBasicInfo(AnalysisID analysisID) throws ApiException {
        // Check cache first
        ai.reveng.model.Basic cachedResult = analysisBasicInfoCache.get(analysisID);
        if (cachedResult != null) {
            Msg.info(this, "Returning cached analysis basic info for analysis ID: " + analysisID.id());
            return cachedResult;
        }

        // If not in cache, make API call
        Msg.info(this, "Fetching analysis basic info from API for analysis ID: " + analysisID.id());
        ai.reveng.model.Basic result = this.analysisCoreApi.getAnalysisBasicInfo(analysisID.id()).getData();

        // Cache the result for future requests
        analysisBasicInfoCache.put(analysisID, result);

        return result;
    }

    @Override
    public FunctionMatchingResponse analysisFunctionMatching(AnalysisID analysisID, AnalysisFunctionMatchingRequest request) throws ApiException {
        return this.functionsCoreApi.analysisFunctionMatching(analysisID.id(), request);
    }

    @Override
    public FunctionMatchingResponse functionFunctionMatching(FunctionMatchingRequest request) throws ApiException {
        return this.functionsCoreApi.batchFunctionMatching(request);
    }

    @Override
    public void batchRenameFunctions(FunctionsListRename functionsList) throws ApiException {
        this.functionsRenamingHistoryApi.batchRenameFunction(functionsList);
    }

    @Override
    public List<String> getAssembly(FunctionID id) {

        FunctionBlocksResponse blocks;
        List<String> result =  new ArrayList<>();
        try {
            blocks = this.functionsCoreApi.getFunctionBlocks(id.asInteger()).getData();
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }
        blocks.getBlocks().stream()
                .sorted( (b1, b2) -> b1.getMinAddr().compareTo(b2.getMinAddr()) )
                .forEach(block -> {
                    result.addAll(block.getAsm());
                });

        return result;
    }

}


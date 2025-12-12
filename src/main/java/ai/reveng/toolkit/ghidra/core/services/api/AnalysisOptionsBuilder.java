package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisScope;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionBoundary;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import org.json.JSONArray;
import org.json.JSONObject;
import ai.reveng.model.AnalysisCreateRequest;
import ai.reveng.model.Tag;

import java.util.ArrayList;
import java.util.List;

public class AnalysisOptionsBuilder {
    private JSONObject options;

    // Package-private constructor for testing
    AnalysisOptionsBuilder() {
        options = new JSONObject();
        options.put("size_in_bytes", 0);
        options.put("tags", new JSONArray());
    }

    public AnalysisOptionsBuilder functionBoundaries(long base, List<FunctionBoundary> functionList){
        JSONObject symbols = new JSONObject();
        symbols.put("base_addr", base);

        JSONArray functions = new JSONArray();
        functionList.forEach(f -> functions.put(f.toJSON()));

        symbols.put("functions", functions);
        options.put("symbols", symbols);
        return this;
    }

    public AnalysisOptionsBuilder hash(TypedApiInterface.BinaryHash hash) {
        options.put("sha_256_hash", hash.sha256());
        return this;
    }

    public AnalysisOptionsBuilder advancedAnalysis(boolean advanced) {
        options.put("advanced_analysis", advanced);
        return this;
    }

    public AnalysisOptionsBuilder fileName(String name) {
        options.put("file_name", name);
        return this;
    }

    public AnalysisOptionsBuilder size(long size) {
        options.put("size_in_bytes", size);
        return this;
    }

    public long getSize() {
        return options.optLong("size_in_bytes", 0);
    }

    public AnalysisOptionsBuilder scope(AnalysisScope scope){
        options.put("binary_scope", scope.scope);
        return this;
    }

    public static AnalysisOptionsBuilder forProgram(Program program) {
        return new AnalysisOptionsBuilder()
                .hash(new TypedApiInterface.BinaryHash(program.getExecutableSHA256()))
                .fileName(program.getName())
                .functionBoundaries(
                        program.getImageBase().getOffset(),
                        GhidraRevengService.exportFunctionBoundaries(program
                        )
                );
    }

    public AnalysisOptionsBuilder skipSBOM(boolean b) {
        options.put("skip_sbom", b);
        return this;
    }

    public AnalysisOptionsBuilder skipScraping(boolean b) {
        options.put("skip_scraping", b);
        return this;
    }

    public AnalysisOptionsBuilder skipCVE(boolean b) {
        options.put("skip_cves", b);
        return this;
    }

    public AnalysisOptionsBuilder dynamicExecution(boolean b) {
        options.put("dynamic_execution", b);
        return this;
    }

    public AnalysisOptionsBuilder skipCapabilities(boolean b) {
        options.put("skip_capabilities", b);
        return this;
    }

    public AnalysisOptionsBuilder addTag(String tag) {
        options.getJSONArray("tags").put(tag);
        return this;
    }

    public AnalysisOptionsBuilder addTags(List<String> tags) {
        JSONArray tagArray = options.getJSONArray("tags");
        tags.forEach(tagArray::put);
        return this;
    }

    public List<String> getTags() {
        JSONArray tagArray = options.getJSONArray("tags");
        List<String> tags = new ArrayList<>();
        for (int i = 0; i < tagArray.length(); i++) {
            tags.add(tagArray.getString(i));
        }
        return tags;
    }

    public AnalysisOptionsBuilder architecture(String arch) {
        options.put("isa_options", arch);
        return this;
    }

    /**
     * Converts the current AnalysisOptionsBuilder to an AnalysisCreateRequest object
     * that can be used with the new API endpoints
     *
     * @return AnalysisCreateRequest object populated with the current options
     */
    public AnalysisCreateRequest toAnalysisCreateRequest() {
        // Create the request with only the core required fields that we know work
        var request = new AnalysisCreateRequest()
                .filename(options.getString("file_name"))
                .sha256Hash(options.getString("sha_256_hash"));

        // Include tags if any were provided
        List<String> tagStrings = getTags();
        if (!tagStrings.isEmpty()) {
            // Convert string tags to Tag objects, filtering out any empty/null strings
            List<Tag> tags = tagStrings.stream()
                    .filter(tagString -> tagString != null && !tagString.trim().isEmpty())
                    .map(tagString -> new Tag().name(tagString))
                    .toList();

            // Only set tags if we have valid ones after filtering
            if (!tags.isEmpty()) {
                request.setTags(tags);
            }
        }

        if (options.has("binary_scope")) {
            var scope = options.getString("binary_scope");
            request.analysisScope(ai.reveng.model.AnalysisScope.fromValue(scope));
        }

        if (options.has("symbols")) {
            JSONObject symbols = options.getJSONObject("symbols");

            var symbolsModel = new ai.reveng.model.Symbols()
                    .baseAddress(symbols.getBigInteger("base_addr"));

            List<ai.reveng.model.FunctionBoundary> boundaries = new ArrayList<>();

            if (symbols.has("functions")) {
                JSONArray functions = symbols.getJSONArray("functions");
                for (int i = 0; i < functions.length(); i++) {
                    var functionJSON = functions.getJSONObject(i);

                    var functionBoundary = new ai.reveng.model.FunctionBoundary()
                            .mangledName(functionJSON.getString("mangled_name"))
                            .startAddress(functionJSON.getLong("start_addr"))
                            .endAddress(functionJSON.getLong("end_addr"));

                    boundaries.add(functionBoundary);
                }
                symbolsModel.setFunctionBoundaries(boundaries);
            }

            request.setSymbols(symbolsModel);
        }

        var analysisConfig = new ai.reveng.model.AnalysisConfig();

        if (options.has("skip_sbom")) {
            analysisConfig.setGenerateSbom(!options.getBoolean("skip_sbom"));
        }

        if (options.has("skip_cves")) {
            analysisConfig.setGenerateCves(!options.getBoolean("skip_cves"));
        }

        if (options.has("skip_capabilities")) {
            analysisConfig.setGenerateCapabilities(!options.getBoolean("skip_capabilities"));
        }

        if (options.has("advanced_analysis")) {
            analysisConfig.setAdvancedAnalysis(options.getBoolean("advanced_analysis"));
        }

        request.setAnalysisConfig(analysisConfig);

        var binaryConfig = new ai.reveng.model.BinaryConfig();

        if (options.has("isa_options")) {
            var isaOption = options.getString("isa_options");
            if (!isaOption.equals("Auto")) {
                var isa = ai.reveng.model.ISA.fromValue(isaOption);
                binaryConfig.setIsa(isa);
            }
        }

        request.setBinaryConfig(binaryConfig);

        Msg.info(this, "Created AnalysisCreateRequest: " + request);

        return request;
    }
}

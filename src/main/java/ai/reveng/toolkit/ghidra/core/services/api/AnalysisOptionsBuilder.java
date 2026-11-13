package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisScope;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionBoundary;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import org.json.JSONArray;
import org.json.JSONObject;
import ai.reveng.model.CreateRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

public class AnalysisOptionsBuilder {
    private JSONObject options;

    // Package-private constructor for testing
    AnalysisOptionsBuilder() {
        options = new JSONObject();
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

    public AnalysisOptionsBuilder fileName(String name) {
        options.put("file_name", name);
        return this;
    }

    public AnalysisOptionsBuilder scope(AnalysisScope scope){
        options.put("binary_scope", scope.scope);
        return this;
    }

    public AnalysisScope getScope() {
        if (!options.has("binary_scope")) {
            return null;
        }
        return AnalysisScope.valueOf(options.getString("binary_scope"));
    }

    public static AnalysisOptionsBuilder forProgram(Program program) {
        return forProgram(program, function -> true);
    }

    public static AnalysisOptionsBuilder forProgram(Program program, Predicate<Function> includePredicate) {
        return new AnalysisOptionsBuilder()
                .hash(new TypedApiInterface.BinaryHash(program.getExecutableSHA256()))
                .fileName(program.getName())
                .functionBoundaries(
                        program.getImageBase().getOffset(),
                        GhidraRevengService.exportFunctionBoundaries(program, includePredicate)
                );
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
     * Converts the current AnalysisOptionsBuilder to the v3 create-analysis request.
     *
     * @return CreateRequest populated with the current options
     */
    public CreateRequest toAnalysisCreateRequest() {
        var request = new CreateRequest()
                .filename(options.getString("file_name"))
                .sha256Hash(options.getString("sha_256_hash"));

        List<String> tags = getTags().stream()
                .filter(tag -> tag != null && !tag.trim().isEmpty())
                .toList();
        if (!tags.isEmpty()) {
            request.setTags(tags);
        }

        if (options.has("binary_scope")) {
            var scope = options.getString("binary_scope");
            request.analysisScope(CreateRequest.AnalysisScopeEnum.fromValue(scope));
        }

        if (options.has("symbols")) {
            JSONObject symbols = options.getJSONObject("symbols");

            var symbolsModel = new ai.reveng.model.Symbols()
                    .baseAddress(symbols.getBigInteger("base_addr").longValue());

            List<ai.reveng.model.FunctionBoundary> boundaries = new ArrayList<>();

            if (symbols.has("functions")) {
                JSONArray functions = symbols.getJSONArray("functions");
                for (int i = 0; i < functions.length(); i++) {
                    var functionJSON = functions.getJSONObject(i);

                    var functionBoundary = new ai.reveng.model.FunctionBoundary()
                            .mangledName(functionJSON.getString("mangled_name"))
                            .startAddress(functionJSON.getLong("start_addr"))
                            .endAddress(functionJSON.getLong("end_addr"))
                            .includeInAnalysis(functionJSON.optBoolean("include_in_analysis", true));

                    boundaries.add(functionBoundary);
                }
                symbolsModel.setFunctionBoundaries(boundaries);
            }

            request.setSymbols(symbolsModel);
        }

        var analysisConfig = new ai.reveng.model.Config();

        if (options.has("skip_capabilities")) {
            analysisConfig.setGenerateCapabilities(!options.getBoolean("skip_capabilities"));
        }

        request.setAnalysisConfig(analysisConfig);

        var binaryConfig = new ai.reveng.model.BinaryConfig();

        if (options.has("isa_options")) {
            var isaOption = options.getString("isa_options");
            if (!isaOption.equals("Auto")) {
                var isa = ai.reveng.model.BinaryConfig.IsaEnum.fromValue(isaOption);
                binaryConfig.setIsa(isa);
            }
        }

        request.setBinaryConfig(binaryConfig);

        Msg.info(this, "Created CreateRequest: " + request);

        return request;
    }
}

package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.model.FunctionBoundary;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisScope;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ai.reveng.model.AnalysisCreateRequest;
import ai.reveng.model.Tag;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class AnalysisOptionsBuilder {
    private String fileName;
    private String sha256Hash;
    private long sizeInBytes;
    private final List<String> tags = new ArrayList<>();
    private AnalysisScope scope;
    private String architecture;
    private boolean advancedAnalysis;
    private boolean skipSBOM;
    private boolean skipScraping;
    private boolean skipCVE;
    private boolean dynamicExecution;
    private boolean skipCapabilities;

    private Long baseAddress;
    private List<FunctionBoundary> functionBoundaries;

    // Package-private constructor for testing
    AnalysisOptionsBuilder() {
    }

    public AnalysisOptionsBuilder functionBoundaries(long base, List<FunctionBoundary> boundaries) {
        this.baseAddress = base;
        this.functionBoundaries = boundaries;
        return this;
    }

    private static FunctionBoundary functionBoundaryForFunction(Function function, Boolean include) {
        return new FunctionBoundary()
                .mangledName(function.getSymbol().getName(false))
                .startAddress(function.getEntryPoint().getOffset())
                .endAddress(function.getBody().getMaxAddress().getOffset())
                .includeInAnalysis(include);

    }

    /**
     * Sets function boundaries from all Ghidra Functions in the program, marking selected ones for analysis.
     *
     * @param base The base address offset
     * @param allFunctions All functions in the program
     * @param selectedFunctions The functions the user selected for analysis
     * @return this builder for method chaining
     */
    public AnalysisOptionsBuilder functionBoundariesFromGhidraFunctions(long base, List<Function> allFunctions, List<Function> selectedFunctions) {
        Set<Function> selectedSet = Set.copyOf(selectedFunctions);

        List<FunctionBoundary> all = new ArrayList<>();

        for (Function function : allFunctions) {
            if (!GhidraRevengService.isRelevantForAnalysis(function)) {
                continue;
            }

            all.add(this.functionBoundaryForFunction(function, selectedFunctions.contains(function)));
        }
        return functionBoundaries(base, all);
    }

    public AnalysisOptionsBuilder hash(TypedApiInterface.BinaryHash hash) {
        this.sha256Hash = hash.sha256();
        return this;
    }

    public AnalysisOptionsBuilder advancedAnalysis(boolean advanced) {
        this.advancedAnalysis = advanced;
        return this;
    }

    public AnalysisOptionsBuilder fileName(String name) {
        this.fileName = name;
        return this;
    }

    public AnalysisOptionsBuilder size(long size) {
        this.sizeInBytes = size;
        return this;
    }

    public long getSize() {
        return sizeInBytes;
    }

    public AnalysisOptionsBuilder scope(AnalysisScope scope) {
        this.scope = scope;
        return this;
    }

    public static AnalysisOptionsBuilder forProgram(Program program) {
        List<FunctionBoundary> result = new ArrayList<>();
        program.getFunctionManager().getFunctions(true).forEach(
                function -> {
                    if (!GhidraRevengService.isRelevantForAnalysis(function)) {
                        return;
                    }
                    result.add(functionBoundaryForFunction(function, true));
                }
        );
        return new AnalysisOptionsBuilder()
                .hash(new TypedApiInterface.BinaryHash(program.getExecutableSHA256()))
                .fileName(program.getName())
                .functionBoundaries(
                        program.getImageBase().getOffset(),
                        result
                );
    }

    /**
     * Creates an AnalysisOptionsBuilder for a program where all functions are sent,
     * but only the selected ones are marked with includeInAnalysis=true.
     *
     * @param program The Ghidra program
     * @param selectedFunctions The list of functions the user selected for analysis
     * @return A new AnalysisOptionsBuilder configured for the program
     */
    public static AnalysisOptionsBuilder forProgramWithFunctions(Program program, List<Function> selectedFunctions) {
        List<Function> allFunctions = new ArrayList<>();
        program.getFunctionManager().getFunctions(true).forEach(allFunctions::add);

        return new AnalysisOptionsBuilder()
                .hash(new TypedApiInterface.BinaryHash(program.getExecutableSHA256()))
                .fileName(program.getName())
                .functionBoundariesFromGhidraFunctions(
                        program.getImageBase().getOffset(),
                        allFunctions,
                        selectedFunctions
                );
    }

    public AnalysisOptionsBuilder skipSBOM(boolean b) {
        this.skipSBOM = b;
        return this;
    }

    public AnalysisOptionsBuilder skipScraping(boolean b) {
        this.skipScraping = b;
        return this;
    }

    public AnalysisOptionsBuilder skipCVE(boolean b) {
        this.skipCVE = b;
        return this;
    }

    public AnalysisOptionsBuilder dynamicExecution(boolean b) {
        this.dynamicExecution = b;
        return this;
    }

    public AnalysisOptionsBuilder skipCapabilities(boolean b) {
        this.skipCapabilities = b;
        return this;
    }

    public AnalysisOptionsBuilder addTag(String tag) {
        tags.add(tag);
        return this;
    }

    public AnalysisOptionsBuilder addTags(List<String> tags) {
        this.tags.addAll(tags);
        return this;
    }

    public List<String> getTags() {
        return List.copyOf(tags);
    }

    public AnalysisOptionsBuilder architecture(String arch) {
        this.architecture = arch;
        return this;
    }

    /**
     * Converts the current AnalysisOptionsBuilder to an AnalysisCreateRequest object
     * that can be used with the API endpoints.
     *
     * @return AnalysisCreateRequest object populated with the current options
     */
    public AnalysisCreateRequest toAnalysisCreateRequest() {
        var request = new AnalysisCreateRequest()
                .filename(fileName)
                .sha256Hash(sha256Hash);

        // Include tags if any were provided
        List<Tag> validTags = tags.stream()
                .filter(t -> t != null && !t.trim().isEmpty())
                .map(t -> new Tag().name(t))
                .toList();
        if (!validTags.isEmpty()) {
            request.setTags(validTags);
        }

        if (scope != null) {
            request.analysisScope(ai.reveng.model.AnalysisScope.fromValue(scope.scope));
        }

        if (baseAddress != null && functionBoundaries != null) {
            var symbolsModel = new ai.reveng.model.Symbols()
                    .baseAddress(BigInteger.valueOf(baseAddress));

            symbolsModel.setFunctionBoundaries(this.functionBoundaries);
            request.setSymbols(symbolsModel);
        }

        var analysisConfig = new ai.reveng.model.AnalysisConfig();
        analysisConfig.setGenerateSbom(!skipSBOM);
        analysisConfig.setGenerateCves(!skipCVE);
        analysisConfig.setGenerateCapabilities(!skipCapabilities);
        analysisConfig.setAdvancedAnalysis(advancedAnalysis);
        request.setAnalysisConfig(analysisConfig);

        var binaryConfig = new ai.reveng.model.BinaryConfig();
        if (architecture != null && !architecture.equals("Auto")) {
            binaryConfig.setIsa(ai.reveng.model.ISA.fromValue(architecture));
        }
        request.setBinaryConfig(binaryConfig);

        Msg.info(this, "Created AnalysisCreateRequest: " + request);

        return request;
    }
}

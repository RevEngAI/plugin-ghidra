package ai.reveng.toolkit.ghidra.core;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ghidra.framework.plugintool.PluginEvent;

/// Indicates that RevEng AI analysis results have been loaded and other components and plugins can now start using them.
/// This event is fired after the analysis results have been fully integrated into the program.
/// This means:
/// - Function IDs have been associated with {@link ghidra.program.model.listing.Function}s
public class RevEngAIAnalysisResultsLoaded extends PluginEvent {
    public static final String NAME = "RevEngAIAnalysisResultsLoaded";
    private final GhidraRevengService.AnalysedProgram programWithBinaryID;

    public RevEngAIAnalysisResultsLoaded(String source, GhidraRevengService.AnalysedProgram programWithBinaryID) {
        super(NAME, source);
        this.programWithBinaryID = programWithBinaryID;
    }
    public GhidraRevengService.AnalysedProgram getProgramWithBinaryID() {
        return programWithBinaryID;
    }
}

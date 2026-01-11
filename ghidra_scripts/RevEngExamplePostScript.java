import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.ApiInfo;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;

public class RevEngExamplePostScript extends GhidraScript {
    @Override
    protected void run() throws Exception {
        // Services are not available in headless mode, so we have to instantiate it ourselves
        var ghidraRevengService = new GhidraRevengService(ApiInfo.fromConfig());

        ghidraRevengService.upload(currentProgram);

        AnalysisOptionsBuilder options = AnalysisOptionsBuilder.forProgram(currentProgram);
        var analyzedProgram = ghidraRevengService.analyse(currentProgram, options, monitor);
    }
}

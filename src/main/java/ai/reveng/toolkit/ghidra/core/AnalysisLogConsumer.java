package ai.reveng.toolkit.ghidra.core;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;

public interface AnalysisLogConsumer {

    void consumeLogs(String logs, GhidraRevengService.ProgramWithBinaryID programWithBinaryID);
}

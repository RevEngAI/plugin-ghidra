package ai.reveng.toolkit.ghidra.core.services.api.types;

/// This is a special box type for an analysis ID
/// It enforces that the integer is specifically an analysis ID,
/// and it implies that the user has access to this ID
public record AnalysisID(int id) {
}

package ai.reveng.toolkit.ghidra.core.services.api.types;

/**
 * The lifecycle states an analysis is reported to be in by the API.
 *
 * <p>A freshly created analysis reports {@link #Uploaded} before it is queued. The server may also
 * report values this plugin does not model, so statuses are resolved with {@link #fromApiValue}
 * rather than {@link #valueOf}: an unrecognised value becomes {@link #Unknown} instead of throwing.
 *
 * <p>The constant names are the wire values, so {@code name()} can be compared against a raw status
 * string from the API.
 */
public enum AnalysisStatus {
    Uploaded,
    Queued,
    Processing,
    Complete,
    Error,
    /** Any status the server reported that is not modelled above. */
    Unknown;

    /**
     * Resolves a status string from the API, mapping null and unrecognised values to {@link #Unknown}.
     */
    public static AnalysisStatus fromApiValue(String value) {
        if (value == null) {
            return Unknown;
        }
        for (AnalysisStatus status : values()) {
            if (status.name().equalsIgnoreCase(value)) {
                return status;
            }
        }
        return Unknown;
    }
}

package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.model.StatusInput;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Guards that every status the API can report resolves to an {@link AnalysisStatus} without throwing.
 */
public class AnalysisStatusTest {

    @Test
    public void uploadedIsAModelledStatus() {
        assertEquals(AnalysisStatus.Uploaded, AnalysisStatus.fromApiValue("Uploaded"));
    }

    @Test
    public void modelledStatusesResolveToThemselves() {
        for (AnalysisStatus status : AnalysisStatus.values()) {
            assertEquals(status, AnalysisStatus.fromApiValue(status.name()));
        }
    }

    @Test
    public void unrecognisedValuesResolveToUnknown() {
        assertEquals(AnalysisStatus.Unknown, AnalysisStatus.fromApiValue("Ludicrous"));
        assertEquals(AnalysisStatus.Unknown, AnalysisStatus.fromApiValue(""));
        assertEquals(AnalysisStatus.Unknown, AnalysisStatus.fromApiValue(null));
    }

    /**
     * The SDK enum for the status endpoint is the contract the plugin has to survive, including the
     * {@code All} filter sentinel and the generator's unknown placeholder.
     */
    @Test
    public void everyStatusTheSdkDeclaresResolves() {
        for (StatusInput sdkStatus : StatusInput.values()) {
            AnalysisStatus resolved = AnalysisStatus.fromApiValue(sdkStatus.getValue());
            assertNotNull("No status resolved for SDK value " + sdkStatus.getValue(), resolved);
        }
    }

    /**
     * {@code RecentAnalysesTableModel} filters completed analyses by comparing this name against the
     * raw status string from the API, so the constant name has to stay the wire value.
     */
    @Test
    public void constantNamesAreTheWireValues() {
        assertEquals(StatusInput.COMPLETE.getValue(), AnalysisStatus.Complete.name());
        assertEquals(StatusInput.UPLOADED.getValue(), AnalysisStatus.Uploaded.name());
        assertEquals(StatusInput.QUEUED.getValue(), AnalysisStatus.Queued.name());
        assertEquals(StatusInput.PROCESSING.getValue(), AnalysisStatus.Processing.name());
        assertEquals(StatusInput.ERROR.getValue(), AnalysisStatus.Error.name());
    }
}

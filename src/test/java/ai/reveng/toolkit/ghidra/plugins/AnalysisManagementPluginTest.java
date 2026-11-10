package ai.reveng.toolkit.ghidra.plugins;

import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AnalysisManagementPluginTest {

    @Test
    public void checkStatusMessageShowsOnlyStatus() {
        assertEquals("Analysis status: Complete", AnalysisManagementPlugin.checkStatusMessage(AnalysisStatus.Complete));
    }
}

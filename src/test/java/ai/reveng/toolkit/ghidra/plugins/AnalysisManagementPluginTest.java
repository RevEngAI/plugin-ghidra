package ai.reveng.toolkit.ghidra.plugins;

import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AnalysisManagementPluginTest {

    @Test
    public void checkStatusMessageShowsOnlyStatus() {
        assertEquals("Analysis status: Complete", AnalysisManagementPlugin.checkStatusMessage(AnalysisStatus.Complete));
    }

    @Test
    public void logTailKeepsLastNonBlankLines() {
        assertEquals("", AnalysisManagementPlugin.logTail(null, 3, 50));
        assertEquals("", AnalysisManagementPlugin.logTail(" \n ", 3, 50));
        assertEquals("b\nc\nd", AnalysisManagementPlugin.logTail("a\nb\n\nc  \nd\n\n", 3, 50));
        assertEquals("a\nb", AnalysisManagementPlugin.logTail("a\r\nb", 3, 50));
    }

    @Test
    public void logTailCutsLongLines() {
        assertEquals("abcde...\nxy", AnalysisManagementPlugin.logTail("abcdefgh\nxy", 3, 5));
    }

    @Test
    public void analysisErrorMessageShowsLogTailAndChoices() {
        var message = AnalysisManagementPlugin.analysisErrorMessage(42, "prog.exe", "step 1\nFATAL");
        assertTrue(message, message.startsWith("The RevEng.AI analysis 42 of prog.exe failed on the server."));
        assertTrue(message, message.contains("End of the analysis log:\nstep 1\nFATAL"));
        assertTrue(message, message.contains("Detach"));

        var noLog = AnalysisManagementPlugin.analysisErrorMessage(42, "prog.exe", "");
        assertTrue(noLog, noLog.contains("No analysis log is available."));
    }
}

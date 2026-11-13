package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.StatusPoller;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.BinaryHash;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ghidra.program.model.data.Undefined;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class GhidraRevengServiceTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void testKnownProgramLookupIsNetworkFree() throws Exception {
        var tool = env.getTool();
        var mock = new OfflineAfterSetupAPI();
        var service = addMockedService(tool, mock);

        var builder = newX64Program();
        builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        var program = programWithID.program();

        mock.offline = true;
        var freshService = new GhidraRevengService(mock);
        int statusCallsBefore = mock.statusCalls;

        assertTrue("known program must resolve from local state without the network",
                freshService.getKnownProgram(program).isPresent());
        assertTrue("analysed program must resolve from local state without the network",
                freshService.getAnalysedProgram(program).isPresent());
        assertEquals("navigation/enablement lookups must not call status()",
                statusCallsBefore, mock.statusCalls);
    }

    /// An unreadable binary must fail with the path and reason, not the SDK's raw HTTP 0 dump.
    @Test
    public void testUploadOfUnreadableFileExplainsWhy() throws Exception {
        Path bin = Files.createTempFile("unreadable", ".bin");
        bin.toFile().deleteOnExit();
        Files.setPosixFilePermissions(bin, Set.of());
        var program = newX64Program().getProgram();
        int tx = program.startTransaction("set path");
        program.setExecutablePath(bin.toString());
        program.endTransaction(tx, true);
        var service = new GhidraRevengService(new UnimplementedAPI() {
            @Override
            public BinaryHash upload(Path binPath) {
                throw new RuntimeException(new ApiException("Message: java.io.FileNotFoundException: " + binPath));
            }
        });

        var e = assertThrows(RuntimeException.class, () -> service.upload(program));

        assertTrue(e.getMessage(), e.getMessage().startsWith("Cannot read " + bin));
    }

    @Test
    public void testStatusPollingGivesUpAfterTenFailures() throws Exception {
        var statusCalls = new int[1];
        var service = new GhidraRevengService(new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) throws ApiException {
                if (++statusCalls[0] > 20) {
                    return AnalysisStatus.Complete;
                }
                throw new ApiException(503, "Service Unavailable");
            }
        });
        setInstanceField("pollIntervalMs", service, 1L);
        setInstanceField("maxPollBackoffMs", service, 1L);
        var programWithID = new GhidraRevengService.ProgramWithID(newX64Program().getProgram(), new AnalysisID(1));

        assertThrows(RuntimeException.class,
                () -> service.waitForFinishedAnalysis(TaskMonitor.DUMMY, programWithID, null, null));
        assertEquals(10, statusCalls[0]);
    }

    @Test
    public void testStatusPollingEndsOnUnrecognisedStatus() throws Exception {
        var statusCalls = new int[1];
        var service = new GhidraRevengService(new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                statusCalls[0]++;
                return AnalysisStatus.Unknown;
            }
        });
        setInstanceField("pollIntervalMs", service, 1L);
        var programWithID = new GhidraRevengService.ProgramWithID(newX64Program().getProgram(), new AnalysisID(1));

        var result = service.waitForAnalysis(TaskMonitor.DUMMY, programWithID, null, null);
        assertEquals(StatusPoller.Ending.UNRECOGNISED, result.ending());
        assertEquals(AnalysisStatus.Unknown, result.status());
        assertEquals(1, statusCalls[0]);
    }

    @Test
    public void testStatusPollingStopsAtTheTimeLimit() throws Exception {
        var logCalls = new int[1];
        var service = new GhidraRevengService(new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return AnalysisStatus.Processing;
            }

            @Override
            public String getAnalysisLogs(AnalysisID analysisID) {
                logCalls[0]++;
                return "still going";
            }
        });
        setInstanceField("pollIntervalMs", service, 5L);
        setInstanceField("maxPollIntervalMs", service, 20L);
        setInstanceField("maxAnalysisWaitMs", service, 200L);
        var programWithID = new GhidraRevengService.ProgramWithID(newX64Program().getProgram(), new AnalysisID(1));

        var result = service.waitForAnalysis(TaskMonitor.DUMMY, programWithID, null, null);
        assertEquals(StatusPoller.Ending.TIMED_OUT, result.ending());
        assertEquals(AnalysisStatus.Processing, result.status());
        // Backing off to 20ms, 200ms holds well under the 40 polls a fixed 5ms interval would make
        assertTrue("polled " + logCalls[0] + " times", logCalls[0] < 25);
    }

    @Test
    public void testStatusPollingWaitsThroughUploaded() throws Exception {
        var statusCalls = new int[1];
        var service = new GhidraRevengService(new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return ++statusCalls[0] < 3 ? AnalysisStatus.Uploaded : AnalysisStatus.Complete;
            }
        });
        setInstanceField("pollIntervalMs", service, 1L);
        var programWithID = new GhidraRevengService.ProgramWithID(newX64Program().getProgram(), new AnalysisID(1));

        assertEquals(AnalysisStatus.Complete,
                service.waitForFinishedAnalysis(TaskMonitor.DUMMY, programWithID, null, null));
        assertEquals(3, statusCalls[0]);
    }

    static class OfflineAfterSetupAPI extends UnimplementedAPI {
        volatile boolean offline = false;
        int statusCalls = 0;

        @Override
        public AnalysisID analyse(AnalysisOptionsBuilder options) throws ApiException {
            return new AnalysisID(1);
        }

        @Override
        public AnalysisStatus status(AnalysisID analysisID) throws ApiException {
            statusCalls++;
            if (offline) {
                throw new ApiException("simulated offline");
            }
            return AnalysisStatus.Complete;
        }

        @Override
        public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
            return List.of(new FunctionInfo(new FunctionID(1), "f1", "f1_mangled", 0x1000L, 10));
        }
    }
}

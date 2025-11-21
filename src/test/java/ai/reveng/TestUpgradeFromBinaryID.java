package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryID;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.program.database.ProgramBuilder;
import org.junit.Assert;
import org.junit.Test;

import java.util.Optional;

public class TestUpgradeFromBinaryID extends RevEngMockableHeadedIntegrationTest {

    /// Tests the logic for handling a program that has only a binary ID stored in its properties
    @Test
    public void test() throws Exception {
        var builder = new ProgramBuilder("upgrade-test", ProgramBuilder._8051, this);
        var tId = builder.getProgram().startTransaction("Set Binary ID");
        builder.getProgram()
                .getOptions(ReaiPluginPackage.REAI_OPTIONS_CATEGORY)
                .setLong(ReaiPluginPackage.OPTION_KEY_BINID, 1);
        builder.getProgram().endTransaction(tId, true);
        addMockedService(env.getTool(), new UnimplementedAPI() {
            @Override
            public AnalysisID getAnalysisIDfromBinaryID(BinaryID binaryID) {
                if (binaryID.value() == 1) {
                    return new AnalysisID(42);
                }
                return null;
            }

            @Override
            public AnalysisStatus status(BinaryID binID) throws ApiException {
                if (binID.value() == 1) {
                    return AnalysisStatus.Complete;
                }
                return AnalysisStatus.Error;
            }
        });
        var program = builder.getProgram();

        env.open(program);

        var service = env.getTool().getService(GhidraRevengService.class);
        Optional<GhidraRevengService.ProgramWithID> analysisID = service.getKnownProgram(program);
        Assert.assertTrue(analysisID.isPresent());
        Assert.assertEquals(42, analysisID.get().analysisID().id());
        // Verify that after opening, the program has the Analysis ID set and the Binary ID removed
        Assert.assertEquals(-1, program.getOptions(ReaiPluginPackage.REAI_OPTIONS_CATEGORY).getLong(ReaiPluginPackage.OPTION_KEY_BINID, -1));
        Assert.assertEquals(42, program.getOptions(ReaiPluginPackage.REAI_OPTIONS_CATEGORY).getLong(ReaiPluginPackage.OPTION_KEY_ANALYSIS_ID, -1));








    }
}

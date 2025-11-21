package ai.reveng;

import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisResultsLoaded;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.*;
import ai.reveng.toolkit.ghidra.plugins.AnalysisManagementPlugin;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PortalAnalysisIntegrationTest extends RevEngMockableHeadedIntegrationTest {

    /// TODO: This test currently tests more things at once than needed and could be split
    /// * Test that the checks the event lifecycle works (status changed -> results loaded)
    /// * Test that loading the function info/details works correctly
    ///
    @Test
    public void testInfoLoading() throws Exception {

        var tool = env.getTool();
        addMockedService(tool, new UnimplementedAPI() {
            @Override
            public List<FunctionInfo> getFunctionInfo(BinaryID binaryID) {
                return List.of(
                        new FunctionInfo(new FunctionID(1), "portal_name_demangled", "portal_name_mangled", 0x4000L, 0x100)
                );
            }

            @Override
            public Optional<FunctionDataTypeStatus> getFunctionDataTypes(AnalysisID analysisID, FunctionID functionID) {
                var ds = new FunctionDataTypeStatus(
                        true,
                        Optional.of(
                                new FunctionDataTypeMessage(
                                        new FunctionArtifact(
                                                0x4000L,
                                                0x100,
                                                new FunctionHeader(
                                                        null,
                                                        "portal_name_demangled",
                                                        0x4000L,
                                                        "int",
                                                        new FunctionArgument[]{
                                                                new FunctionArgument(0, 8,
                                                                        null,
                                                                        "named_param_1",
                                                                        "char *"
                                                                ),
                                                        }

                                                ),
                                                new StackVariable[]{}
                                        ),
                                        new FunctionDependencies(
                                                new Typedef[]{},
                                                new Struct[]{}
                                        )
                                )
                        ),
                        "completed",
                        null,
                        functionID
                );
                return Optional.of(ds);
            }

            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return AnalysisStatus.Complete;
            }

            @Override
            public FunctionDetails getFunctionDetails(FunctionID id) {
                return new FunctionDetails(
                        id,
                        "portal_name_mangled",
                        0x4000L,
                        0x100L,
                        new AnalysisID(1),
                        new BinaryID(1),
                        "binary_name",
                        new BinaryHash("dummyhash")
                );
            }
        });
        var builder = new ProgramBuilder("mock", ProgramBuilder._8051, this);
        // Add an example function
        var exampleFunc = builder.createEmptyFunction(null, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        /// Tell Ghidra that the function signature source is just default,
        /// as the logic in {@link GhidraRevengService#pullFunctionInfoFromAnalysis(GhidraRevengService.AnalysedProgram, TaskMonitor)}
        /// relies on this to decide whether to update the function signature or not
        var tId = builder.getProgram().startTransaction("Set function signature source");
        exampleFunc.setSignatureSource(SourceType.DEFAULT);
        builder.getProgram().endTransaction(tId, true);
        // We need to also create the memory where the function lives, `getFunctions` doesn't find it otherwise
        builder.createMemory("test", "0x4000", 0x100);
        Assert.assertNotNull(builder.getProgram().getFunctionManager().getFunctionAt(exampleFunc.getEntryPoint()));
        assert builder.getProgram().getFunctionManager().getFunctionCount() == 1;
        assert builder.getProgram().getFunctionManager().getFunctionAt(exampleFunc.getEntryPoint()) != null;
        assert builder.getProgram().getFunctionManager().getFunctions(true).hasNext();
        var program = builder.getProgram();

        var defaultTool = env.showTool(program);

        env.addPlugin(AnalysisManagementPlugin.class);

        waitForSwing();

        var id = new GhidraRevengService.ProgramWithBinaryID(program, new BinaryID(1), new AnalysisID(1));
        var service = defaultTool.getService(GhidraRevengService.class);
        service.addBinaryIDtoProgramOptions(program, id.binaryID());

        // Register a listener for the results loaded event, to verify that has been fired later
        AtomicBoolean receivedResultsLoadedEvent = new AtomicBoolean(false);
        defaultTool.addEventListener(RevEngAIAnalysisResultsLoaded.class, e -> {
            receivedResultsLoadedEvent.set(true);
        });

        // Simulate the analysis status change event
        // We have to run this without waiting, otherwise the test case doesn't continue until the dialog is closed
        runSwing(
                () -> defaultTool.firePluginEvent(
                        new RevEngAIAnalysisStatusChangedEvent(
                                "test",
                                id,
                                AnalysisStatus.Complete
                        )
                ), false
        );

        waitForSwing();
        // Check that we received the results loaded event, i.e. other plugins would have been notified
        assertTrue(receivedResultsLoadedEvent.get());
        // Check that the function names have been updated to the one returned by the portal
        assertEquals("portal_name_demangled", exampleFunc.getName());

        assertEquals(SourceType.ANALYSIS, exampleFunc.getSignatureSource());
        var signature = exampleFunc.getSignature(true);
        assertEquals("int portal_name_demangled(char * named_param_1)", signature.getPrototypeString());


        // Check the function ID has been stored in the program options
        var funcIDMap = service.getFunctionMap(program);

        var storedFunc = funcIDMap.get(new FunctionID(1));

        Assert.assertNotNull(storedFunc);
        assertEquals("portal_name_demangled", storedFunc.getName());

        // Check the function mangled name has been stored
        var mangledNamesMap = service.getFunctionMangledNamesMap(program);

        assertTrue(mangledNamesMap.isPresent());
        assertEquals("portal_name_mangled", mangledNamesMap.get().getString(exampleFunc.getEntryPoint()));

        // TODO: What else should happen when the analysis is finished?
    }
}

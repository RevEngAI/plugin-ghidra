package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.BatchFunctionSignatureEntry;
import ai.reveng.model.SignatureParameterEntry;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisResultsLoaded;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.FunctionSignatureBatch;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataTypeReader;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import com.google.gson.JsonParser;
import ai.reveng.toolkit.ghidra.plugins.AnalysisManagementPlugin;
import ghidra.framework.Application;
import ghidra.framework.ApplicationVersion;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;
import java.util.Map;
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
            public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
                return List.of(
                        new FunctionInfo(new FunctionID(1), "portal_name_demangled", "portal_name_mangled", 0x4000L, 0x100)
                );
            }

            @Override
            public FunctionSignatureBatch listFunctionSignatures(List<FunctionID> functionIDs,
                                                                 boolean includeDataTypes) {
                // int portal_name_demangled(EVP_PKEY_CTX *ctx), where EVP_PKEY_CTX is a typedef in
                // the "ossl_typ.h" namespace for an (empty) struct. Every reference between the
                // types is by data_type_id, which is what the decoder resolves.
                var dataTypes = ServerDataTypeReader.readEntries(JsonParser.parseString(
                        """
                        {
                          "items": [
                            {
                              "data_type_id": 10,
                              "namespace": "",
                              "name": "int",
                              "kind": "BASE",
                              "size": 4,
                              "source_type": "AUTO",
                              "has_definition": false
                            },
                            {
                              "data_type_id": 11,
                              "namespace": "ossl_typ.h",
                              "name": "evp_pkey_ctx_st",
                              "kind": "STRUCT",
                              "size": 0,
                              "source_type": "AUTO",
                              "has_definition": true,
                              "definition": { "members": [] }
                            },
                            {
                              "data_type_id": 12,
                              "namespace": "ossl_typ.h",
                              "name": "EVP_PKEY_CTX",
                              "kind": "TYPEDEF",
                              "size": 0,
                              "source_type": "AUTO",
                              "has_definition": true,
                              "definition": { "target_data_type_id": 11 }
                            },
                            {
                              "data_type_id": 13,
                              "namespace": "",
                              "name": "EVP_PKEY_CTX *",
                              "kind": "POINTER",
                              "size": 8,
                              "source_type": "AUTO",
                              "has_definition": true,
                              "definition": { "pointee_data_type_id": 12 }
                            }
                          ]
                        }
                        """), "items");

                var parameter = new SignatureParameterEntry();
                parameter.setName("ctx");
                parameter.setOrdinal(0L);
                parameter.setDataTypeId(13L);
                parameter.setBitLength(64L);

                var entry = new BatchFunctionSignatureEntry();
                entry.setAnalysisId(1L);
                entry.setFunctionId(1L);
                entry.setFunctionName("portal_name_demangled");
                entry.setHasSignature(true);
                entry.setReturnDataTypeId(10L);
                entry.setParameters(List.of(parameter));

                return new FunctionSignatureBatch(List.of(entry), Map.of(new AnalysisID(1), dataTypes));
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
                        "binary_name",
                        new BinaryHash("dummyhash"),
                        "portal_name_demangled"
                );
            }

            @Override
            public AnalysisID analyse(AnalysisOptionsBuilder options) throws ApiException {
                return new AnalysisID(1);
            }
        });
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
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

        var service = defaultTool.getService(GhidraRevengService.class);
        // We start an analysis to get an Analysis ID associated with the program
        var id  = service.startAnalysis(program, null);

        assert service.getKnownProgram(program).isPresent();
        assert service.getAnalysedProgram(program).isEmpty();

        // Register a listener for the results loaded event, to verify that has been fired later
        AtomicBoolean receivedResultsLoadedEvent = new AtomicBoolean(false);
        defaultTool.addEventListener(RevEngAIAnalysisResultsLoaded.class, e -> {
            receivedResultsLoadedEvent.set(true);
        });

        // Simulate the analysis status change event being triggered when the analysis is complete
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

        // Check that an analysed program is now known
        assert service.getAnalysedProgram(program).isPresent();
        var analyzedProgram = service.getAnalysedProgram(program).get();

        // Check that the function names have been updated to the one returned by the portal
        assertEquals("portal_name_demangled", exampleFunc.getName());

        var signature = exampleFunc.getSignature(true);
        assertEquals("int portal_name_demangled(EVP_PKEY_CTX * ctx)", signature.getPrototypeString());
        // For unclear reasons the signature source is not set by the command in Ghidra 11.2.x
        // So we only test this for Ghidra 11.3 and above
        ApplicationVersion version = new ApplicationVersion(Application.getApplicationVersion());
        if (version.compareTo(new ApplicationVersion("11.3")) > 0) {
            assertEquals(SourceType.ANALYSIS, exampleFunc.getSignatureSource());
        }



        // Check the function ID has been stored in the program options
        var funcIDMap = analyzedProgram.getFunctionMap();
        var storedFunc = funcIDMap.get(new TypedApiInterface.FunctionID(1));

        Assert.assertNotNull(storedFunc);
        assertEquals("portal_name_demangled", storedFunc.getName());

        // Check the function mangled name has been stored
//        assertEquals("portal_name_mangled", mangledNamesMap.get().getString(exampleFunc.getEntryPoint()));
        assertEquals("portal_name_mangled", analyzedProgram.getMangledNameForFunction(exampleFunc));
        // TODO: What else should happen when the analysis is finished?
    }
}

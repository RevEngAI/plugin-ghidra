package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.util.Iterator;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class UnstripTest extends RevEngMockableHeadedIntegrationTest{


    @Test
    public void testFinishedUnstrip() throws Exception {

        var tool = env.getTool();
        var service = addMockedService(tool, new UnimplementedAPI() {


            @Override
            public AutoUnstripResponse autoUnstrip(AnalysisID analysisID) {
                return new AutoUnstripResponse(
                        100,
                        "STATUS",
                        0,
                        List.of(new AutoUnstripResponse.Match(new FunctionID(1), 0x1000, "unstripped_function_name", "unstripped_function_name_demangled" ) ),
                        false,
                        null
                );
            }

            @Override
            public AnalysisID analyse(AnalysisOptionsBuilder options) throws ApiException {
                return new AnalysisID(1);
            }

            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return AnalysisStatus.Complete;
            }

            @Override
            public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
                return List.of(new FunctionInfo(new FunctionID(1), "default_function_info_name",  "default_function_info_name_mangled",0x1000L, 10));
            }
        });

        addPlugin(tool, BinarySimilarityPlugin.class);
        var builder = new ProgramBuilder("mock", ProgramBuilder._8051, this);
        var func = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));

        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);

        env.showTool(programWithID.program());
        // Get the auto unstrip action and execute it
        var action = getAction(tool, "Auto Unstrip");
        performAction(action, false);

        // Wait for the dialog to appear and interact with it
        var dialog = waitForDialogComponent("RevEng.AI: Auto Unstrip");
        waitForSwing();
        capture(dialog.getComponent(), "auto_unstrip");
        assertEquals("unstripped_function_name_demangled", func.getName());
        assertEquals("RevEng.AI", func.getParentNamespace().getName(true));

    }

    @Test
    public void testProgressingUnstrip() throws Exception {
        var tool = env.getTool();
        Iterator<AutoUnstripResponse> responses = List.of(
                new AutoUnstripResponse(
                        0,
                        "QUEUED",
                        0,
                        List.of(),
                        false,
                        null
                ),
// The poll interval is not configurable, so we can only test two responses before hitting a Ghidra test timeout
//                new AutoUnstripResponse(
//                        50,
//                        "PROCESSING",
//                        0,
//                        List.of(new AutoUnstripResponse.Match(new FunctionID(1), 0x1000, "unstripped_function_name") ),
//                        false,
//                        null
//                ),
                new AutoUnstripResponse(
                        100,
                        "COMPLETED",
                        0,
                        List.of(new AutoUnstripResponse.Match(new FunctionID(1), 0x1000, "unstripped_function_name", "unstripped_function_name_demangled") ),
                        false,
                        null
                )
        ).iterator();

        var service = addMockedService(tool, new UnimplementedAPI() {


            @Override
            public AutoUnstripResponse autoUnstrip(AnalysisID analysisID) {
                return responses.next();
            }

            @Override
            public AnalysisID analyse(AnalysisOptionsBuilder options) throws ApiException {
                return new AnalysisID(1);
            }

            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return AnalysisStatus.Complete;
            }

            @Override
            public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
                // the function info will return a name, but it will _not_ be the unstripped name
                return List.of(new FunctionInfo(new FunctionID(1), "default_function_info_name", "default_function_info_name_mangled",0x1000L, 10));
            }
        });

        addPlugin(tool, BinarySimilarityPlugin.class);
        var builder = new ProgramBuilder("mock", ProgramBuilder._8051, this);
        // We provide no function name, so ghidra will assign the default "FUN_1000" name
        var func = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));

        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);

        env.showTool(programWithID.program());
        // Get the auto unstrip action and execute it
        var action = getAction(tool, "Auto Unstrip");
        performAction(action, false);

        // Wait for the dialog to appear and interact with it
        var dialog = waitForDialogComponent("RevEng.AI: Auto Unstrip");
        waitForSwing();

        waitForCondition(() -> !responses.hasNext());
        waitForSwing();
        // Specifically test that the function has been renamed to the unstripped name
        assertEquals("unstripped_function_name_demangled", func.getName());
        // And also that it is part of the RevEng.AI namespace
        assertEquals("RevEng.AI", func.getParentNamespace().getName(true));

    }

}

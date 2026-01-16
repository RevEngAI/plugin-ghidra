package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler.AIDecompilationdWindow;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin;
import docking.widgets.dialogs.InputDialog;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class AIDecompilerComponentTest extends RevEngMockableHeadedIntegrationTest{

    @Test
    public void testAIDecompilerBasics() throws Exception {

        // Set up the initial program and service
        var tool = env.getTool();



        var service = addMockedService(tool, new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return AnalysisStatus.Complete;
            }

            @Override
            public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
                return List.of(
                        new FunctionInfo(
                                new FunctionID(1),
                                "portal_func_1",
                                "portal_func_1_mangled",
                                0x1000L,
                                10),
                        new FunctionInfo(
                                new FunctionID(2),
                                "portal_func_2",
                                "portal_func_2_mangled",
                                0x2000L,
                                10)
                );
            }

            @Override
            public AIDecompilationStatus pollAIDecompileStatus(FunctionID functionID) {

                if (functionID.value() == 2) {
                    return new AIDecompilationStatus(
                            "success",
                            "int func2(int a) { return a + 1; }",
                            "int func2(int a) { return a + 1; }",
                            "Mocked Description Summary for func2",
                            "Summary for func2",
                            null,
                            null
                    );
                } else if (functionID.value() == 1) {

                    return new AIDecompilationStatus(
                            "success",
                            "void func1() { return; }",
                            "void func1() { return; }",
                            "Mocked Description Summary",
                            "Summary",
                            null,
                            null
                    );
                } else {
                    throw new RuntimeException("Unknown FunctionID");
                }

            }

            @Override
            public AnalysisID analyse(AnalysisOptionsBuilder options) throws ApiException {
                return new AnalysisID(1);
            }

            @Override
            public boolean triggerAIDecompilationForFunctionID(FunctionID functionID) {
                return true;
//                return super.triggerAIDecompilationForFunctionID(functionID);
            }
        });

        var binarySimilarityPlugin = env.addPlugin(BinarySimilarityPlugin.class);

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var func1 = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var func2 = builder.createEmptyFunction(null, "0x2000", 10, Undefined.getUndefinedDataType(4));

        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);

        env.showTool(programWithID.program());

        // get AIDecompiledWindow, and some internal fields for testing
        var aiDecompComponent = getComponentProvider(AIDecompilationdWindow.class);
        Map<Function, AIDecompilationStatus> aiDecompCache = (Map<Function, AIDecompilationStatus>) getInstanceField("cache", aiDecompComponent);
        RSyntaxTextArea textArea = (RSyntaxTextArea) getInstanceField("textArea", aiDecompComponent);

        // Make sure it's hidden to start with
        aiDecompComponent.setVisible(false);

        // Navigate to function 1, while the window is not visible
        goTo(tool, programWithID.program(), func1.getEntryPoint());
        waitForTasks();
        assertFalse(aiDecompCache.containsKey(func1));
        waitForSwing();

        // Get the UI Action and perform it to show the window
        // We need to create a context, because the action is context-sensitive
        var action = getAction(tool, "AI Decompilation");
        var context = new ProgramLocationActionContext(
                null,
                programWithID.program(),
                new ProgramLocation(
                        programWithID.program(),
                        func1.getEntryPoint()
                ),
                null, null);
        performAction(action, context,true);
        waitForTasks();
        // Check that the decompiled code is displayed in the visible window
        assertTrue(aiDecompComponent.isVisible());
        assertEquals("void func1() { return; }", textArea.getText());

        // Now navigate to function 2, while the window is visible
        goTo(tool, programWithID.program(), func2.getEntryPoint());
        // This should have automatically triggered a task to decompile function 2, test that it is tracked
        assertTrue(aiDecompCache.containsKey(func2));
        // Wait for it to finish
        waitForTasks();
        // check that result is displayed
        assertEquals("int func2(int a) { return a + 1; }", textArea.getText());
    }

    @Test
    public void testAIDecompFeedbackMechanism() throws Exception {
// Set up the initial program and service
        var tool = env.getTool();

        var ratingsAPI = new RatingsAPI();
        var service = addMockedService(tool, ratingsAPI);

        var binarySimilarityPlugin = env.addPlugin(BinarySimilarityPlugin.class);
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var func1 = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var func2 = builder.createEmptyFunction(null, "0x2000", 10, Undefined.getUndefinedDataType(4));

        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
//        service.getAnalysedProgram(programWithID);
        env.showTool(programWithID.program());
        waitForSwing();

        // get AIDecompiledWindow, and some internal fields for testing
        var aiDecompComponent = getComponentProvider(AIDecompilationdWindow.class);
        // Get the reason field

        aiDecompComponent.setVisible(true);
        setInstanceField("function", aiDecompComponent, func1);
        var positiveFeedbackAction = getLocalAction(aiDecompComponent, "Positive Feedback Action");
        performAction(positiveFeedbackAction);
        waitForTasks();
        assertEquals("POSITIVE", ratingsAPI.lastFeedback);

        // Send negative feedback with reason
        var negativeFeedbackAction = getLocalAction(aiDecompComponent, "Negative Feedback Action");
        performAction(negativeFeedbackAction, false);
        var dialog = waitForDialogComponent(InputDialog.class);
        var reason = "The decompilation was incorrect";
        dialog.setValue(reason);
        dialog.close();
        waitForSwing();
        assertEquals("NEGATIVE", ratingsAPI.lastFeedback);
        assertEquals(reason, ratingsAPI.lastReason);

    }

    static class RatingsAPI extends UnimplementedAPI {
        String lastFeedback;
        String lastReason;

        public RatingsAPI() {
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
            return List.of(
                    new FunctionInfo(
                            new FunctionID(1),
                            "portal_func_1",
                            "portal_func_1_mangled",
                            0x1000L,
                            10),
                    new FunctionInfo(
                            new FunctionID(2),
                            "portal_func_2",
                            "portal_func_2_mangled",
                            0x2000L,
                            10)
            );
        }

        @Override
        public AIDecompilationStatus pollAIDecompileStatus(FunctionID functionID) {
                return new AIDecompilationStatus(
                        "success",
                        "void func1() { return; }",
                        "void func1() { return; }",
                        "Mocked Description Summary",
                        "Summary",
                        null,
                        null
                );
        }

        @Override
        public boolean triggerAIDecompilationForFunctionID(FunctionID functionID) {
            return true;
        }

        @Override
        public void aiDecompRating(FunctionID functionID, String rating, String reason) {
            lastFeedback = rating;
            lastReason = reason;
        }
    }
}

package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.DecompilationData;
import ai.reveng.model.WorkflowProgress;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler.AIDecompilationdWindow;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.types.AIDecompilationStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
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
                            DecompilationData.StatusEnum.COMPLETED,
                            "int func2(int a) { return a + 1; }",
                            "Mocked Description Summary for func2",
                            null,
                            WorkflowProgress.StatusEnum.COMPLETED,
                            WorkflowProgress.StatusEnum.COMPLETED,
                            java.util.List.of(),
                            null);
                } else if (functionID.value() == 1) {
                    return new AIDecompilationStatus(
                            DecompilationData.StatusEnum.COMPLETED,
                            "void func1() { return; }",
                            "Mocked Description Summary",
                            null,
                            WorkflowProgress.StatusEnum.COMPLETED,
                            WorkflowProgress.StatusEnum.COMPLETED,
                            java.util.List.of(),
                            null);
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
        waitForTasks();
        assertEquals("NEGATIVE", ratingsAPI.lastFeedback);
        assertEquals(reason, ratingsAPI.lastReason);

    }

    @Test
    public void testFeedbackDoesNotBlockSwingThread() throws Exception {
        var tool = env.getTool();

        var ratingsAPI = new BlockingRatingsAPI();
        var service = addMockedService(tool, ratingsAPI);

        env.addPlugin(BinarySimilarityPlugin.class);
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var func1 = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        builder.createEmptyFunction(null, "0x2000", 10, Undefined.getUndefinedDataType(4));

        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(programWithID.program());
        waitForSwing();

        var aiDecompComponent = getComponentProvider(AIDecompilationdWindow.class);
        aiDecompComponent.setVisible(true);
        setInstanceField("function", aiDecompComponent, func1);

        var positiveFeedbackAction = getLocalAction(aiDecompComponent, "Positive Feedback Action");
        performAction(positiveFeedbackAction);

        assertTrue("Feedback send should run off the Swing thread",
                ratingsAPI.ratingStarted.await(5, java.util.concurrent.TimeUnit.SECONDS));
        assertNull("Rating must not be recorded while the network call is blocked", ratingsAPI.lastFeedback);

        ratingsAPI.blockRating.countDown();
        waitForTasks();
        assertEquals("POSITIVE", ratingsAPI.lastFeedback);
    }

    @Test
    public void testDecompilationFailureIsShownInWindow() throws Exception {
        var tool = env.getTool();

        var service = addMockedService(tool, new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return AnalysisStatus.Complete;
            }

            @Override
            public AnalysisID analyse(AnalysisOptionsBuilder options) throws ApiException {
                return new AnalysisID(1);
            }

            @Override
            public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
                return List.of(new FunctionInfo(new FunctionID(1), "portal_func_1", "portal_func_1_mangled", 0x1000L, 10));
            }

            @Override
            public AIDecompilationStatus pollAIDecompileStatus(FunctionID functionID) {
                throw new RuntimeException("decompilation backend unavailable");
            }
        });

        env.addPlugin(BinarySimilarityPlugin.class);
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var func1 = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(programWithID.program());

        var aiDecompComponent = getComponentProvider(AIDecompilationdWindow.class);
        aiDecompComponent.setVisible(true);

        var action = getAction(tool, "AI Decompilation");
        var context = new ProgramLocationActionContext(
                null,
                programWithID.program(),
                new ProgramLocation(programWithID.program(), func1.getEntryPoint()),
                null, null);
        performAction(action, context, true);
        waitForTasks();
        waitForSwing();

        javax.swing.JEditorPane descriptionArea =
                (javax.swing.JEditorPane) getInstanceField("descriptionArea", aiDecompComponent);
        assertTrue("decompilation failure should be surfaced in the window, was: " + descriptionArea.getText(),
                descriptionArea.getText().contains("AI Decompilation failed"));
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
                    DecompilationData.StatusEnum.COMPLETED,
                    "void func1() { return; }",
                    "Mocked Description Summary",
                    null,
                    WorkflowProgress.StatusEnum.COMPLETED,
                    WorkflowProgress.StatusEnum.COMPLETED,
                    java.util.List.of(),
                    null);
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

    static class BlockingRatingsAPI extends RatingsAPI {
        final java.util.concurrent.CountDownLatch ratingStarted = new java.util.concurrent.CountDownLatch(1);
        final java.util.concurrent.CountDownLatch blockRating = new java.util.concurrent.CountDownLatch(1);

        @Override
        public void aiDecompRating(FunctionID functionID, String rating, String reason) {
            ratingStarted.countDown();
            try {
                blockRating.await(10, java.util.concurrent.TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            super.aiDecompRating(functionID, rating, reason);
        }
    }
}

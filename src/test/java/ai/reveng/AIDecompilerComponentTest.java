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
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

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

        var builder = newX64Program();
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
        var builder = newX64Program();
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
        var builder = newX64Program();
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
        var builder = newX64Program();
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

    @Test
    public void testInlineCommentsRenderedInCodeBox() throws Exception {
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
                return new AIDecompilationStatus(
                        DecompilationData.StatusEnum.COMPLETED,
                        "int main() {\n    return 0;\n}",
                        "Mocked Description Summary",
                        null,
                        WorkflowProgress.StatusEnum.COMPLETED,
                        WorkflowProgress.StatusEnum.COMPLETED,
                        List.of(new AIDecompilationStatus.InlineCommentEntry(2, "the exit code")),
                        null);
            }

            @Override
            public boolean triggerAIDecompilationForFunctionID(FunctionID functionID) {
                return true;
            }
        });

        env.addPlugin(BinarySimilarityPlugin.class);
        var builder = newX64Program();
        var func1 = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(programWithID.program());

        var aiDecompComponent = getComponentProvider(AIDecompilationdWindow.class);
        aiDecompComponent.setVisible(true);
        RSyntaxTextArea textArea = (RSyntaxTextArea) getInstanceField("textArea", aiDecompComponent);

        var action = getAction(tool, "AI Decompilation");
        var context = new ProgramLocationActionContext(
                null,
                programWithID.program(),
                new ProgramLocation(programWithID.program(), func1.getEntryPoint()),
                null, null);
        performAction(action, context, true);
        waitForTasks();
        waitForSwing();

        String text = textArea.getText();
        assertTrue("inline comment should be spliced into the code box, was:\n" + text,
                text.contains("// the exit code"));
        assertTrue("comment must be rendered above the line it annotates",
                text.indexOf("// the exit code") < text.indexOf("return 0;"));
        assertTrue("comment must preserve the annotated line's indentation",
                text.contains("    // the exit code"));
    }

    @Test
    public void testSummaryTriggerRetriedAfterConflict() throws Exception {
        var tool = env.getTool();
        var summaryTriggers = new AtomicInteger();
        var polls = new AtomicInteger();

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
                WorkflowProgress.StatusEnum summaryStatus;
                if (summaryTriggers.get() > 1) {
                    summaryStatus = WorkflowProgress.StatusEnum.COMPLETED;
                } else if (polls.incrementAndGet() > 5) {
                    summaryStatus = WorkflowProgress.StatusEnum.FAILED;
                } else {
                    summaryStatus = WorkflowProgress.StatusEnum.UNINITIALISED;
                }
                return new AIDecompilationStatus(
                        DecompilationData.StatusEnum.COMPLETED,
                        "void func1() { return; }",
                        null,
                        null,
                        summaryStatus,
                        WorkflowProgress.StatusEnum.UNINITIALISED,
                        List.of(),
                        null);
            }

            @Override
            public boolean triggerAIDecompilationForFunctionID(FunctionID functionID) {
                return true;
            }

            @Override
            public void triggerAIDecompilationSummary(FunctionID functionID) {
                if (summaryTriggers.incrementAndGet() == 1) {
                    throw new RuntimeException("Failed to trigger AI decompilation summary",
                            new ApiException(409, "A decompilation is in progress for this function"));
                }
            }

            @Override
            public void triggerAIDecompilationInlineComments(FunctionID functionID) {
                throw new RuntimeException("stop polling");
            }
        });

        env.addPlugin(BinarySimilarityPlugin.class);
        var builder = newX64Program();
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

        assertEquals("summary trigger must be retried after a 409", 2, summaryTriggers.get());
    }

    /// A summary trigger that fails with anything but 409 ends the wait: the summary will never arrive
    @Test
    public void testSummaryTriggerFailureStopsPolling() throws Exception {
        var tool = env.getTool();
        var summaryTriggers = new AtomicInteger();
        var polls = new AtomicInteger();

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
                polls.incrementAndGet();
                return new AIDecompilationStatus(
                        DecompilationData.StatusEnum.COMPLETED,
                        "void func1() { return; }",
                        null,
                        null,
                        WorkflowProgress.StatusEnum.UNINITIALISED,
                        WorkflowProgress.StatusEnum.UNINITIALISED,
                        List.of(),
                        null);
            }

            @Override
            public void triggerAIDecompilationSummary(FunctionID functionID) {
                summaryTriggers.incrementAndGet();
                throw new RuntimeException("Failed to trigger AI decompilation summary",
                        new ApiException(402, "Insufficient credits"));
            }
        });

        env.addPlugin(BinarySimilarityPlugin.class);
        var builder = newX64Program();
        var func1 = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(programWithID.program());

        var aiDecompComponent = getComponentProvider(AIDecompilationdWindow.class);
        aiDecompComponent.setVisible(true);
        RSyntaxTextArea textArea = (RSyntaxTextArea) getInstanceField("textArea", aiDecompComponent);

        var action = getAction(tool, "AI Decompilation");
        var context = new ProgramLocationActionContext(
                null,
                programWithID.program(),
                new ProgramLocation(programWithID.program(), func1.getEntryPoint()),
                null, null);
        performAction(action, context, true);
        waitForTasks();
        waitForSwing();

        assertEquals(1, summaryTriggers.get());
        // The status check before triggering, and the one poll that saw the decompilation completed
        assertEquals(2, polls.get());
        assertEquals("void func1() { return; }", textArea.getText());
    }

    /// A FAILED decompilation can be run again with the Regenerate action; Refresh alone only re-reads the failure
    @Test
    public void testRegenerateFailedDecompilation() throws Exception {
        var tool = env.getTool();
        var triggers = new AtomicInteger();

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
                if (triggers.get() == 0) {
                    return new AIDecompilationStatus(
                            DecompilationData.StatusEnum.FAILED, "", null, null, null, null, List.of(), null);
                }
                return new AIDecompilationStatus(
                        DecompilationData.StatusEnum.COMPLETED,
                        "void func1() { return; }",
                        "Mocked Description Summary",
                        null,
                        WorkflowProgress.StatusEnum.COMPLETED,
                        WorkflowProgress.StatusEnum.COMPLETED,
                        List.of(),
                        null);
            }

            @Override
            public boolean triggerAIDecompilationForFunctionID(FunctionID functionID) {
                triggers.incrementAndGet();
                return true;
            }
        });

        env.addPlugin(BinarySimilarityPlugin.class);
        var builder = newX64Program();
        var func1 = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(programWithID.program());

        var aiDecompComponent = getComponentProvider(AIDecompilationdWindow.class);
        aiDecompComponent.setVisible(true);
        RSyntaxTextArea textArea = (RSyntaxTextArea) getInstanceField("textArea", aiDecompComponent);
        javax.swing.JEditorPane descriptionArea =
                (javax.swing.JEditorPane) getInstanceField("descriptionArea", aiDecompComponent);

        var action = getAction(tool, "AI Decompilation");
        var context = new ProgramLocationActionContext(
                null,
                programWithID.program(),
                new ProgramLocation(programWithID.program(), func1.getEntryPoint()),
                null, null);
        performAction(action, context, true);
        waitForTasks();
        waitForSwing();

        assertEquals("a FAILED decompilation must not be re-triggered on its own", 0, triggers.get());
        assertTrue(descriptionArea.getText(), descriptionArea.getText().contains("Regenerate"));

        performAction(getLocalAction(aiDecompComponent, "Refresh AI Decompilation"));
        waitForTasks();
        waitForSwing();
        assertEquals("Refresh only re-reads the result", 0, triggers.get());

        var regenerate = getLocalAction(aiDecompComponent, "Regenerate AI Decompilation");
        assertTrue(runSwing(() -> regenerate.isEnabledForContext(aiDecompComponent.getActionContext(null))));
        performAction(regenerate);
        waitForTasks();
        waitForSwing();

        assertEquals(1, triggers.get());
        assertEquals("void func1() { return; }", textArea.getText());
        assertFalse("Regenerate is only offered for a failed decompilation",
                runSwing(() -> regenerate.isEnabledForContext(aiDecompComponent.getActionContext(null))));
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

    /// The Decompiler reports a context without an address when the cursor is on a blank line.
    @Test
    public void popupActionsAreDisabledForContextWithoutAddress() throws Exception {
        var tool = env.getTool();
        addMockedService(tool, new UnimplementedAPI());
        env.addPlugin(BinarySimilarityPlugin.class);
        var program = newX64Program().getProgram();

        var context = new ProgramLocationActionContext(null, program, null, null, null);
        for (String name : List.of("Match function", "AI Decompilation", "View function in portal")) {
            assertFalse(name, getAction(tool, name).isEnabledForContext(context));
        }
    }

    /// Moving in the listing lights the decompilation lines an instruction fed; clicking a
    /// decompilation line lights its instructions in the listing.
    @Test
    public void lineAttributionsLinkListingAndDecompilation() throws Exception {
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
                return List.of(new FunctionInfo(new FunctionID(1), "portal_func_1", "portal_func_1_mangled", 0x1000L, 0xf1));
            }

            @Override
            public AIDecompilationStatus pollAIDecompileStatus(FunctionID functionID) {
                return new AIDecompilationStatus(
                        DecompilationData.StatusEnum.COMPLETED,
                        "int func1() {\n  int a = 1;\n  return a;\n}",
                        null,
                        null,
                        WorkflowProgress.StatusEnum.COMPLETED,
                        WorkflowProgress.StatusEnum.COMPLETED,
                        List.of(),
                        null);
            }

            @Override
            public Map<String, List<Long>> getAIDecompilationLineAttributions(FunctionID functionID) {
                return Map.of("0", List.of(1L), "1", List.of(2L), "2", List.of(3L));
            }

            @Override
            public List<String> getAssembly(FunctionID functionID) {
                return List.of("0x1000\tPUSH RBP", "0x1001\tMOV EAX,0x1", "0x1006\tRET", "0x10f0\tRET");
            }
        });

        var codeBrowser = env.addPlugin(ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin.class);
        env.addPlugin(BinarySimilarityPlugin.class);
        var builder = newX64Program();
        builder.createMemory(".text", "0x1000", 0x100);
        // PUSH RBP; MOV EAX,0x1; RET
        builder.setBytes("0x1000", "55 b8 01 00 00 00 c3", true);
        // A RET far enough down that the function header and it cannot share the screen
        builder.setBytes("0x10f0", "c3", true);
        var func1 = builder.createEmptyFunction(null, "0x1000", 0xf1, Undefined.getUndefinedDataType(4));
        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        var program = programWithID.program();
        env.showTool(program);
        // Room for the function header and its first few instructions
        runSwing(() -> tool.getToolFrame().setSize(1200, 1000));
        waitForSwing();

        var aiDecompComponent = getComponentProvider(AIDecompilationdWindow.class);
        RSyntaxTextArea textArea = (RSyntaxTextArea) getInstanceField("textArea", aiDecompComponent);
        var action = getAction(tool, "AI Decompilation");
        performAction(action, new ProgramLocationActionContext(null, program,
                new ProgramLocation(program, func1.getEntryPoint()), null, null), true);
        waitForTasks();
        waitForSwing();

        goTo(tool, program, program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1001));
        waitForSwing();
        assertEquals(List.of(1), highlightedLines(textArea));

        goTo(tool, program, func1.getEntryPoint());
        waitForSwing();
        assertEquals(List.of(), highlightedLines(textArea));

        // Scroll the function header off screen, so the click has to bring it back
        goTo(tool, program, program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10f0));
        waitForSwing();

        var cursor = codeBrowser.getCurrentAddress();
        var lineTwo = textArea.modelToView2D(textArea.getLineStartOffset(2)).getBounds();
        clickMouse(textArea, java.awt.event.MouseEvent.BUTTON1, lineTwo.x + 1, lineTwo.y + 1, 1, 0);
        waitForSwing();
        var highlight = codeBrowser.getProvider().getHighlight();
        var space = program.getAddressFactory().getDefaultAddressSpace();
        assertTrue(highlight.contains(space.getAddress(0x1006)));
        assertFalse(highlight.contains(space.getAddress(0x1001)));
        assertEquals("the cursor must stay put", cursor, codeBrowser.getCurrentAddress());
        assertEquals(List.of(2), highlightedLines(textArea));
        assertFalse(textArea.getHighlightCurrentLine());
        var listing = codeBrowser.getProvider().getListingPanel();
        var indexes = listing.getAddressIndexMap();
        assertEquals("a nearby instruction leaves the function header on top",
                indexes.getIndex(func1.getEntryPoint()), listing.getFieldPanel().getViewerPosition().getIndex());

        var lineThree = textArea.modelToView2D(textArea.getLineStartOffset(3)).getBounds();
        clickMouse(textArea, java.awt.event.MouseEvent.BUTTON1, lineThree.x + 1, lineThree.y + 1, 1, 0);
        waitForSwing();
        var farIndex = indexes.getIndex(space.getAddress(0x10f0));
        assertTrue("a distant instruction is scrolled into view", listing.getFieldPanel().getVisibleLayouts()
                .stream().anyMatch(layout -> layout.getIndex().equals(farIndex)));
        assertNotEquals(indexes.getIndex(func1.getEntryPoint()), listing.getFieldPanel().getViewerPosition().getIndex());

        runSwing(() -> {
            try {
                textArea.setCaretPosition(textArea.getLineStartOffset(1));
            } catch (javax.swing.text.BadLocationException e) {
                throw new RuntimeException(e);
            }
        });
        waitForSwing();
        highlight = codeBrowser.getProvider().getHighlight();
        assertTrue("moving the caret by keyboard lights its instructions", highlight.contains(space.getAddress(0x1001)));
        assertFalse(highlight.contains(space.getAddress(0x1006)));
        assertEquals(List.of(1), highlightedLines(textArea));
    }

    @SuppressWarnings("unchecked")
    private static List<Integer> highlightedLines(RSyntaxTextArea textArea) throws Exception {
        Object manager = invokeInstanceMethod("getLineHighlightManager", textArea);
        if (manager == null) {
            return List.of();
        }
        var lines = new java.util.ArrayList<Integer>();
        for (Object tag : (List<Object>) invokeInstanceMethod("getCurrentLineHighlightTags", manager)) {
            lines.add(textArea.getLineOfOffset((int) invokeInstanceMethod("getOffset", tag)));
        }
        java.util.Collections.sort(lines);
        return lines;
    }
}

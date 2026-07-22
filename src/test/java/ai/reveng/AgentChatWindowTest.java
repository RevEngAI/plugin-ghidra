package ai.reveng;

import ai.reveng.invoker.ApiException;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem;
import ai.reveng.toolkit.ghidra.chat.model.ChatState;
import ai.reveng.toolkit.ghidra.chat.ui.AgentChatWindow;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ai.reveng.toolkit.ghidra.plugins.AgentChatPlugin;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import javax.swing.JEditorPane;
import javax.swing.JLabel;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Headed integration test that the Agent Chat plugin loads, registers its dockable panel and menu
 * action, and resolves the chat context (analysis + function) as the cursor moves.
 */
public class AgentChatWindowTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void pluginRegistersPanelActionAndTracksContext() throws Exception {
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
                return List.of(new FunctionInfo(new FunctionID(1), "portal_func_1",
                        "portal_func_1_mangled", 0x1000L, 10));
            }
        });

        env.addPlugin(AgentChatPlugin.class);
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var func1 = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        env.showTool(programWithID.program());
        waitForSwing();

        var chatWindow = getComponentProvider(AgentChatWindow.class);
        assertNotNull("Agent Chat panel should be registered with the tool", chatWindow);
        assertNotNull("Agent Chat menu action should be installed", getAction(tool, "Agent Chat"));

        chatWindow.setVisible(true);
        goTo(tool, programWithID.program(), func1.getEntryPoint());
        waitForTasks();
        waitForSwing();

        JLabel contextLabel = (JLabel) getInstanceField("contextLabel", chatWindow);
        assertTrue("context chip should reflect the attached analysis, was: " + contextLabel.getText(),
                contextLabel.getText().contains("analysis #1"));
        assertTrue("context chip should reflect the focused function, was: " + contextLabel.getText(),
                contextLabel.getText().contains("fn:"));
    }

    @Test
    public void resolvesJumpAndExternalLinkHrefsFromRenderedTranscript() throws Exception {
        var tool = env.getTool();
        addMockedService(tool, new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return AnalysisStatus.Complete;
            }
        });
        env.addPlugin(AgentChatPlugin.class);
        var chatWindow = getComponentProvider(AgentChatWindow.class);

        var toolCall = new ChatItem.ToolCall("t1", "rename", "finished", false,
                List.of(new ChatItem.FunctionRef(0x1000L, "foo")));
        var message = new ChatItem.AssistantMessage("m1", "See [docs](https://example.com/help)", false);
        var state = new ChatState(List.of(message, toolCall), null, "idle", null);
        runSwing(() -> chatWindow.render(state));

        JEditorPane transcript = (JEditorPane) getInstanceField("transcript", chatWindow);
        Set<String> hrefs = new HashSet<>();
        int length = transcript.getDocument().getLength();
        for (int i = 0; i < length; i++) {
            Object href = invokeInstanceMethod("hrefAt", chatWindow,
                    new Class[]{int.class}, new Object[]{i});
            if (href != null) {
                hrefs.add((String) href);
            }
        }

        assertTrue("jump link href should be resolvable from the rendered anchor, found: " + hrefs,
                hrefs.contains("reai://jump/4096"));
        assertTrue("external markdown link href should be resolvable, found: " + hrefs,
                hrefs.contains("https://example.com/help"));
    }

    @Test
    public void forceAppliesAgentRenameOverExistingLocalName() throws Exception {
        var tool = env.getTool();
        var api = new UnimplementedAPI() {
            volatile String currentName = "original_name";

            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return AnalysisStatus.Complete;
            }

            @Override
            public AnalysisID analyse(AnalysisOptionsBuilder options) {
                return new AnalysisID(1);
            }

            @Override
            public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
                return List.of(new FunctionInfo(new FunctionID(1), currentName, currentName, 0x1000L, 10));
            }
        };
        var service = addMockedService(tool, api);
        env.addPlugin(AgentChatPlugin.class);

        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var func = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);
        Program program = programWithID.program();

        // Give the function an explicit, non-default local name.
        int tx = program.startTransaction("test setup rename");
        func.setName("user_named", ghidra.program.model.symbol.SourceType.USER_DEFINED);
        program.endTransaction(tx, true);
        assertEquals("user_named", func.getName());

        // The agent renamed it server-side; applying the authoritative name must overwrite the local one.
        var analysed = service.getAnalysedProgram(program).orElseThrow();
        AgentChatWindow.applyRenames(program, analysed, java.util.Map.of(1L, "renamed_by_agent"));

        assertEquals("agent rename must overwrite the existing local name",
                "renamed_by_agent", func.getName());
    }
}

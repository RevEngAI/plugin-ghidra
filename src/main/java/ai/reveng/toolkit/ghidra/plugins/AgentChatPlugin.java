package ai.reveng.toolkit.ghidra.plugins;

import ai.reveng.toolkit.ghidra.chat.service.ConversationsApiChatService;
import ai.reveng.toolkit.ghidra.chat.ui.AgentChatWindow;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import docking.action.builder.ActionBuilder;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;

/**
 * Provides the RevEng.AI Agent Chat dockable panel: a conversational agent that can read and modify
 * the current analysis. Port of the IDA plugin's Agent Chat feature (PLU-298).
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ReaiPluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "RevEng.AI Agent Chat.",
    description = "Chat with the RevEng.AI agent about the current binary; the agent can rename and "
            + "re-type functions, and its changes are pulled back into Ghidra.",
    servicesRequired = { GhidraRevengService.class, ReaiLoggingService.class, ProgramManager.class }
)
//@formatter:on
public class AgentChatPlugin extends ProgramPlugin {

    private final AgentChatWindow chatWindow;

    public AgentChatPlugin(PluginTool tool) {
        super(tool);
        chatWindow = new AgentChatWindow(tool, getName(), new ConversationsApiChatService());
        chatWindow.addToTool();
        setupActions();
    }

    private void setupActions() {
        new ActionBuilder("Agent Chat", getName())
                .menuGroup(ReaiPluginPackage.NAME)
                .menuPath(ReaiPluginPackage.MENU_GROUP_NAME, "Agent Chat")
                .onAction(context -> chatWindow.setVisible(true))
                .buildAndInstall(tool);
    }

    @Override
    protected void locationChanged(ProgramLocation location) {
        super.locationChanged(location);
        chatWindow.locationChanged(location);
    }

    @Override
    protected void dispose() {
        chatWindow.dispose();
        super.dispose();
    }
}

package ai.reveng.toolkit.ghidra.core.ui.wizard;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.models.ReaiConfig;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.ui.wizard.panels.UserCredentialsPanel;
import docking.wizard.AbstractMagePanelManager;
import docking.wizard.IllegalPanelStateException;
import docking.wizard.MagePanel;
import docking.wizard.WizardState;
import ghidra.framework.plugintool.PluginTool;

import static ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage.REAI_OPTIONS_CATEGORY;
import static ai.reveng.toolkit.ghidra.plugins.ReaiAPIServicePlugin.REAI_WIZARD_RUN_PREF;

public class SetupWizardManager extends AbstractMagePanelManager<SetupWizardStateKey> {
	private PluginTool tool;
	private ReaiLoggingService loggingService;

	public SetupWizardManager(WizardState<SetupWizardStateKey> initialState, PluginTool tool) {
		super(initialState);
		this.tool = tool;
	}

	@Override
	protected List<MagePanel<SetupWizardStateKey>> createPanels() {
		List<MagePanel<SetupWizardStateKey>> panels = new ArrayList<MagePanel<SetupWizardStateKey>>();
		panels.add(new UserCredentialsPanel(tool));

		return panels;
	}

	@Override
	protected void doFinish() throws IllegalPanelStateException {
		getWizardManager().completed(true);
		String apiKey = (String) getState().get(SetupWizardStateKey.API_KEY);
		String hostname = (String) getState().get(SetupWizardStateKey.HOSTNAME);
        String portalHostname = (String) getState().get(SetupWizardStateKey.PORTAL_HOSTNAME);
		String model = (String) getState().get(SetupWizardStateKey.MODEL);
		
		tool.getOptions(REAI_OPTIONS_CATEGORY).setString(ReaiPluginPackage.OPTION_KEY_APIKEY, apiKey);
		tool.getOptions(REAI_OPTIONS_CATEGORY).setString(ReaiPluginPackage.OPTION_KEY_HOSTNAME, hostname);
		tool.getOptions(REAI_OPTIONS_CATEGORY).setString(ReaiPluginPackage.OPTION_KEY_PORTAL_HOSTNAME, portalHostname);
		tool.getOptions(REAI_OPTIONS_CATEGORY).setString(ReaiPluginPackage.OPTION_KEY_MODEL, model);
		tool.getOptions(REAI_OPTIONS_CATEGORY).setString(REAI_WIZARD_RUN_PREF, "true");
		
		String configFileOverride = (String) getState().get(SetupWizardStateKey.CONFIGFILE);
		Path configFilePath = configFileOverride != null
				? Path.of(configFileOverride)
				: ReaiPluginPackage.DEFAULT_CONFIG_PATH;
		Path configDirPath = configFilePath.getParent();
		
		// check that our .reai directory exists
		if (!Files.exists(configDirPath)) {
			try {
				Files.createDirectories(configDirPath);
			} catch (IOException e) {
                cleanup();
                return;
            }
		}
		
		// create a new config file, overwritting any existing one
        try (FileWriter file = new FileWriter(configFilePath.toString())) {
        	ReaiConfig config = new ReaiConfig();
        	ReaiConfig.PluginSettings pluginSettings = new ReaiConfig.PluginSettings();
        	
        	pluginSettings.setApiKey(apiKey);
        	pluginSettings.setHostname(hostname);
            pluginSettings.setPortalHostname(portalHostname);
        	pluginSettings.setModelName(model);
        	config.setPluginSettings(pluginSettings);

        	Gson gson = new GsonBuilder().setPrettyPrinting().create();
        	gson.toJson(config, file);
        } catch (IOException e) {
        	cleanup();
            return;
        }
		
		cleanup();

	}

	@Override
	public void cancel() {
		cleanup();
	}

	private void cleanup() {
		List<MagePanel<SetupWizardStateKey>> panels = getPanels();
		for (MagePanel<SetupWizardStateKey> magePanel : panels) {
			magePanel.dispose();
		}
	}

}

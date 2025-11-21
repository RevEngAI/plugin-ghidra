package ai.reveng.toolkit.ghidra.plugins;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

import javax.swing.*;

/**
 * Top-level package object for RevEng.AI Ghidra Plugins
 */
public class ReaiPluginPackage extends PluginPackage {
	public static final String NAME = "RevEng.AI";
	public static final String PREFIX = "RevEngAI.";
	public static final String MENU_GROUP_NAME = "RevEng.AI";
	public static final String DEV_TOOLING_MENU_GROUP_NAME = "RevEng.AI Dev";
	public static final String WINDOW_PREFIX = "RevEng.AI: ";
	/*
	 * Below are the keys used to store/retrieve key-value pairs in Ghidra
	 * preferences
	 */
	public static final String OPTION_KEY_APIKEY = PREFIX + "API Key";
	public static final String OPTION_KEY_HOSTNAME = PREFIX + "Hostname";
	public static final String OPTION_KEY_PORTAL_HOSTNAME = PREFIX + "Portal Hostname";
	public static final String OPTION_KEY_MODEL = PREFIX + "Model";
    @Deprecated
	public static final String OPTION_KEY_BINID = PREFIX + "Binary ID";
    public static final String OPTION_KEY_ANALYSIS_ID = PREFIX + "Analysis ID";

    public static final String REAI_OPTIONS_CATEGORY = "RevEngAI Options";


    @Deprecated
	public static final Integer INVALID_BINARY_ID = -1;
    public static final Integer INVALID_ANALYSIS_ID = -1;

	public static final Icon REVENG_16 = ResourceManager.loadImage("images/reveng_16.png");


	/**
	 * Create a Top Level Plugin Package that uses the RevEng.AI logo
	 */
	public ReaiPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/icon.png"), "AI Assisted Binary Analysis");
	}
}
/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ai.reveng.toolkit.ghidra.plugins;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler.AIDecompilationdWindow;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.autounstrip.AutoUnstripDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.collectiondialog.DataSetControlPanelComponent;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching.BinaryLevelFunctionMatchingDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching.FunctionLevelFunctionMatchingDialog;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisResultsLoaded;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import docking.action.builder.ActionBuilder;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

import java.util.Arrays;

/**
 * This plugin provides features for performing binary code similarity using the
 * RevEng.AI API
 *
 * This depends on an Analysis ID being associated with a program
 *
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ReaiPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Support for Binary Similarity Features of RevEng.AI Toolkit.",
	description = "Enable features that support binary similarity operations, including binary upload, and auto-renaming",
	servicesRequired = { GhidraRevengService.class, ProgramManager.class, ExportFunctionBoundariesService.class, ReaiLoggingService.class },
	eventsConsumed = { RevEngAIAnalysisResultsLoaded.class, }
)
//@formatter:on
public class BinarySimilarityPlugin extends ProgramPlugin {
	private final AIDecompilationdWindow decompiledWindow;

    private GhidraRevengService apiService;

	public final static String REVENG_AI_NAMESPACE = "RevEng.AI";


	@Override
	protected void locationChanged(ProgramLocation loc) {
		super.locationChanged(loc);

        // If no location, nothing to do
        if (loc == null) {
            return;
        }

        // If no program, or not attached to a complete analysis, do not trigger location change events
        var program = loc.getProgram();
        if (program == null || apiService.getAnalysedProgram(program).isEmpty()) {
            return;
        }

		decompiledWindow.locationChanged(loc);
	}

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public BinarySimilarityPlugin(PluginTool tool) {
		super(tool);

		setupActions();

		// Setup windows
        decompiledWindow = new AIDecompilationdWindow(tool, REVENG_AI_NAMESPACE);
		decompiledWindow.addToTool();


		// Install Collections Control Panel
        DataSetControlPanelComponent collectionsComponent = new DataSetControlPanelComponent(tool, REVENG_AI_NAMESPACE);
		collectionsComponent.addToTool();
	}

    /// In `init()` the services are guaranteed to be available
    @Override
    public void init() {
        super.init();

        apiService = tool.getService(GhidraRevengService.class);
    }

	private void setupActions() {
        new ActionBuilder("Auto Unstrip", this.getName())
                .menuGroup(ReaiPluginPackage.NAME)
                .menuPath(ReaiPluginPackage.MENU_GROUP_NAME, "Auto Unstrip")
                .enabledWhen(context -> {
                            var program = tool.getService(ProgramManager.class).getCurrentProgram();
                            if (program != null) {
                                return apiService.getKnownProgram(program).isPresent();
                            } else {
                                return false;
                            }
                        }
                )
                .onAction(context -> {
                    var program = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (apiService.getAnalysedProgram(program).isEmpty()) {
                        Msg.showError(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Auto Unstrip",
                                "Analysis must have completed before running auto unstrip");
                        return;
                    }
                    var knownProgram = apiService.getKnownProgram(program);
                    if (knownProgram.isEmpty()){
                        Msg.info(this, "Program has no saved binary ID");
                        return;
                    }

                    var autoUnstrip = new AutoUnstripDialog(tool, knownProgram.get());

                    tool.showDialog(autoUnstrip);
                })
                .buildAndInstall(tool);

        // Top menu function matching
        new ActionBuilder("Function Matching", this.getName())
                .menuGroup(ReaiPluginPackage.NAME)
                .menuPath(ReaiPluginPackage.MENU_GROUP_NAME, "Function Matching")
                .enabledWhen(context -> {
                            var program = tool.getService(ProgramManager.class).getCurrentProgram();
                            if (program != null) {
                                return apiService.getAnalysedProgram(program).isPresent();
                            } else {
                                return false;
                            }
                        }
                )
                .onAction(context -> {
                    var program = tool.getService(ProgramManager.class).getCurrentProgram();
                    var knownProgram = apiService.getAnalysedProgram(program);
                    if (knownProgram.isEmpty()){
                        Msg.showError(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Function Matching",
                                "Analysis must have completed before running function matching");
                        return;
                    }

                    var functionMatchingDialog = new BinaryLevelFunctionMatchingDialog(tool, knownProgram.get());
                    tool.showDialog(functionMatchingDialog);
                })
                .buildAndInstall(tool);

        // Popup menu function matching
        new ActionBuilder("Match function", this.getName())
                .withContext(ProgramLocationActionContext.class)
                .enabledWhen(context -> {
                    var func = context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress());
                    return func != null
                            // Exclude thunks and external functions because we do not support them in the portal
                            && !func.isExternal()
                            && !func.isThunk()
                            && apiService.getAnalysedProgram(context.getProgram()).isPresent();
                })
                .onAction(context -> {
                    // We know analysed program is present due to enabledWhen
                    var knownProgram = apiService.getAnalysedProgram(context.getProgram()).get();

                    var func = context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress());

                    var functionMatchingDialog = new FunctionLevelFunctionMatchingDialog(tool, knownProgram, func);
                    tool.showDialog(functionMatchingDialog);
                })
                .popupMenuPath(new String[] { "Match function" })
                .popupMenuIcon(ReaiPluginPackage.REVENG_16)
                .popupMenuGroup(ReaiPluginPackage.MENU_GROUP_NAME)
                .buildAndInstall(tool);


		new ActionBuilder("AI Decompilation", this.getName())
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(context -> {
					var func = context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress());
					return func != null
                            // Exclude thunks and external functions because we do not support them in the portal
                            && !func.isExternal()
                            && !func.isThunk()
                            && apiService.getAnalysedProgram(context.getProgram()).isPresent();
				})
				.onAction(context -> {
					var func = context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress());
                    var analysedProgram = apiService.getAnalysedProgram(context.getProgram()).get();
                    var functionWithId = analysedProgram.getIDForFunction(func);
					if (functionWithId.isEmpty()) {
						Msg.showError(this, null, ReaiPluginPackage.WINDOW_PREFIX + "AI Decompilation",
								"Function is not known to the RevEng.AI API." +
										"This can happen if the function boundaries do not match.\n" +
										"You can create a new analysis based on the current analysis state to fix this.");
						return;
					}
					// Spawn Task to decompile the function
                    tool.getService(ReaiLoggingService.class).info("Requested AI Decompilation via Action for function " + func.getName());
                    decompiledWindow.setVisible(true);
                    decompiledWindow.refresh(functionWithId.get());
				})
				.popupMenuPath(new String[] { "AI Decompilation" })
				.popupMenuIcon(ReaiPluginPackage.REVENG_16)
				.popupMenuGroup(ReaiPluginPackage.MENU_GROUP_NAME)
				.buildAndInstall(tool);

        new ActionBuilder("View function in portal", this.getName())
                .withContext(ProgramLocationActionContext.class)
                .enabledWhen(context -> {
                    var func = context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress());
                    return func != null
                            && apiService.getAnalysedProgram(context.getProgram()).isPresent();
                })
                .onAction(context -> {
                    var func = context.getProgram().getFunctionManager().getFunctionContaining(context.getAddress());
                    var analysedProgram = apiService.getAnalysedProgram(context.getProgram()).get();
                    var functionWithID = analysedProgram.getIDForFunction(func);
                    if (functionWithID.isEmpty()) {
                        Msg.showError(this, null, ReaiPluginPackage.WINDOW_PREFIX + "View function in portal",
                                "Function is not known to the RevEng.AI API." +
                                        "This can happen if the function boundaries do not match.\n" +
                                        "You can create a new analysis based on the current analysis state to fix this.");
                        return;
                    }

                    apiService.openFunctionInPortal(functionWithID.get().functionID());
                })
                .popupMenuPath(new String[] { "View function in portal" })
                .popupMenuIcon(ReaiPluginPackage.REVENG_16)
                .popupMenuGroup(ReaiPluginPackage.MENU_GROUP_NAME)
                .buildAndInstall(tool);
	}

	@Override
	public void readDataState(SaveState saveState) {
		int[] rawCollectionIDs = saveState.getInts("collectionIDs", new int[0]);
		var restoredCollections = Arrays.stream(rawCollectionIDs)
				.mapToObj(CollectionID::new)
				.map(cID -> apiService.getApi().getCollectionInfo(cID))
				.toList();
		apiService.setActiveCollections(restoredCollections);
	}

	@Override
	public void writeDataState(SaveState saveState) {
		int[] collectionIDs = apiService.getActiveCollections().stream().map(Collection::collectionID).mapToInt(CollectionID::id).toArray();
		saveState.putInts("collectionIDs", collectionIDs);
	}

	@Override
	public void processEvent(PluginEvent event) {
        super.processEvent(event);
        if (event instanceof RevEngAIAnalysisResultsLoaded eventLoaded) {
                tool.getService(ReaiLoggingService.class).info("ANALYSIS COMPLETE EVENT");
            }
	}
}

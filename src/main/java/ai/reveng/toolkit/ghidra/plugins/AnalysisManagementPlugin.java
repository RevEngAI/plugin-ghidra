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

import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisResultsLoaded;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.analysiscreation.RevEngAIAnalysisOptionsDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc.AnalysisLogComponent;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses.RecentAnalysisDialog;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;

import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesService;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesServiceImpl;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.tasks.AttachToAnalysisTask;
import ai.reveng.toolkit.ghidra.core.tasks.StartAnalysisTask;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import docking.options.OptionsService;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskMonitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.util.Objects;

/**
 * CorePlugin for accessing the RevEng.AI Platform
 * It provides the {@link GhidraRevengService}
 * This is then used by other plugins to implement functionalities
 *
 * The UI components provided by this plugin are those for managing the basic actions such as
 * - running the setup wizard
 * - uploading a binary to the platform
 *
 * Other concepts such as creating a new analysis for a binary are still blurred between this and the
 * {@link BinarySimilarityPlugin}
 *
 * This distinction will be made clearer in future versions, when more features are available on the platform
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ReaiPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Toolkit for using the RevEng.AI API",
	description = "Toolkit for using RevEng.AI API",
	servicesRequired = { OptionsService.class, ReaiLoggingService.class, GhidraRevengService.class},
	servicesProvided = { ExportFunctionBoundariesService.class },
	eventsConsumed = { RevEngAIAnalysisStatusChangedEvent.class}
)
//@formatter:on
public class AnalysisManagementPlugin extends ProgramPlugin {
	private static final String REAI_ANALYSIS_MANAGEMENT_MENU_GROUP = "RevEng.AI Analysis Management";
	private static final String REAI_PLUGIN_PORTAL_MENU_GROUP = "RevEng.AI Portal";
    private static final Logger log = LoggerFactory.getLogger(AnalysisManagementPlugin.class);

    // Store references to actions that need to be refreshed
    private DockingAction createNewAction;
    private DockingAction attachToExistingAction;
    private DockingAction detachAction;
    private DockingAction checkStatusAction;
    private DockingAction viewInPortalAction;

    private GhidraRevengService revengService;
	private ExportFunctionBoundariesService exportFunctionBoundariesService;
	private AnalysisLogComponent analysisLogComponent;

	private PluginTool tool;


	public AnalysisManagementPlugin(PluginTool tool) {
		super(tool);

		this.tool = tool;


        exportFunctionBoundariesService = new ExportFunctionBoundariesServiceImpl(tool);
        registerServiceProvided(ExportFunctionBoundariesService.class, exportFunctionBoundariesService);

    }

    @Override
    public void init() {
        ReaiLoggingService loggingService = tool.getService(ReaiLoggingService.class);

        // Install analysis log viewer
        analysisLogComponent = new AnalysisLogComponent(tool);
        tool.addComponentProvider(analysisLogComponent, false);

        revengService = Objects.requireNonNull(tool.getService(GhidraRevengService.class));

        setupActions();
        installDecompilerToolbarAction();

        loggingService.info("CorePlugin initialized");
    }

    /**
     * Installs a toolbar action into the Decompiler window's local toolbar.
     * The action is enabled only when the current function is associated with
     * an analysis (i.e. has a known FunctionID on the server).
     */
    private void installDecompilerToolbarAction() {
        ComponentProvider decompilerProvider = tool.getComponentProvider("Decompiler");
        if (decompilerProvider == null) {
            Msg.warn(this, "Decompiler provider not found, skipping toolbar action installation");
            return;
        }

        DockingAction action = new DockingAction("RevEng.AI Actions", getName()) {
            @Override
            public boolean isValidContext(ActionContext context) {
                return context instanceof DecompilerActionContext;
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                if (!(context instanceof DecompilerActionContext ctx)) {
                    setDescription("Open function in portal");
                    return false;
                }
                if (ctx.isDecompiling() || !ctx.hasRealFunction()) {
                    setDescription("Open function in portal");
                    return false;
                }
                var program = ctx.getProgram();
                if (program == null) {
                    setDescription("Open function in portal");
                    return false;
                }
                var analysedProgram = revengService.getAnalysedProgram(program);
                if (analysedProgram.isEmpty()) {
                    setDescription("No analysis associated with this program");
                    return false;
                }
                var function = ctx.getFunction();
                if (analysedProgram.get().getIDForFunction(function).isEmpty()) {
                    setDescription("Function has no associated remote function ID");
                    return false;
                }
                setDescription("Open function in portal");
                return true;
            }

            @Override
            public void actionPerformed(ActionContext context) {
                if (!(context instanceof DecompilerActionContext ctx)) {
                    return;
                }
                var program = ctx.getProgram();
                if (program == null) {
                    return;
                }
                var analysedProgram = revengService.getAnalysedProgram(program).get();
                var function = ctx.getFunction();
                revengService.openPortalFor(analysedProgram.getIDForFunction(function).get());
            }
        };
        action.setToolBarData(new ToolBarData(ReaiPluginPackage.REVENG_16, "ZZ_RevEngAI"));
        action.setDescription("Open function in portal");

        tool.addLocalAction(decompilerProvider, action);
    }

	private void setupActions() {





        createNewAction = new ActionBuilder("Create new", this.getName())
                .enabledWhen(context -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (currentProgram == null) {
                        // Disable the action if no program is open
                        return false;
                    }
                    return revengService.getKnownProgram(currentProgram).isEmpty();
                })
                .onAction(context -> {
                    var program = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (!GhidraProgramUtilities.isAnalyzed(program)) {
                        Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Create new",
                                "Program has not been auto-analyzed by Ghidra yet. Please run auto-analysis first.");
                        return;
                    }
                    var ghidraService = tool.getService(GhidraRevengService.class);
                    var dialog = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, ghidraService, tool);
                    tool.showDialog(dialog);
                    var analysisOptions = dialog.getOptionsFromUI();
                    if (dialog.isOkPressed()) {
                        // User clicked OK
                        // Prepare Task that starts the analysis (uploading the binary and registering the analysis)
                        var task = new StartAnalysisTask(program, analysisOptions, revengService, analysisLogComponent, tool);
                        // Launch in Background
                        var builder = TaskBuilder.withTask(task);
                        analysisLogComponent.setVisible(true);
                        builder.launchInBackground(analysisLogComponent.getTaskMonitor());
                        // The task will fire the RevEngAIAnalysisStatusChangedEvent event when done
                        // which is then picked up by the AnalysisManagementPlugin and forwarded to the AnalysisLogComponent
                        tool.getService(ReaiLoggingService.class).info("Started analysis: ");
                    } else {
                        // User clicked Cancel
                        tool.getService(ReaiLoggingService.class).info("Create new analysis dialog cancelled by user");
                    }


                })
                .menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "Create new" })
                .menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "100")
                .popupMenuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP)
                .popupMenuPath(new String[] { "Create new" })
                .popupMenuIcon(ReaiPluginPackage.REVENG_16)
                .buildAndInstall(tool);

		attachToExistingAction = new ActionBuilder("Attach to existing", this.toString())
				.enabledWhen(c -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (currentProgram == null) {
                        return false;
                    }
                    return revengService.getKnownProgram(currentProgram).isEmpty();
                })
				.onAction(context -> {
					var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
					RecentAnalysisDialog dialog = new RecentAnalysisDialog(tool, currentProgram);
					tool.showDialog(dialog);
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "Attach to existing" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "200")
				// Also add this to the context action submenu to make it clear that this still needs to be done
				.popupMenuPath(new String[] { "Attach to existing" })
				.popupMenuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP)
				.popupMenuIcon(ReaiPluginPackage.REVENG_16)
				.buildAndInstall(tool);

		detachAction = new ActionBuilder("Detach", this.toString())
				.enabledWhen(c -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (currentProgram == null) {
                        // Disable the action if no program is open
                        return false;
                    }
                    return revengService.getKnownProgram(currentProgram).isPresent();
                })
				.onAction(context -> {
					var program = tool.getService(ProgramManager.class).getCurrentProgram();
					var knownProgram = this.revengService.getKnownProgram(program);
					var displayText = knownProgram.map(p -> "analysis " + p.analysisID().id()).orElseThrow();

					var result = OptionDialog.showOptionDialogWithCancelAsDefaultButton(
							tool.getToolFrame(),
							"Detach from " + displayText,
							"Are you sure you want to remove the association with " + displayText + "?",
							"Detach",
							OptionDialog.QUESTION_MESSAGE);
					if (result == OptionDialog.YES_OPTION) {
						// For now this is the only place to trigger the removal of the association
						// If this changes, the RevEngAIAnalysisStatusChanged event should be changed to accommodate
						// this kind of event
						program.withTransaction("Undo binary association", () -> revengService.removeProgramAssociation(program));

						// Refresh action states after detaching
                        tool.contextChanged(null);
					}

				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "Detach" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "300")
				.buildAndInstall(tool);

		checkStatusAction = new ActionBuilder("Check status", this.getName())
				.enabledWhen(context -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    if (currentProgram == null) {
                        // Disable the action if no program is open
                        return false;
                    }
                    return revengService.getKnownProgram(currentProgram).isPresent();
                })
				.onAction(context -> {
					var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
					var knownProgram = revengService.getKnownProgram(currentProgram).orElseThrow();
					var logs = revengService.getAnalysisLog(knownProgram.analysisID());
					analysisLogComponent.setLogs(logs);
					AnalysisStatus status = revengService.status(knownProgram);
                    tool.getService(ReaiLoggingService.class).info("Check Status: " + status);
					Msg.showInfo(this, null, ReaiPluginPackage.WINDOW_PREFIX + "Check status",
							"Status of analysis " + knownProgram + ": " + status);
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "Check status" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "400")
				.buildAndInstall(tool);

        viewInPortalAction = new DockingAction("View in portal", getName()) {
            @Override
            public boolean isEnabledForContext(ActionContext context) {
                var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                if (currentProgram == null) {
                    setDescription("No program is open");
                    return false;
                }
                if (revengService.getKnownProgram(currentProgram).isEmpty()) {
                    setDescription("No analysis associated with this program");
                    return false;
                }
                setDescription("View analysis in RevEng.AI portal");
                return true;
            }

            @Override
            public void actionPerformed(ActionContext context) {
                var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                var knownProgram = revengService.getKnownProgram(currentProgram).orElseThrow();
                revengService.openPortalFor(knownProgram);
            }
        };
        viewInPortalAction.setToolBarData(new ToolBarData(ReaiPluginPackage.REVENG_16, "ZZ_RevEngAI"));
        viewInPortalAction.setMenuBarData(
                new MenuData(
                        new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "View in portal" },
                        null,
                        REAI_ANALYSIS_MANAGEMENT_MENU_GROUP));
        viewInPortalAction.setDescription("View analysis in RevEng.AI portal");
        tool.addAction(viewInPortalAction);
	}

    @Override
    protected void programOpened(Program program) {
        super.programOpened(program);
        // When a program is opened, we check if it has an associated analysis (not necessarily finished yet)
        var knownProgram = revengService.getKnownProgram(program);
        if (knownProgram.isPresent()) {
            log.info("Opened known program: {}", knownProgram.get());
            var analysedProgram = revengService.getAnalysedProgram(program);
            if (analysedProgram.isPresent()) {
                // Nothing to do, we already have loaded the function IDs and similar
                log.info("Loaded analysed program: {}", analysedProgram);
            } else {
                // There is an associated program that hasn't been fully loaded yet
                // This can happen if the analysis was started in a previous session but hadn't finished when closing Ghidra
                // Either the analysis is finished already now, or we want to actively wait for it to finish
                log.info("Detected known program that hasn't been fully loaded yet: {}", knownProgram.get());
                var status = revengService.status(knownProgram.get());
                switch (status) {
                    case Complete -> {
                        tool.firePluginEvent(
                                new RevEngAIAnalysisStatusChangedEvent(
                                        "programOpened",
                                        knownProgram.get(),
                                        status));
                    }
                    case Queued, Processing -> {
                        // This is the same code as above, but it has the implicit assumption that someone
                        /// Currently this is done by {@link AnalysisLogComponent#processEvent(RevEngAIAnalysisStatusChangedEvent)}
                        tool.firePluginEvent(
                                new RevEngAIAnalysisStatusChangedEvent(
                                        "programOpened",
                                        knownProgram.get(),
                                        status));
                    }


                    case Error -> {
                        // The analysis failed on the server side
                        Msg.showError(this, null, "Analysis Error",
                                "The RevEng.AI analysis for the program " + knownProgram.get() + " is in error state on the server side.");
                    }
                }
            }
        } else {
            log.info("Opened unknown program: {}", program.getName());
        }
    }

    @Override
	protected void programActivated(Program program) {
		super.programActivated(program);
        // Any ComponentProviders that need to refresh based on the current program should be notified here
        analysisLogComponent.programActivated(program);
	}

    @Override
    public void processEvent(PluginEvent event) {
        super.processEvent(event);
        // Forward the event to the analysis log component
        if (event instanceof RevEngAIAnalysisStatusChangedEvent analysisEvent) {

            analysisLogComponent.processEvent(analysisEvent);
            if (analysisEvent.getStatus() == AnalysisStatus.Complete) {
                Msg.info(this, "Received analysis complete event for " + analysisEvent.getProgramWithBinaryID());

                // If the analysis is complete, we refresh the function signatures from the server
                var program = analysisEvent.getProgramWithBinaryID();
                var task = new AttachToAnalysisTask(program, null, revengService, tool);
                TaskBuilder.withTask(task)
                        .setCanCancel(false)
                        .setStatusTextAlignment(SwingConstants.LEADING)
                        .launchModal();

            }
        }
    }

}

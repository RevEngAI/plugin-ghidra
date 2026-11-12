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

import ai.reveng.toolkit.ghidra.core.services.sync.AutoUnstripSyncService;
import ai.reveng.toolkit.ghidra.core.services.sync.LocalEditSyncService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.tasks.StartAnalysisTask;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import docking.options.OptionsService;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import javax.annotation.Nullable;
import ghidra.util.task.Task;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskMonitor;
import javax.swing.SwingUtilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;

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
	eventsConsumed = { RevEngAIAnalysisStatusChangedEvent.class}
)
//@formatter:on
public class AnalysisManagementPlugin extends ProgramPlugin {
	private static final String REAI_ANALYSIS_MANAGEMENT_MENU_GROUP = "RevEng.AI Analysis Management";
    private static final Logger log = LoggerFactory.getLogger(AnalysisManagementPlugin.class);

    private GhidraRevengService revengService;
	private AnalysisLogComponent analysisLogComponent;
	private LocalEditSyncService localEditSyncService;
	private AutoUnstripSyncService autoUnstripSyncService;
	/// Programs whose analysis results failed to load, for the Retry action. Touched from tasks and the Swing thread.
	private final Set<Program> failedLoads = ConcurrentHashMap.newKeySet();
	private static final String RETRY_HINT =
			"The program was left unchanged. Retry now, or later from RevEng.AI > Analysis > Retry loading results.";

	private PluginTool tool;


	public AnalysisManagementPlugin(PluginTool tool) {
		super(tool);

		this.tool = tool;
    }

    @Override
    public void init() {
        ReaiLoggingService loggingService = tool.getService(ReaiLoggingService.class);

        // Install analysis log viewer
        analysisLogComponent = new AnalysisLogComponent(tool);
        tool.addComponentProvider(analysisLogComponent, false);

        revengService = Objects.requireNonNull(tool.getService(GhidraRevengService.class));
        BiConsumer<String, Boolean> statusNotifier =
                (message, warning) -> SwingUtilities.invokeLater(() -> tool.setStatusInfo(message, warning));
        localEditSyncService = new LocalEditSyncService(revengService, loggingService, statusNotifier);
        autoUnstripSyncService = new AutoUnstripSyncService(revengService, loggingService, statusNotifier);

        setupActions();

        loggingService.info("CorePlugin initialized");
    }

	private void setupActions() {





        new ActionBuilder("Create new", this.getName())
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
                    var dialog = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, ghidraService);
                    tool.showDialog(dialog);
                    var analysisOptions = dialog.getOptionsFromUI();
                    if (analysisOptions != null) {
                        // User clicked OK
                        // Prepare Task that starts the analysis (uploading the binary and registering the analysis)
                        var task = new StartAnalysisTask(program, analysisOptions, revengService, analysisLogComponent, tool);
                        // Launch in Background
                        var builder = TaskBuilder.withTask(task);
                        analysisLogComponent.setVisible(true);
                        builder.launchInBackground(analysisLogComponent.getTaskMonitor());
                        // The task runs in the background and logs the actual outcome (success or failure)
                        // itself. On success it fires the RevEngAIAnalysisStatusChangedEvent, which is picked
                        // up by the AnalysisManagementPlugin and forwarded to the AnalysisLogComponent.
                        tool.getService(ReaiLoggingService.class).info("Launching analysis task in background");
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

		new ActionBuilder("Attach to existing", this.toString())
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

		new ActionBuilder("Detach", this.toString())
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

		new ActionBuilder("Check status", this.getName())
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
					tool.execute(new Task("Check status", true, false, false) {
						@Override
						public void run(TaskMonitor monitor) {
							try {
								var logs = revengService.getAnalysisLog(knownProgram.analysisID());
								AnalysisStatus status = revengService.status(knownProgram);
								tool.getService(ReaiLoggingService.class).info("Check Status: " + status);
								SwingUtilities.invokeLater(() -> {
									analysisLogComponent.setLogs(logs);
									Msg.showInfo(AnalysisManagementPlugin.this, null, ReaiPluginPackage.WINDOW_PREFIX + "Check status",
											checkStatusMessage(status));
								});
							} catch (Exception e) {
								Msg.error(AnalysisManagementPlugin.this, "Failed to check analysis status: " + e.getMessage(), e);
							}
						}
					}, 0);
				})
				.menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "Check status" })
				.menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "400")
				.buildAndInstall(tool);

        new ActionBuilder("Retry loading results", this.getName())
                .enabledWhen(context -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    return currentProgram != null && failedLoads.contains(currentProgram);
                })
                .onAction(context -> {
                    var currentProgram = tool.getService(ProgramManager.class).getCurrentProgram();
                    revengService.getKnownProgram(currentProgram).ifPresent(this::loadAnalysisResults);
                })
                .menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "Retry loading results" })
                .menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "250")
                .buildAndInstall(tool);

        new ActionBuilder("View in portal", this.getName())
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
                    revengService.openPortalFor(tool, knownProgram);
                })
                .menuPath(new String[] { ReaiPluginPackage.MENU_GROUP_NAME, "Analysis", "View in portal" })
                .menuGroup(REAI_ANALYSIS_MANAGEMENT_MENU_GROUP, "400")
                .buildAndInstall(tool);
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
                localEditSyncService.attach(program);
                autoUnstripSyncService.pollAndSync(analysedProgram.get(), false);
            } else {
                // There is an associated program that hasn't been fully loaded yet
                // This can happen if the analysis was started in a previous session but hadn't finished when closing Ghidra
                // Either the analysis is finished already now, or we want to actively wait for it to finish
                log.info("Detected known program that hasn't been fully loaded yet: {}", knownProgram.get());
                // Off the Swing thread: programs are opened on it, and without network the request blocks until it times out
                tool.execute(new Task("Check RevEng.AI analysis status", false, false, false) {
                    @Override
                    public void run(TaskMonitor monitor) {
                        AnalysisStatus status;
                        try {
                            status = revengService.status(knownProgram.get());
                        } catch (Exception e) {
                            Msg.warn(AnalysisManagementPlugin.this,
                                    "Could not check the RevEng.AI analysis status for " + knownProgram.get() + ": " + e.getMessage());
                            return;
                        }
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
                                Msg.showError(AnalysisManagementPlugin.this, null, "Analysis Error",
                                        "The RevEng.AI analysis for the program " + knownProgram.get() + " is in error state on the server side.");
                            }
                        }
                    }
                }, 0);
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
    protected void programClosed(Program program) {
        super.programClosed(program);
        failedLoads.remove(program);
        if (localEditSyncService != null) {
            localEditSyncService.detach(program);
        }
        if (autoUnstripSyncService != null) {
            revengService.getKnownProgram(program)
                    .ifPresent(known -> autoUnstripSyncService.stopPolling(known.analysisID()));
        }
    }

    @Override
    protected void dispose() {
        if (localEditSyncService != null) {
            localEditSyncService.dispose();
        }
        if (autoUnstripSyncService != null) {
            autoUnstripSyncService.dispose();
        }
        super.dispose();
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
                loadAnalysisResults(analysisEvent.getProgramWithBinaryID());
            }
        }
    }

    private void loadAnalysisResults(GhidraRevengService.ProgramWithID program) {
        failedLoads.remove(program.program());
        // Disables the Retry action straight away, so a second click cannot start a second load
        tool.contextChanged(null);
        // Events arrive on the Swing thread, and loading the results makes several requests
        tool.execute(new Task("Load RevEng.AI analysis results", true, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    var analysedProgram = revengService.registerFinishedAnalysisForProgram(program, monitor);
                    localEditSyncService.attach(program.program());
                    tool.firePluginEvent(new RevEngAIAnalysisResultsLoaded("AnalysisManagementPlugin", analysedProgram));
                    // Auto-unstrip runs server-side after the analysis is marked complete, so poll for it
                    // and sync the recovered names / data types once it finishes (PLU-300).
                    autoUnstripSyncService.pollAndSync(analysedProgram, true);
                } catch (CancelledException e) {
                    reportFailedLoad(program, loadCancelledMessage(program), null);
                } catch (Exception e) {
                    Msg.error(AnalysisManagementPlugin.this, "Error registering finished analysis for program " + program, e);
                    reportFailedLoad(program, loadFailedMessage(program, e), e);
                }
            }
        }, 0);
    }

    /// The service leaves the program as it was before the load, so it can simply be loaded again: from the
    /// dialog straight away, or later from the Retry action.
    private void reportFailedLoad(GhidraRevengService.ProgramWithID program, String message, @Nullable Exception error) {
        var loggingService = tool.getService(ReaiLoggingService.class);
        if (loggingService != null) {
            loggingService.error(message);
        }
        // On the Swing thread, like programClosed, so a program closed during the load cannot be added after it
        SwingUtilities.invokeLater(() -> {
            if (program.program().isClosed()) {
                // Closed during the load, which is likely why it failed. There is nothing left to retry on.
                return;
            }
            failedLoads.add(program.program());
            tool.setStatusInfo(message, true);
            tool.contextChanged(null);
            if (error == null) {
                // Cancelled by the analyst, who needs no dialog to learn about it
                return;
            }
            var choice = OptionDialog.showOptionDialog(tool.getToolFrame(),
                    ReaiPluginPackage.WINDOW_PREFIX + "Load analysis results", message + "\n\n" + RETRY_HINT,
                    "Retry", OptionDialog.ERROR_MESSAGE);
            if (choice == OptionDialog.OPTION_ONE && failedLoads.contains(program.program())) {
                loadAnalysisResults(program);
            }
        });
    }

    private static String loadFailedMessage(GhidraRevengService.ProgramWithID program, Exception error) {
        // The API wraps its exceptions as `new RuntimeException(cause)`, whose message is the cause's class name
        // followed by its message. The analyst only needs the message.
        Throwable shown = error.getCause() != null && Objects.equals(error.getMessage(), error.getCause().toString())
                ? error.getCause() : error;
        var reason = shown.getMessage() != null ? shown.getMessage() : shown.getClass().getSimpleName();
        return "Could not load the results of RevEng.AI analysis %d into %s: %s"
                .formatted(program.analysisID().id(), program.program().getName(), reason);
    }

    private static String loadCancelledMessage(GhidraRevengService.ProgramWithID program) {
        return "Loading the results of RevEng.AI analysis %d into %s was cancelled"
                .formatted(program.analysisID().id(), program.program().getName());
    }

    static String checkStatusMessage(AnalysisStatus status) {
        return "Analysis status: " + status;
    }

}

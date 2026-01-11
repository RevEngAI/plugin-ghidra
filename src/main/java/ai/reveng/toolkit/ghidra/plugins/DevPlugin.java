package ai.reveng.toolkit.ghidra.plugins;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.APIConflictException;
import ai.reveng.toolkit.ghidra.devplugin.RevEngMetadataProvider;
import docking.action.builder.ActionBuilder;
import docking.options.OptionsService;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.util.List;

import static ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage.DEV_TOOLING_MENU_GROUP_NAME;

/**
 * Plugin for development and debug helpers for the RevEng.AI Toolkit
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ReaiPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Helper and Debug Tools for the RevEng.AI Toolkit",
	description = "Collection of tools that are not relevant for end user use," +
			"but are useful for developing your own scripts or debugging the RevEng.AI Toolkit",
	servicesRequired = { OptionsService.class, GhidraRevengService.class }
)
//@formatter:on
public class DevPlugin extends ProgramPlugin {

	private final RevEngMetadataProvider revEngMetadataProvider;
	private GhidraRevengService apiService;

	public DevPlugin(PluginTool tool) {
		super(tool);
		revEngMetadataProvider = new RevEngMetadataProvider(tool, ReaiPluginPackage.NAME);
		tool.addComponentProvider(revEngMetadataProvider, false);

		var generateSignaturesAction = new ActionBuilder("Generate Signatures", ReaiPluginPackage.NAME)
				.menuPath(DEV_TOOLING_MENU_GROUP_NAME, "Generate Signatures for current program")
				.onAction(e -> {
					GhidraRevengService reAIService = tool.getService(GhidraRevengService.class);
					var api = reAIService.getApi();
                    var analysedProgram = reAIService.getAnalysedProgram(currentProgram).orElseThrow();
					var functionMap = analysedProgram.getFunctionMap();
					var task = new Task("Generate Signatures", true, true, true) {
						@Override
						public void run(TaskMonitor monitor) {
							monitor.setMaximum(functionMap.size());
							functionMap.forEach(
									(fID, function) -> {
										try {
											monitor.checkCancelled();
											api.generateFunctionDataTypes(analysedProgram.analysisID(), List.of(fID));
											monitor.incrementProgress(1);
										} catch (APIConflictException e) {
											// Already requested
										} catch (Exception e) {
											Msg.showError(this, null, "Error", e.getMessage(), e);
										}
									}
							);
						}
					};
					tool.execute(task);
				})
				.buildAndInstall(tool);



	}

	@Override
	protected void programActivated(Program program) {
		revEngMetadataProvider.setProgram(program);
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		super.locationChanged(loc);
		revEngMetadataProvider.locationChanged(loc);
	}

	@Override
	public void init() {
		super.init();
		this.apiService = tool.getService(GhidraRevengService.class);
	}

}

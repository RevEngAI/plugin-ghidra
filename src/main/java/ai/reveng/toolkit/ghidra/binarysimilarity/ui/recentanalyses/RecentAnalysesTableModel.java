package ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.function.export.ExportFunctionBoundariesService;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RecentAnalysesTableModel extends ThreadedTableModelStub<LegacyAnalysisResult> {
    private final TypedApiInterface.BinaryHash hash;
    private final Address imageBase;

    public RecentAnalysesTableModel(PluginTool tool, TypedApiInterface.BinaryHash hash, Address imageBase) {
        super("Recent Analyses Table Model", tool);
        this.hash = hash;
        this.imageBase = imageBase;
    }

    @Override
    protected void doLoad(Accumulator<LegacyAnalysisResult> accumulator, TaskMonitor monitor) throws CancelledException {
        var revEngAIService = serviceProvider.getService(GhidraRevengService.class);
        var functionBoundariesService = serviceProvider.getService(ExportFunctionBoundariesService.class);
        var loggingService = serviceProvider.getService(ReaiLoggingService.class);

        // The search endpoint only returns analyses we have access to so there is no need to filter them.
        revEngAIService.searchForHash(hash).forEach(
                result -> {
                    // Filter out analyses that are not Complete
                    if (result.status() != AnalysisStatus.Complete) {
                        loggingService.info("[RevEng] Skipping analysis for " + result.binary_id() + " as status is " + result.status());
                        return;
                    }

                    // Filter out analyses where the base address does not match our program
                    if (result.base_address() != imageBase.getOffset()) {
                        loggingService.info(
                            "[RevEng] Skipping analysis for " + result.binary_id() + " as base address does not match. Expected " +
                            imageBase.getOffset() + " but got " + result.base_address());
                        return;
                    }

                    accumulator.add(result);
                }
        );
    }

    @Override
    protected TableColumnDescriptor<LegacyAnalysisResult> createTableColumnDescriptor() {
        TableColumnDescriptor<LegacyAnalysisResult> descriptor = new TableColumnDescriptor<>();
        descriptor.addVisibleColumn(new AbstractDynamicTableColumn<LegacyAnalysisResult, String, Object>() {
            @Override
            public String getColumnName() {
                return "Analysis ID";
            }

            @Override
            public String getValue(LegacyAnalysisResult rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return String.valueOf(rowObject.analysis_id().id());
            }

            @Override
            public String getColumnDescription() {
                return "Click to open analysis in RevEng.AI portal";
            }
        });
        descriptor.addVisibleColumn(new AbstractDynamicTableColumn<LegacyAnalysisResult, String, Object>() {
            @Override
            public String getColumnName() {
                return "Binary Name";
            }

            @Override
            public String getValue(LegacyAnalysisResult rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return rowObject.binary_name();
            }
        });

        descriptor.addVisibleColumn(new AbstractDynamicTableColumn<LegacyAnalysisResult, String, Object>() {
            @Override
            public String getColumnName() {
                return "Creation Time";
            }

            @Override
            public String getValue(LegacyAnalysisResult rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return rowObject.creation();
            }
        });

        descriptor.addVisibleColumn(new AbstractDynamicTableColumn<LegacyAnalysisResult, AnalysisStatus, Object>() {
            @Override
            public String getColumnName() {
                return "Status";
            }

            @Override
            public AnalysisStatus getValue(LegacyAnalysisResult rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return rowObject.status();
            }
        });


        return descriptor;
    }
}

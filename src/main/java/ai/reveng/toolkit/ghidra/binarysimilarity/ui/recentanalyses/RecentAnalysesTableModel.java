package ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses;

import ai.reveng.model.AnalysisRecordBody;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
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

import java.time.OffsetDateTime;

public class RecentAnalysesTableModel extends ThreadedTableModelStub<AnalysisRecordBody> {
    private final TypedApiInterface.BinaryHash hash;
    private final Address imageBase;

    public RecentAnalysesTableModel(PluginTool tool, TypedApiInterface.BinaryHash hash, Address imageBase) {
        super("Recent Analyses Table Model", tool);
        this.hash = hash;
        this.imageBase = imageBase;
    }

    @Override
    protected void doLoad(Accumulator<AnalysisRecordBody> accumulator, TaskMonitor monitor) throws CancelledException {
        var revEngAIService = serviceProvider.getService(GhidraRevengService.class);
        var loggingService = serviceProvider.getService(ReaiLoggingService.class);

        // The search endpoint only returns analyses we have access to so there is no need to filter them.
        revEngAIService.searchForHash(hash).forEach(
                result -> {
                    // Filter out analyses that are not Complete
                    if (!AnalysisStatus.Complete.name().equals(result.getStatus())) {
                        loggingService.info("[RevEng] Skipping analysis for " + result.getBinaryId() + " as status is " + result.getStatus());
                        return;
                    }

                    // Filter out analyses where the base address does not match our program
                    if (result.getBaseAddress() == null || result.getBaseAddress() != imageBase.getOffset()) {
                        loggingService.info(
                            "[RevEng] Skipping analysis for " + result.getBinaryId() + " as base address does not match. Expected " +
                            imageBase.getOffset() + " but got " + result.getBaseAddress());
                        return;
                    }

                    accumulator.add(result);
                }
        );
    }

    @Override
    protected TableColumnDescriptor<AnalysisRecordBody> createTableColumnDescriptor() {
        TableColumnDescriptor<AnalysisRecordBody> descriptor = new TableColumnDescriptor<>();
        descriptor.addVisibleColumn(new AbstractDynamicTableColumn<AnalysisRecordBody, String, Object>() {
            @Override
            public String getColumnName() {
                return "Analysis ID";
            }

            @Override
            public String getValue(AnalysisRecordBody rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return String.valueOf(rowObject.getAnalysisId());
            }

            @Override
            public String getColumnDescription() {
                return "Click to open analysis in RevEng.AI portal";
            }
        });
        descriptor.addVisibleColumn(new AbstractDynamicTableColumn<AnalysisRecordBody, String, Object>() {
            @Override
            public String getColumnName() {
                return "Binary Name";
            }

            @Override
            public String getValue(AnalysisRecordBody rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return rowObject.getBinaryName();
            }
        });

        descriptor.addVisibleColumn(new AbstractDynamicTableColumn<AnalysisRecordBody, OffsetDateTime, Object>() {
            @Override
            public String getColumnName() {
                return "Creation Time";
            }

            @Override
            public OffsetDateTime getValue(AnalysisRecordBody rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return rowObject.getCreation();
            }
        });

        descriptor.addVisibleColumn(new AbstractDynamicTableColumn<AnalysisRecordBody, String, Object>() {
            @Override
            public String getColumnName() {
                return "Status";
            }

            @Override
            public String getValue(AnalysisRecordBody rowObject, Settings settings, Object data, ServiceProvider serviceProvider) throws IllegalArgumentException {
                return rowObject.getStatus();
            }
        });


        return descriptor;
    }
}

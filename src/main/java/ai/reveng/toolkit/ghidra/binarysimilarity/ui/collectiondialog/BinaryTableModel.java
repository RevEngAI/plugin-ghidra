package ai.reveng.toolkit.ghidra.binarysimilarity.ui.collectiondialog;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import static ai.reveng.toolkit.ghidra.Utils.addRowToDescriptor;

public class BinaryTableModel extends ThreadedTableModelStub<BinaryRowObject> {
    public BinaryTableModel(PluginTool tool) {
        super("Binary Table Model", tool);

    }

    @Override
    protected void doLoad(Accumulator<BinaryRowObject> accumulator, TaskMonitor monitor) throws CancelledException {
        var service = serviceProvider.getService(GhidraRevengService.class);
        if (service == null) return;
        service.getActiveAnalysisIDsFilter()
                .forEach(
                        analysisResult -> accumulator.add(new BinaryRowObject(analysisResult, true))
                );
    }

    @Override
    protected void clearData() {
        super.clearData();
    }

    @Override
    protected TableColumnDescriptor<BinaryRowObject> createTableColumnDescriptor() {
        var descriptor = new TableColumnDescriptor<BinaryRowObject>();
        addRowToDescriptor(descriptor, "Name", String.class, (row) -> row.analysisResult().binary_name());
        descriptor.addVisibleColumn(new BinaryIncludeColumn());
        addRowToDescriptor(descriptor, "SHA256 Hash", false, String.class, (row) -> row.analysisResult().sha_256_hash().sha256());
//        addRowToDescriptor(descriptor, "Binary ID", String.class, (row) -> row.analysisResult().b);
//        addRowToDescriptor(descriptor, "Is Debug"

        return descriptor;
    }

    public void storeBinaryFiltersInService() {
        serviceProvider.getService(GhidraRevengService.class).setAnalysisIDMatchFilter(
                getModelData()
                        .stream()
                        .filter(BinaryRowObject::include)
                        .map(BinaryRowObject::analysisResult)
                        .toList()
        );
    }
    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return tableColumns.get(columnIndex).getColumnName().equals("Include");
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (tableColumns.get(columnIndex).getColumnName().equals("Include")) {
            if (aValue instanceof Boolean) {
                BinaryRowObject ro = getRowObject(rowIndex);
                ro.setInclude((Boolean) aValue);
                fireTableRowsUpdated(rowIndex, rowIndex);
                storeBinaryFiltersInService();
            }
        }
    }


    private class BinaryIncludeColumn extends AbstractDynamicTableColumn<BinaryRowObject, Boolean, Object> {

        @Override
        public String getColumnName() {
            return "Include";
        }

        @Override
        public Boolean getValue(BinaryRowObject rowObject, Settings settings, Object data,
                                ServiceProvider serviceProvider) {
            return rowObject.include();
        }

    }

}

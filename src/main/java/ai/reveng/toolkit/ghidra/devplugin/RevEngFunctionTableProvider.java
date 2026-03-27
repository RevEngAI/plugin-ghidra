package ai.reveng.toolkit.ghidra.devplugin;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigatableRemovalListener;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static ai.reveng.toolkit.ghidra.Utils.addRowToDescriptor;

/**
 * Component provider that displays all functions in the current program
 * along with their RevEng.AI metadata (function ID, remote name, mangled name).
 */
public class RevEngFunctionTableProvider extends ComponentProviderAdapter {

    private final JPanel mainPanel;
    private final FunctionInfoTableModel tableModel;
    private final GhidraFilterTable<FunctionInfoRow> filterTable;
    private Program currentProgram;

    public RevEngFunctionTableProvider(PluginTool tool, String owner) {
        super(tool, "RevEng.AI Function Table", owner);
        setIcon(ReaiPluginPackage.REVENG_16);

        tableModel = new FunctionInfoTableModel(tool);
        filterTable = new GhidraFilterTable<>(tableModel);

        // Navigate to function on row selection
        filterTable.getTable().getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int row = filterTable.getTable().getSelectedRow();
            if (row < 0) {
                return;
            }
            FunctionInfoRow rowObject = tableModel.getRowObject(row);
            if (rowObject == null) {
                return;
            }
            GoToService goToService = tool.getService(GoToService.class);
            if (goToService != null) {
                goToService.goTo(rowObject.getAddress());
            }
        });

        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(filterTable, BorderLayout.CENTER);
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    public void setProgram(Program program) {
        this.currentProgram = program;
        reload();
    }

    public void reload() {
        tableModel.reload(currentProgram);
    }

    /**
     * Row object holding a Ghidra function and its RevEng.AI metadata.
     */
    static class FunctionInfoRow {
        private final Function function;
        private final TypedApiInterface.FunctionID remoteFunctionID;
        private final String remoteMangledName;

        FunctionInfoRow(Function function, TypedApiInterface.FunctionID remoteFunctionID, String remoteMangledName) {
            this.function = function;
            this.remoteFunctionID = remoteFunctionID;
            this.remoteMangledName = remoteMangledName;
        }

        public Function getFunction() {
            return function;
        }

        public Address getAddress() {
            return function.getEntryPoint();
        }

        public String getLocalName() {
            return function.getName();
        }

        public long getSize() {
            return function.getBody().getNumAddresses();
        }

        public boolean isThunk() {
            return function.isThunk();
        }

        public Long getRemoteFunctionIDValue() {
            return remoteFunctionID != null ? remoteFunctionID.value() : null;
        }

        public String getRemoteName() {
            // The Ghidra function name will have been updated to the remote name if available
            // but we track the original remote name separately via the mangled name
            return remoteFunctionID != null ? function.getName() : null;
        }

        public String getRemoteMangledName() {
            return remoteMangledName;
        }

        public boolean hasRemoteInfo() {
            return remoteFunctionID != null;
        }
    }

    /**
     * Table model for displaying function info with RevEng.AI metadata.
     */
    static class FunctionInfoTableModel extends ThreadedTableModelStub<FunctionInfoRow> {
        private final List<FunctionInfoRow> rows = new ArrayList<>();
        private final PluginTool pluginTool;

        FunctionInfoTableModel(PluginTool tool) {
            super("RevEng.AI Function Info", tool);
            this.pluginTool = tool;
        }

        void reload(Program program) {
            rows.clear();
            if (program == null) {
                reload();
                return;
            }

            GhidraRevengService service = pluginTool.getService(GhidraRevengService.class);
            Optional<GhidraRevengService.AnalysedProgram> analysedOpt =
                    service != null ? service.getAnalysedProgram(program) : Optional.empty();

            program.getFunctionManager().getFunctions(true).forEach(function -> {
                TypedApiInterface.FunctionID fID = null;
                String mangledName = null;

                if (analysedOpt.isPresent()) {
                    var analysed = analysedOpt.get();
                    var fWithID = analysed.getIDForFunction(function);
                    if (fWithID.isPresent()) {
                        fID = fWithID.get().functionID();
                        try {
                            mangledName = analysed.getMangledNameForFunction(function);
                        } catch (Exception ignored) {
                            // mangled name map may not exist yet
                        }
                    }
                }

                rows.add(new FunctionInfoRow(function, fID, mangledName));
            });
            reload();
        }

        @Override
        protected void doLoad(Accumulator<FunctionInfoRow> accumulator, TaskMonitor monitor) {
            monitor.setMessage("Loading function info");
            monitor.setMaximum(rows.size());
            for (int i = 0; i < rows.size(); i++) {
                if (monitor.isCancelled()) {
                    break;
                }
                accumulator.add(rows.get(i));
                monitor.setProgress(i + 1);
            }
        }

        @Override
        protected TableColumnDescriptor<FunctionInfoRow> createTableColumnDescriptor() {
            TableColumnDescriptor<FunctionInfoRow> descriptor = new TableColumnDescriptor<>();
            addRowToDescriptor(descriptor, "Address", Address.class, FunctionInfoRow::getAddress, 1, true);
            addRowToDescriptor(descriptor, "Local Name", String.class, FunctionInfoRow::getLocalName);
            addRowToDescriptor(descriptor, "Size", Long.class, FunctionInfoRow::getSize);
            addRowToDescriptor(descriptor, "Thunk", Boolean.class, FunctionInfoRow::isThunk);
            addRowToDescriptor(descriptor, "Has Remote Info", Boolean.class, FunctionInfoRow::hasRemoteInfo);
            addRowToDescriptor(descriptor, "Remote Function ID", Long.class, FunctionInfoRow::getRemoteFunctionIDValue);
            addRowToDescriptor(descriptor, "Remote Mangled Name", String.class, FunctionInfoRow::getRemoteMangledName);
            return descriptor;
        }
    }
}

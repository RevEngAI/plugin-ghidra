package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionselection;

import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionInfo;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.table.GhidraFilterTable;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import java.awt.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A reusable panel for selecting functions from a Ghidra program.
 * Contains a filterable table of functions with selection checkboxes,
 * toolbar buttons for bulk selection operations, and a summary label.
 */
public class FunctionSelectionPanel extends JPanel {
    private final FunctionSelectionTableModel tableModel;
    private final GhidraFilterTable<FunctionRowObject> filterTable;
    private final JLabel summaryLabel;

    public FunctionSelectionPanel(ServiceProvider serviceProvider) {
        super(new BorderLayout());

        tableModel = new FunctionSelectionTableModel(serviceProvider);
        filterTable = new GhidraFilterTable<>(tableModel);
        summaryLabel = new JLabel();

        buildInterface();

        // Listen for table changes to update the summary
        tableModel.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                updateSummaryLabel();
            }
        });
    }

    private void buildInterface() {
        setBorder(new TitledBorder("Function Selection"));

        // Toolbar with bulk selection buttons
        JPanel toolbarPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton selectAllButton = new JButton("Select All");
        selectAllButton.setName("selectAllButton");
        selectAllButton.addActionListener(e -> {
            tableModel.selectAll();
            updateSummaryLabel();
        });

        JButton deselectAllButton = new JButton("Deselect All");
        deselectAllButton.setName("deselectAllButton");
        deselectAllButton.addActionListener(e -> {
            tableModel.deselectAll();
            updateSummaryLabel();
        });

        JButton excludeUserDefinedButton = new JButton("Exclude User-Defined");
        excludeUserDefinedButton.setName("excludeUserDefinedButton");
        excludeUserDefinedButton.setToolTipText("Deselect functions with user-defined name or signature");
        excludeUserDefinedButton.addActionListener(e -> {
            tableModel.deselectUserDefined();
            updateSummaryLabel();
        });

        toolbarPanel.add(selectAllButton);
        toolbarPanel.add(deselectAllButton);
        toolbarPanel.add(excludeUserDefinedButton);

        // Summary label on the right side of the toolbar
        JPanel summaryPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        summaryPanel.add(summaryLabel);

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(toolbarPanel, BorderLayout.WEST);
        topPanel.add(summaryPanel, BorderLayout.EAST);

        add(topPanel, BorderLayout.NORTH);
        add(filterTable, BorderLayout.CENTER);

        updateSummaryLabel();
    }

    /**
     * Initialize the panel with functions from the given program.
     * External and thunk functions are excluded. By default, all functions are selected.
     */
    public void initForProgram(Program program) {
        tableModel.initForProgram(program);
        updateSummaryLabel();
    }

    /**
     * Returns the list of currently selected functions.
     */
    public List<Function> getSelectedFunctions() {
        return tableModel.getSelectedFunctions();
    }

    /**
     * Returns the count of selected functions.
     */
    public int getSelectedCount() {
        return tableModel.getSelectedCount();
    }

    /**
     * Returns the total number of functions.
     */
    public int getTotalFunctionCount() {
        return tableModel.getTotalCount();
    }

    /**
     * Returns the underlying table model.
     */
    public FunctionSelectionTableModel getTableModel() {
        return tableModel;
    }

    /**
     * Returns the underlying filter table component.
     */
    public GhidraFilterTable<FunctionRowObject> getFilterTable() {
        return filterTable;
    }

    /**
     * Cross-reference local functions with remote function info.
     * Functions without a remote match (or with a size mismatch) are disabled.
     */
    public void applyRemoteFunctionInfo(List<FunctionInfo> remoteFunctions) {
        // Build lookup by virtual address
        Map<Long, FunctionInfo> byAddress = new HashMap<>();
        for (FunctionInfo info : remoteFunctions) {
            byAddress.put(info.functionVirtualAddress(), info);
        }

        for (FunctionRowObject row : tableModel.getAllRows()) {
            // Reset state from any previous matching
            row.setEnabled(true);
            row.setRemoteFunctionInfo(null);

            long localAddr = row.getAddress().getOffset();
            FunctionInfo match = byAddress.get(localAddr);
            if (match != null && sizeMatches(row, match)) {
                row.setRemoteFunctionInfo(match);
                row.setSelected(true);
            } else {
                row.setEnabled(false);
            }
        }

        tableModel.fireTableDataChanged();
        updateSummaryLabel();
    }

    /**
     * Check if the local function size matches the remote function size,
     * using the same off-by-one tolerance as GhidraRevengService.
     */
    private static boolean sizeMatches(FunctionRowObject row, FunctionInfo info) {
        long localSize = row.getSize();
        int remoteSize = info.functionSize();
        return localSize == remoteSize || localSize - 1 == remoteSize;
    }

    private void updateSummaryLabel() {
        int selected = tableModel.getSelectedCount();
        int total = tableModel.getTotalCount();
        int enabled = tableModel.getEnabledCount();
        if (enabled < total) {
            summaryLabel.setText(String.format("%d of %d functions selected (%d matched remotely)", selected, total, enabled));
        } else {
            summaryLabel.setText(String.format("%d of %d functions selected", selected, total));
        }
    }
}

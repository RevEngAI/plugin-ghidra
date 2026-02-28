package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionselection;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static ai.reveng.toolkit.ghidra.Utils.addRowToDescriptor;

/**
 * Table model for displaying and selecting functions from a Ghidra program.
 * The model allows users to select which functions should be included in analysis.
 */
public class FunctionSelectionTableModel extends ThreadedTableModelStub<FunctionRowObject> {
    // Column index for editable Select column
    static final int SELECT = 0;

    private final List<FunctionRowObject> functionList = new ArrayList<>();
    private int tooSmallCount = 0;

    public FunctionSelectionTableModel(ServiceProvider serviceProvider) {
        super("Function Selection Table Model", serviceProvider);
    }

    /**
     * Initialize the model with functions from the given program.
     * External and thunk functions are excluded from the list entirely.
     * By default, all functions are selected.
     */
    public void initForProgram(Program program) {
        functionList.clear();
        tooSmallCount = 0;

        if (program != null) {
            program.getFunctionManager().getFunctions(true).forEach(function -> {
                if (!GhidraRevengService.isRelevantForAnalysis(function)) {
                    return;
                }
                var row = new FunctionRowObject(function, true);
                // If the function has zero instructions then it's not a valid function to send
                if (!program.getListing().getInstructions(function.getBody(), true).hasNext()) {
                    row.setEnabled(false);
                    tooSmallCount++;
                }
                functionList.add(row);
            });
        }
        reload();
    }

    @Override
    protected void doLoad(Accumulator<FunctionRowObject> accumulator, TaskMonitor monitor) {
        monitor.setMessage("Loading functions");
        monitor.setMaximum(functionList.size());
        int count = 0;
        for (FunctionRowObject row : functionList) {
            if (monitor.isCancelled()) {
                break;
            }
            accumulator.add(row);
            monitor.setProgress(++count);
        }
    }

    @Override
    protected TableColumnDescriptor<FunctionRowObject> createTableColumnDescriptor() {
        TableColumnDescriptor<FunctionRowObject> descriptor = new TableColumnDescriptor<>();
        addRowToDescriptor(descriptor, "Select", Boolean.class, FunctionRowObject::isSelected);
        addRowToDescriptor(descriptor, "Address", Address.class, FunctionRowObject::getAddress, 1, true);
        addRowToDescriptor(descriptor, "Namespace", false, Namespace.class, fo -> fo.getFunction().getParentNamespace());
        addRowToDescriptor(descriptor, "Name", String.class, FunctionRowObject::getName);
        addRowToDescriptor(descriptor, "Name Source", SourceType.class, fo -> fo.getFunction().getSymbol().getSource());
        addRowToDescriptor(descriptor, "Signature", false, FunctionSignature.class, fo -> fo.getFunction().getSignature());
        addRowToDescriptor(descriptor, "Signature Source", SourceType.class, fo -> fo.getFunction().getSignatureSource());
        addRowToDescriptor(descriptor, "Size", false, Long.class, FunctionRowObject::getSize);
        addRowToDescriptor(descriptor, "Remote Name", String.class, FunctionRowObject::getRemoteFunctionName);
        addRowToDescriptor(descriptor, "Remote Mangled Name", false, String.class, FunctionRowObject::getRemoteMangledName);
        addRowToDescriptor(descriptor, "Remote Function ID", false, Long.class, FunctionRowObject::getRemoteFunctionID);
        return descriptor;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        if (columnIndex != SELECT) {
            return false;
        }
        FunctionRowObject row = getRowObject(rowIndex);
        return row.isEnabled();
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == SELECT && aValue instanceof Boolean) {
            FunctionRowObject row = getRowObject(rowIndex);
            if (!row.isEnabled()) {
                return;
            }
            row.setSelected((Boolean) aValue);
            fireTableRowsUpdated(rowIndex, rowIndex);
        }
    }

    /**
     * Select all enabled functions in the table.
     */
    public void selectAll() {
        for (FunctionRowObject row : functionList) {
            if (row.isEnabled()) {
                row.setSelected(true);
            }
        }
        fireTableDataChanged();
    }

    /**
     * Deselect all functions in the table.
     */
    public void deselectAll() {
        for (FunctionRowObject row : functionList) {
            row.setSelected(false);
        }
        fireTableDataChanged();
    }

    /**
     * Select all non-thunk enabled functions.
     * Thunk and disabled functions will be deselected.
     * (External functions are not included in the list.)
     */
    public void selectNonThunk() {
        for (FunctionRowObject row : functionList) {
            if (row.isEnabled()) {
                row.setSelected(!row.isThunk());
            }
        }
        fireTableDataChanged();
    }

    /**
     * Deselect functions that have user-defined name or signature source.
     * These are functions where the user has already made manual changes.
     */
    public void deselectUserDefined() {
        for (FunctionRowObject row : functionList) {
            var func = row.getFunction();
            var nameSource = func.getSymbol().getSource();
            var sigSource = func.getSignatureSource();
            if (nameSource == SourceType.USER_DEFINED || sigSource == SourceType.USER_DEFINED) {
                row.setSelected(false);
            }
        }
        fireTableDataChanged();
    }

    /**
     * Returns the list of selected functions.
     */
    public List<Function> getSelectedFunctions() {
        List<Function> selected = new ArrayList<>();
        for (FunctionRowObject row : functionList) {
            if (row.isSelected()) {
                selected.add(row.getFunction());
            }
        }
        return selected;
    }

    /**
     * Returns the count of selected functions.
     */
    public int getSelectedCount() {
        int count = 0;
        for (FunctionRowObject row : functionList) {
            if (row.isSelected()) {
                count++;
            }
        }
        return count;
    }

    /**
     * Returns the total number of functions.
     */
    public int getTotalCount() {
        return functionList.size();
    }

    /**
     * Returns an unmodifiable view of all rows.
     */
    public List<FunctionRowObject> getAllRows() {
        return Collections.unmodifiableList(functionList);
    }

    /**
     * Returns the count of functions that are too small (1 byte or less) to be analyzed.
     */
    public int getTooSmallCount() {
        return tooSmallCount;
    }

    /**
     * Returns the count of enabled (matched remotely) rows.
     */
    public int getEnabledCount() {
        int count = 0;
        for (FunctionRowObject row : functionList) {
            if (row.isEnabled()) {
                count++;
            }
        }
        return count;
    }
}

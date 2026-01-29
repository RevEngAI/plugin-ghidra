package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionselection;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/**
 * Wrapper around a Ghidra {@link Function} with a mutable selection flag.
 * Used to display functions in a table where users can select which functions
 * to include in analysis.
 */
public class FunctionRowObject {
    private final Function function;
    private boolean selected;

    public FunctionRowObject(Function function, boolean selected) {
        this.function = function;
        this.selected = selected;
    }

    public Function getFunction() {
        return function;
    }

    public String getName() {
        return function.getName();
    }

    public Address getAddress() {
        return function.getEntryPoint();
    }

    /**
     * Returns the size of the function based on address count.
     */
    public long getSize() {
        return function.getBody().getNumAddresses();
    }

    public boolean isExternal() {
        return function.isExternal();
    }

    public boolean isThunk() {
        return function.isThunk();
    }

    /**
     * Returns a human-readable type string for the function.
     */
    public String getType() {
        if (isExternal()) {
            return "External";
        } else if (isThunk()) {
            return "Thunk";
        } else {
            return "Normal";
        }
    }

    public boolean isSelected() {
        return selected;
    }

    public void setSelected(boolean selected) {
        this.selected = selected;
    }
}

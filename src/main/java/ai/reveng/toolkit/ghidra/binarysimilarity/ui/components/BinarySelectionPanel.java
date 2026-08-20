package ai.reveng.toolkit.ghidra.binarysimilarity.ui.components;

import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.List;

/**
 * A component that allows multiple selection of binaries with autocomplete support.
 * This is a specialized version of ItemSelectionPanel for binaries.
 */
public class BinarySelectionPanel extends ItemSelectionPanel {

    public interface BinarySelectionListener {
        void onBinariesChanged(Set<SelectableItem> selectedBinaries);
    }

    /**
     * @param dynamicBinaryLoader Function that takes a query string and returns matching binaries
     * @param minimumQueryLength Minimum characters before triggering API calls (typically 2-3)
     */
    public BinarySelectionPanel(Function<String, CompletableFuture<List<SelectableItem>>> dynamicBinaryLoader, int minimumQueryLength) {
        super(dynamicBinaryLoader, minimumQueryLength, "Binary");
    }

    /**
     * Gets the IDs of currently selected binaries
     */
    public Set<Integer> getSelectedBinaryIds() {
        return getSelectedItemIds();
    }

    /**
     * Gets the names of currently selected binaries
     */
    public Set<String> getSelectedBinaryNames() {
        return getSelectedItemNames();
    }

    /**
     * Adds a listener for binary selection changes
     */
    public void addBinarySelectionListener(BinarySelectionListener listener) {
        addItemSelectionListener(selectedItems -> listener.onBinariesChanged(selectedItems));
    }
}

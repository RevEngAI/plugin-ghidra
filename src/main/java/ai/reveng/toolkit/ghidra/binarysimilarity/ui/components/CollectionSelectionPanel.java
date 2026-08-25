package ai.reveng.toolkit.ghidra.binarysimilarity.ui.components;

import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.List;

/**
 * A component that allows multiple selection of collections with autocomplete support.
 * This is a specialized version of ItemSelectionPanel for collections.
 */
public class CollectionSelectionPanel extends ItemSelectionPanel {

    public interface CollectionSelectionListener {
        void onCollectionsChanged(Set<SelectableItem> selectedCollections);
    }

    /**
     * @param dynamicCollectionLoader Function that takes a query string and returns matching collections
     * @param minimumQueryLength Minimum characters before triggering API calls (typically 2-3)
     */
    public CollectionSelectionPanel(Function<String, CompletableFuture<List<SelectableItem>>> dynamicCollectionLoader, int minimumQueryLength) {
        super(dynamicCollectionLoader, minimumQueryLength, "Collection");
    }

    /**
     * Gets the IDs of currently selected collections
     */
    public Set<Integer> getSelectedCollectionIds() {
        return getSelectedItemIds();
    }

    /**
     * Gets the names of currently selected collections
     */
    public Set<String> getSelectedCollectionNames() {
        return getSelectedItemNames();
    }

    /**
     * Adds a listener for collection selection changes
     */
    public void addCollectionSelectionListener(CollectionSelectionListener listener) {
        addItemSelectionListener(listener::onCollectionsChanged);
    }
}

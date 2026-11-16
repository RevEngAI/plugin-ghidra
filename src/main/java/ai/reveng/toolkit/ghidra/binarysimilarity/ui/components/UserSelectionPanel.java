package ai.reveng.toolkit.ghidra.binarysimilarity.ui.components;

import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.List;

/**
 * A component that allows multiple selection of users with autocomplete support.
 * This is a specialized version of ItemSelectionPanel for users.
 */
public class UserSelectionPanel extends ItemSelectionPanel {

    /**
     * @param dynamicUserLoader Function that takes a query string and returns matching users
     * @param minimumQueryLength Minimum characters before triggering API calls (the users endpoint needs 3)
     */
    public UserSelectionPanel(Function<String, CompletableFuture<List<SelectableItem>>> dynamicUserLoader, int minimumQueryLength) {
        super(dynamicUserLoader, minimumQueryLength, "User");
    }

    /**
     * Gets the IDs of currently selected users
     */
    public Set<Integer> getSelectedUserIds() {
        return getSelectedItemIds();
    }

    /**
     * Gets the names of currently selected users
     */
    public Set<String> getSelectedUserNames() {
        return getSelectedItemNames();
    }
}

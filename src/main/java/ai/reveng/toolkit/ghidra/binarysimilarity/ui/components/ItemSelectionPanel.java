package ai.reveng.toolkit.ghidra.binarysimilarity.ui.components;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A generic component that allows multiple selection of items with autocomplete support.
 */
public class ItemSelectionPanel extends JPanel {
    private SimpleAutocompleteField autocompleteField;
    private JPanel selectedItemsPanel;
    private final Set<SelectableItem> selectedItems;
    private final List<ItemSelectionListener> listeners;
    private Function<String, CompletableFuture<List<SelectableItem>>> dynamicItemLoader;
    private String panelTitle;

    public interface ItemSelectionListener {
        void onItemsChanged(Set<SelectableItem> selectedItems);
    }

    /**
     * @param dynamicItemLoader Function that takes a query string and returns matching items
     * @param minimumQueryLength Minimum characters before triggering API calls (typically 2-3)
     * @param title The title to display on the panel border
     */
    public ItemSelectionPanel(Function<String, CompletableFuture<List<SelectableItem>>> dynamicItemLoader, int minimumQueryLength, String title) {
        this.selectedItems = new HashSet<>();
        this.listeners = new ArrayList<>();
        this.dynamicItemLoader = dynamicItemLoader;
        this.panelTitle = title;

        initializeUI(minimumQueryLength);
    }

    private void initializeUI(int minimumQueryLength) {
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder(panelTitle));

        // Create top panel with autocomplete
        JPanel inputPanel = createInputPanel(minimumQueryLength);
        add(inputPanel, BorderLayout.NORTH);

        // Create panel for selected items (tags) without any border
        selectedItemsPanel = new JPanel();
        selectedItemsPanel.setLayout(new WrapLayout(FlowLayout.LEFT));

        JScrollPane scrollPane = new JScrollPane(selectedItemsPanel);
        scrollPane.setPreferredSize(new Dimension(0, 60));
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setBorder(null); // Remove any border from the scroll pane

        add(scrollPane, BorderLayout.CENTER);
    }

    private JPanel createInputPanel(int minimumQueryLength) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Create the autocomplete field without label or add button
        // Convert SelectableItem results to strings for autocomplete display
        Function<String, CompletableFuture<List<String>>> stringItemLoader = query ->
            dynamicItemLoader.apply(query).thenApply(items ->
                items.stream().map(SelectableItem::getName).collect(Collectors.toList()));

        autocompleteField = new SimpleAutocompleteField(stringItemLoader, minimumQueryLength);

        // Handle selection from autocomplete
        autocompleteField.addActionListener(e -> addSelectedItem());

        panel.add(autocompleteField, BorderLayout.CENTER);

        return panel;
    }

    private void addSelectedItem() {
        String selectedName = autocompleteField.getText();
        if (selectedName != null && !selectedName.trim().isEmpty()) {
            String trimmedName = selectedName.trim();

            // Find the SelectableItem that matches this name
            dynamicItemLoader.apply(trimmedName).thenAccept(items -> {
                SelectableItem matchingItem = items.stream()
                    .filter(item -> item.getName().equals(trimmedName))
                    .findFirst()
                    .orElse(null);

                if (matchingItem != null && selectedItems.add(matchingItem)) {
                    SwingUtilities.invokeLater(() -> {
                        addItemTag(matchingItem);
                        autocompleteField.clear(); // Clear input
                        notifyListeners();
                    });
                }
            });
        }
    }

    private void addItemTag(SelectableItem item) {
        JPanel tagPanel = new JPanel(new BorderLayout());
        tagPanel.setBorder(createTagBorder());
        tagPanel.setBackground(new Color(230, 240, 250));

        JLabel label = new JLabel(item.getName()); // Display name to user
        label.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));

        JButton removeButton = new JButton("×");
        removeButton.setPreferredSize(new Dimension(20, 20));
        removeButton.setFont(removeButton.getFont().deriveFont(Font.BOLD, 12f));
        removeButton.setMargin(new Insets(0, 0, 0, 0));
        removeButton.setBackground(Color.WHITE);
        removeButton.setBorder(BorderFactory.createRaisedBevelBorder());
        removeButton.addActionListener(e -> removeItem(item, tagPanel));

        tagPanel.add(label, BorderLayout.CENTER);
        tagPanel.add(removeButton, BorderLayout.EAST);

        selectedItemsPanel.add(tagPanel);
        selectedItemsPanel.revalidate();
        selectedItemsPanel.repaint();
    }

    private Border createTagBorder() {
        return BorderFactory.createCompoundBorder(
                BorderFactory.createRaisedBevelBorder(),
                BorderFactory.createEmptyBorder(2, 2, 2, 2)
        );
    }

    private void removeItem(SelectableItem item, JPanel tagPanel) {
        selectedItems.remove(item);
        selectedItemsPanel.remove(tagPanel);
        selectedItemsPanel.revalidate();
        selectedItemsPanel.repaint();
        notifyListeners();
    }

    /**
     * Gets the currently selected items
     */
    public Set<SelectableItem> getSelectedItems() {
        return new HashSet<>(selectedItems);
    }

    /**
     * Gets the IDs of currently selected items
     */
    public Set<Integer> getSelectedItemIds() {
        return selectedItems.stream()
            .map(SelectableItem::getId)
            .collect(Collectors.toSet());
    }

    /**
     * Gets the names of currently selected items
     */
    public Set<String> getSelectedItemNames() {
        return selectedItems.stream()
            .map(SelectableItem::getName)
            .collect(Collectors.toSet());
    }

    /**
     * Sets the selected items
     */
    public void setSelectedItems(Set<SelectableItem> items) {
        // Clear existing selections
        selectedItems.clear();
        selectedItemsPanel.removeAll();

        // Add new selections
        for (SelectableItem item : items) {
            selectedItems.add(item);
            addItemTag(item);
        }

        selectedItemsPanel.revalidate();
        selectedItemsPanel.repaint();
        notifyListeners();
    }

    /**
     * Adds a listener for item selection changes
     */
    public void addItemSelectionListener(ItemSelectionListener listener) {
        listeners.add(listener);
    }

    private void notifyListeners() {
        Set<SelectableItem> items = getSelectedItems();
        for (ItemSelectionListener listener : listeners) {
            listener.onItemsChanged(items);
        }
    }

    /**
     * Custom FlowLayout that wraps to next line
     */
    private static class WrapLayout extends FlowLayout {
        public WrapLayout(int align) {
            super(align);
        }

        @Override
        public Dimension preferredLayoutSize(Container target) {
            return layoutSize(target, true);
        }

        @Override
        public Dimension minimumLayoutSize(Container target) {
            Dimension minimum = layoutSize(target, false);
            minimum.width -= (getHgap() + 1);
            return minimum;
        }

        private Dimension layoutSize(Container target, boolean preferred) {
            synchronized (target.getTreeLock()) {
                Container container = target;

                while (container.getSize().width == 0 && container.getParent() != null) {
                    container = container.getParent();
                }
                int targetWidth = container.getSize().width;

                if (targetWidth == 0) {
                    targetWidth = Integer.MAX_VALUE;
                }

                int hgap = getHgap();
                int vgap = getVgap();
                Insets insets = target.getInsets();
                int horizontalInsetsAndGap = insets.left + insets.right + (hgap * 2);
                int maxWidth = targetWidth - horizontalInsetsAndGap;

                Dimension dim = new Dimension(0, 0);
                int rowWidth = 0;
                int rowHeight = 0;

                int nmembers = target.getComponentCount();

                for (int i = 0; i < nmembers; i++) {
                    Component m = target.getComponent(i);

                    if (m.isVisible()) {
                        Dimension d = preferred ? m.getPreferredSize() : m.getMinimumSize();

                        if (rowWidth + d.width > maxWidth) {
                            addRow(dim, rowWidth, rowHeight);
                            rowWidth = d.width;
                            rowHeight = d.height;
                        } else {
                            rowWidth += d.width + hgap;
                            rowHeight = Math.max(rowHeight, d.height);
                        }
                    }
                }

                addRow(dim, rowWidth, rowHeight);

                dim.width = Math.max(dim.width, maxWidth);
                dim.height += insets.top + insets.bottom + vgap * 2;

                Container scrollPane = SwingUtilities.getAncestorOfClass(JScrollPane.class, target);
                if (scrollPane != null && target.isValid()) {
                    dim.width -= (hgap + 1);
                }

                return dim;
            }
        }

        private void addRow(Dimension dim, int rowWidth, int rowHeight) {
            dim.width = Math.max(dim.width, rowWidth);

            if (dim.height > 0) {
                dim.height += getVgap();
            }

            dim.height += rowHeight;
        }
    }
}

package ai.reveng.toolkit.ghidra.binarysimilarity.ui.components;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

/**
 * A simple and reliable autocomplete text field with dropdown suggestions.
 * Uses dynamic API-based collection fetching only.
 */
public class SimpleAutocompleteField extends JPanel {
    private JTextField textField;
    private JList<String> suggestionsList;
    private JScrollPane suggestionsScrollPane;
    private JPopupMenu suggestionsPopup;
    private DefaultListModel<String> listModel;

    private Function<String, CompletableFuture<List<String>>> dynamicLoader;
    private int minimumQueryLength = 2;
    private Timer searchTimer;
    private final int searchDelay = 300;

    /**
     * Constructor for dynamic API-based autocomplete
     */
    public SimpleAutocompleteField(Function<String, CompletableFuture<List<String>>> dynamicLoader, int minimumQueryLength) {
        this.dynamicLoader = dynamicLoader;
        this.minimumQueryLength = minimumQueryLength;

        initializeComponents();
        setupEventListeners();
    }

    private void initializeComponents() {
        setLayout(new BorderLayout());

        // Create text field
        textField = new JTextField();
        textField.setPreferredSize(new Dimension(250, textField.getPreferredSize().height));
        add(textField, BorderLayout.CENTER);

        // Create suggestions list
        listModel = new DefaultListModel<>();
        suggestionsList = new JList<>(listModel);
        suggestionsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        suggestionsList.setVisibleRowCount(8);

        // Create popup for suggestions
        suggestionsScrollPane = new JScrollPane(suggestionsList);
        suggestionsScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        suggestionsScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

        suggestionsPopup = new JPopupMenu();
        suggestionsPopup.setLayout(new BorderLayout());
        suggestionsPopup.add(suggestionsScrollPane, BorderLayout.CENTER);
        suggestionsPopup.setFocusable(false);

        // Setup timer for dynamic search
        searchTimer = new Timer(searchDelay, e -> performDynamicSearch());
        searchTimer.setRepeats(false);
    }

    private void setupEventListeners() {
        // Document listener for text changes
        textField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                handleTextChange();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                handleTextChange();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                handleTextChange();
            }
        });

        // Key listener for navigation and selection
        textField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (suggestionsPopup.isVisible()) {
                    switch (e.getKeyCode()) {
                        case KeyEvent.VK_DOWN:
                            if (suggestionsList.getSelectedIndex() < listModel.getSize() - 1) {
                                suggestionsList.setSelectedIndex(suggestionsList.getSelectedIndex() + 1);
                            }
                            e.consume();
                            break;
                        case KeyEvent.VK_UP:
                            if (suggestionsList.getSelectedIndex() > 0) {
                                suggestionsList.setSelectedIndex(suggestionsList.getSelectedIndex() - 1);
                            }
                            e.consume();
                            break;
                        case KeyEvent.VK_ENTER:
                            selectCurrentSuggestion();
                            e.consume();
                            break;
                        case KeyEvent.VK_ESCAPE:
                            hideSuggestions();
                            e.consume();
                            break;
                    }
                }
            }
        });

        // Mouse listener for list selection
        suggestionsList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 1) {
                    selectCurrentSuggestion();
                }
            }
        });

        // Focus listener to hide popup when text field loses focus
        textField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                // Hide popup after a short delay to allow for mouse clicks
                SwingUtilities.invokeLater(() -> {
                    if (!suggestionsPopup.isAncestorOf(e.getOppositeComponent())) {
                        hideSuggestions();
                    }
                });
            }
        });
    }

    private void handleTextChange() {
        String text = textField.getText().trim();

        // Dynamic mode - use API
        if (text.length() >= minimumQueryLength) {
            if (searchTimer != null) {
                searchTimer.restart();
            }
        } else {
            hideSuggestions();
        }
    }

    private void performDynamicSearch() {
        String query = textField.getText().trim();

        if (query.length() < minimumQueryLength) {
            hideSuggestions();
            return;
        }

        // Show loading
        SwingUtilities.invokeLater(() -> {
            listModel.clear();
            listModel.addElement("Loading...");
            showSuggestions();
        });

        // Perform search
        dynamicLoader.apply(query)
            .thenAccept(results -> SwingUtilities.invokeLater(() -> {
                listModel.clear();
                if (results.isEmpty()) {
                    listModel.addElement("No results found");
                } else {
                    for (String result : results) {
                        listModel.addElement(result);
                    }
                    suggestionsList.setSelectedIndex(0);
                }
                showSuggestions();
            }))
            .exceptionally(throwable -> {
                SwingUtilities.invokeLater(() -> {
                    listModel.clear();
                    listModel.addElement("Error loading results");
                    showSuggestions();
                });
                return null;
            });
    }

    private void selectCurrentSuggestion() {
        String selected = suggestionsList.getSelectedValue();
        if (selected != null &&
            !selected.equals("Loading...") &&
            !selected.equals("No results found") &&
            !selected.equals("Error loading results")) {

            textField.setText(selected);
            hideSuggestions();

            // Notify listeners
            fireActionPerformed();
        }
    }

    private void showSuggestions() {
        if (listModel.getSize() > 0) {
            suggestionsPopup.show(textField, 0, textField.getHeight());
            suggestionsScrollPane.setPreferredSize(new Dimension(
                textField.getWidth(),
                Math.min(200, suggestionsList.getPreferredSize().height + 10)
            ));
            suggestionsPopup.pack();
        }
    }

    private void hideSuggestions() {
        suggestionsPopup.setVisible(false);
    }

    public String getText() {
        return textField.getText();
    }

    public void setText(String text) {
        textField.setText(text);
    }

    public void clear() {
        textField.setText("");
        hideSuggestions();
    }

    // Action listener support for when user selects an item
    public void addActionListener(ActionListener listener) {
        listenerList.add(ActionListener.class, listener);
    }

    protected void fireActionPerformed() {
        ActionEvent event = new ActionEvent(this, ActionEvent.ACTION_PERFORMED, getText());
        for (ActionListener listener : listenerList.getListeners(ActionListener.class)) {
            listener.actionPerformed(event);
        }
    }
}

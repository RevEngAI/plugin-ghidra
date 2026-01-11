package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching;

import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.binarysimilarity.cmds.ApplyMatchCmd;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.CollectionSelectionPanel;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.BinarySelectionPanel;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.SelectableItem;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import com.google.common.collect.BiMap;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitorComponent;
import ghidra.util.Msg;
import resources.ResourceManager;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin.REVENG_AI_NAMESPACE;

public abstract class AbstractFunctionMatchingDialog extends RevEngDialogComponentProvider {
    protected final GhidraRevengService revengService;
    protected final GhidraRevengService.AnalysedProgram analyzedProgram;

    // UI Components
    protected JPanel contentPanel;
    protected JTable resultsTable;
    protected JScrollPane resultsScrollPane;
    protected CollectionSelectionPanel collectionSelector;
    protected BinarySelectionPanel binarySelector;
    protected JTextField functionFilterField;
    protected JSlider thresholdSlider;
    protected JLabel thresholdValueLabel;
    protected JCheckBox debugSymbolsCheckBox;
    protected JCheckBox userSubmittedDebugSymbolsCheckBox;
    protected JLabel statusLabel;
    protected JTextArea errorArea;
    protected JScrollPane errorScrollPane;
    protected final TaskMonitorComponent taskMonitorComponent;
    protected Timer pollTimer;
    protected JPanel renameButtonsPanel;

    // Data
    protected Basic analysisBasicInfo;
    protected FunctionMatchingResponse functionMatchingResponse;
    protected final List<GhidraFunctionMatchWithSignature> functionMatchResults;
    protected final List<GhidraFunctionMatchWithSignature> filteredFunctionMatchResults;

    // Polling configuration
    protected static final int POLL_INTERVAL_MS = 2000; // Poll every 2 seconds

//    /// Inner class to hold function match results
//    /// @deprecated {@link ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch}
//    public record FunctionMatchResult(
//            String virtualAddress,
//            String functionName,
//            String bestMatchName,
//            String bestMatchMangledName,
//            String similarity,
//            String confidence,
//            String matchedHash,
//            String binary,
//            Long matcherFunctionId
//    ) {
//        // Constructor for function-level dialog (without virtual address and function name)
//        public FunctionMatchResult(String bestMatchName, String bestMatchMangledName, String similarity,
//                                   String confidence, String matchedHash, String binary, Long matcherFunctionId) {
//            this("", "", bestMatchName, bestMatchMangledName, similarity, confidence, matchedHash, binary, matcherFunctionId);
//        }
//    }

    protected AbstractFunctionMatchingDialog(String title, Boolean isModal, GhidraRevengService revengService,
                                           GhidraRevengService.AnalysedProgram analyzedProgram) {
        super(title, isModal);
        this.revengService = revengService;
        this.analyzedProgram = analyzedProgram;
        this.taskMonitorComponent = new TaskMonitorComponent(false, true);
        this.functionMatchResults = new ArrayList<>();
        this.filteredFunctionMatchResults = new ArrayList<>();

        try {
            this.analysisBasicInfo = revengService.getBasicDetailsForAnalysis(analyzedProgram.analysisID());
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null,
                    "Failed to fetch analysis details: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            close();
            return;
        }

        // Initialize UI
        addDismissButton();
        addWorkPanel(buildMainPanel());

        // Set dialog size to be wider
        setPreferredSize(1000, 800);

        // Don't start function matching automatically - wait for user to click Match button
        statusLabel.setText("Ready - adjust filters and click 'Match Functions' to begin search");
        taskMonitorComponent.setVisible(false);
    }

    protected void startFunctionMatching() {
        // Show initial status
        statusLabel.setText("Starting function matching...");
        taskMonitorComponent.initialize(100);

        // Start polling timer
        pollTimer = new Timer(POLL_INTERVAL_MS, e -> pollFunctionMatchingStatus());
        pollTimer.start();

        // Make initial call
        pollFunctionMatchingStatus();
    }

    protected abstract void pollFunctionMatchingStatus();

    protected void processFunctionMatchingResults(FunctionMatchingResponse response) {
        functionMatchResults.clear();
        List<GhidraFunctionMatch> matches = new ArrayList<>();
        final BiMap<TypedApiInterface.FunctionID, Function> functionMap = analyzedProgram.getFunctionMap();

        response.getMatches().forEach(matchResult -> {
            // Retrieve the local function name
            var funcId = new TypedApiInterface.FunctionID(matchResult.getFunctionId());
            Function localFunction = functionMap.get(funcId);
            if (localFunction == null) {
                // If we can't find the local function, skip this match (boundaries do not match the remote ones)
                return;
            }
            // Process each matched function in this result
            matchResult.getMatchedFunctions().forEach(match -> {
                // Create function match result using the abstract method
                FunctionMatch result = FunctionMatch.fromMatchedFunctionAPIType(match, funcId);
                GhidraFunctionMatch ghidraResult = new GhidraFunctionMatch(localFunction, result);
//                FunctionMatch result = createFunctionMatchResult(localFunction, match, funcId);
                matches.add(ghidraResult);
            });
        });

        // Get the type info for all matches
        var ghidraResultsWithSignatures = revengService.getSignatures(matches);

        // For all matches we got, create a GhidraFunctionMatchWithSignature object (signature can be null!)
        for (GhidraFunctionMatch match : matches) {
            var sig = ghidraResultsWithSignatures.get(match);
            functionMatchResults.add(new GhidraFunctionMatchWithSignature(match.function(), match.functionMatch(), sig));
        }

        // Apply any existing function filter after getting results
        onFunctionFilterChanged();

        // Update results table after processing is complete
        SwingUtilities.invokeLater(this::updateResultsTable);
    }


    protected void updateUI() {
        if (functionMatchingResponse == null) return;

        // Update progress bar
        if (functionMatchingResponse.getProgress() != null) {
            taskMonitorComponent.setProgress(functionMatchingResponse.getProgress());
            taskMonitorComponent.setMessage(functionMatchingResponse.getProgress() + "%");
        }

        // Update status
        if (functionMatchingResponse.getStatus() != null) {
            statusLabel.setText("Status: " + getFriendlyStatusMessage(functionMatchingResponse.getStatus()));
        }

        // Handle error message - dynamically add/remove error panel
        if (functionMatchingResponse.getErrorMessage() != null && !functionMatchingResponse.getErrorMessage().isEmpty()) {
            showError(functionMatchingResponse.getErrorMessage());
        } else {
            hideError();
        }

        // Update results table
        updateResultsTable();
    }

    protected void updateResultsTable() {
        // Determine which results to show based on whether we have an active filter
        String filterText = functionFilterField != null ? functionFilterField.getText().trim() : "";
        List<GhidraFunctionMatchWithSignature> resultsToShow;

        if (filterText.isEmpty()) {
            // No filter text, show all results
            resultsToShow = functionMatchResults;
        } else {
            // Filter text exists, show filtered results (even if empty)
            resultsToShow = filteredFunctionMatchResults;
        }

        DefaultTableModel model = new DefaultTableModel(getTableColumnNames(), 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                //all cells false
                return false;
            }
        };
        for (GhidraFunctionMatchWithSignature result : resultsToShow) {
            model.addRow(getTableRowData(result));
        }
        resultsTable.setModel(model);

        // Update the dynamic title with filtered count
        int totalMatchCount = functionMatchResults.size();
        int displayedMatchCount = resultsToShow.size();
        String title;
        if (filterText.isEmpty()) {
            title = getTableTitle() + " (" + totalMatchCount + " matches found)";
        } else {
            title = getTableTitle() + " (" + displayedMatchCount + " of " + totalMatchCount + " matches shown)";
        }
        resultsScrollPane.setBorder(BorderFactory.createTitledBorder(title));

        // Show/hide rename buttons based on whether we have results
        boolean hasResults = displayedMatchCount > 0;
        renameButtonsPanel.setVisible(hasResults);

        // Enable table selection model for rename operations
        if (hasResults) {
            resultsTable.setSelectionMode(getTableSelectionMode());
            resultsTable.setRowSelectionAllowed(true);
        }

        // Fix table header appearance
        resultsTable.getTableHeader().setOpaque(false);
        resultsTable.getTableHeader().setBackground(UIManager.getColor("TableHeader.background"));
        resultsTable.getTableHeader().setForeground(UIManager.getColor("TableHeader.foreground"));

        // Configure table columns
        configureTableColumns();
    }

    protected abstract String[] getTableColumnNames();
    protected abstract Object[] getTableRowData(GhidraFunctionMatchWithSignature result);
    protected abstract String getTableTitle();
    protected abstract int getTableSelectionMode();
    protected abstract void configureTableColumns();

    /**
     * Custom cell renderer that colors percentage values based on their range
     */
    protected static class PercentageColorCellRenderer extends javax.swing.table.DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (value instanceof String percentageStr) {
                Color textColor = getColorForPercentage(percentageStr);

                if (!isSelected) {
                    // Set text color based on percentage value
                    c.setForeground(textColor);
                    // Keep default background color
                    c.setBackground(table.getBackground());
                } else {
                    // Keep default selection colors when selected
                    c.setBackground(table.getSelectionBackground());
                    c.setForeground(table.getSelectionForeground());
                }
            }

            return c;
        }

        /**
         * Get the text color based on percentage value
         */
        private Color getColorForPercentage(String percentageStr) {
            try {
                // Remove the % symbol and parse as double
                String numStr = percentageStr.replace("%", "").trim();
                if (numStr.equals("N/A")) {
                    return Color.BLACK; // Default color for N/A values
                }

                double percentage = Double.parseDouble(numStr);

                if (percentage >= 0 && percentage <= 1) {
                    return new Color(255, 0, 0); // Red
                } else if (percentage > 1 && percentage <= 50) {
                    return new Color(128, 0, 128); // Purple
                } else if (percentage > 50 && percentage <= 70) {
                    return new Color(255, 165, 0); // Orange
                } else if (percentage > 70 && percentage <= 90) {
                    return new Color(200, 140, 0); // Darker yellow for better visibility
                } else if (percentage > 90 && percentage <= 95) {
                    return new Color(34, 139, 34); // Forest Green
                } else if (percentage > 95 && percentage <= 100) {
                    return new Color(0, 100, 0); // Dark Green
                } else {
                    return Color.BLACK; // Default for out-of-range values
                }
            } catch (NumberFormatException e) {
                return Color.BLACK; // Default color for unparseable values
            }
        }
    }

    /**
     * Parse a percentage string (e.g., "95.50%") into a double value for sorting
     */
    protected Double parsePercentage(String percentageStr) {
        if (percentageStr == null || percentageStr.equals("N/A")) {
            return -1.0; // Sort N/A values to the bottom
        }
        try {
            return Double.parseDouble(percentageStr.replace("%", "").trim());
        } catch (NumberFormatException e) {
            return -1.0; // Sort unparseable values to the bottom
        }
    }

    /**
     * Configure custom comparators for percentage columns to enable proper numerical sorting
     * @param similarityColumnIndex the index of the similarity column
     * @param confidenceColumnIndex the index of the confidence column
     */
    protected void configurePercentageColumnSorting(int similarityColumnIndex, int confidenceColumnIndex) {
        if (resultsTable.getRowSorter() != null) {
            javax.swing.table.TableRowSorter<?> sorter = (javax.swing.table.TableRowSorter<?>) resultsTable.getRowSorter();
            java.util.Comparator<String> percentageComparator = (s1, s2) -> {
                Double val1 = parsePercentage(s1);
                Double val2 = parsePercentage(s2);
                return val1.compareTo(val2);
            };
            sorter.setComparator(similarityColumnIndex, percentageComparator);
            sorter.setComparator(confidenceColumnIndex, percentageComparator);
        }
    }

    /**
     * Convert API status values to user-friendly messages
     */
    protected String getFriendlyStatusMessage(String apiStatus) {
        if (apiStatus == null) {
            return "Unknown";
        }

        return switch (apiStatus) {
            case "STARTED" -> "started function matching...";
            case "IN_PROGRESS" -> "running function matching...";
            case "COMPLETED" -> "completed function matching";
            case "ERROR", "NOT_FOUND" -> "function matching failed";
            case "CANCELLED" -> "function matching was cancelled";
            default -> apiStatus; // Fallback to original if unknown
        };
    }

    protected void handleError(String message) {
        statusLabel.setText("An error occurred, press 'Match Functions' again to retry");
        showError(message);
        taskMonitorComponent.setMessage("Error");
    }

    protected void showError(String message) {
        errorArea.setText(message);
        // Only add the error panel if it's not already added
        if (errorScrollPane.getParent() == null) {
            contentPanel.add(errorScrollPane, BorderLayout.SOUTH);
            contentPanel.revalidate();
            contentPanel.repaint();
        }
    }

    protected void hideError() {
        // Only remove the error panel if it's currently added
        if (errorScrollPane.getParent() != null) {
            contentPanel.remove(errorScrollPane);
            contentPanel.revalidate();
            contentPanel.repaint();
        }
    }

    protected void stopPolling() {
        if (pollTimer != null) {
            pollTimer.stop();
            pollTimer = null;
        }
    }

    protected JComponent buildMainPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // Create title panel
        JPanel titlePanel = createTitlePanel(getDialogDescription());
        panel.add(titlePanel, BorderLayout.NORTH);

        // Create content panel
        contentPanel = new JPanel(new BorderLayout());

        // Create top panel with progress and filters
        JPanel topPanel = new JPanel(new BorderLayout());

        // Progress panel at the top
        JPanel progressPanel = createProgressPanel();
        topPanel.add(progressPanel, BorderLayout.NORTH);

        // Create filter panel
        JPanel filterPanel = createFilterPanel();
        topPanel.add(filterPanel, BorderLayout.CENTER);
        contentPanel.add(topPanel, BorderLayout.NORTH);

        // Match button panel and function filter
        JPanel buttonAndFilterPanel = createButtonAndFilterPanel();

        // Create a center panel to hold the button and results
        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.add(buttonAndFilterPanel, BorderLayout.NORTH);

        // Initialize error area but don't add it to the panel yet
        errorArea = new JTextArea(5, 60);
        errorArea.setLineWrap(true);
        errorArea.setWrapStyleWord(true);
        errorArea.setEditable(false);
        errorArea.setBackground(Color.PINK);
        errorArea.setBorder(BorderFactory.createTitledBorder("Error Details"));
        errorScrollPane = new JScrollPane(errorArea);

        // Results table with rename buttons container
        JPanel resultsContainer = createResultsContainer();
        centerPanel.add(resultsContainer, BorderLayout.CENTER);

        contentPanel.add(centerPanel, BorderLayout.CENTER);
        panel.add(contentPanel, BorderLayout.CENTER);

        return panel;
    }

    protected abstract String getDialogDescription();

    protected JPanel createFilterPanel() {
        JPanel filterPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weighty = 0;

        // Row 0, Col 0: Collection selector (50% width)
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        gbc.weightx = 0.5;
        gbc.insets = new Insets(10, 0, 10, 10);
        filterPanel.add(createCollectionSelectorPanel(), gbc);

        // Row 0, Col 1: Binary selector (50% width)
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.weightx = 0.5;
        gbc.insets = new Insets(10, 0, 10, 0);
        filterPanel.add(createBinarySelectorPanel(), gbc);

        // Row 1, Col 0: Threshold panel (50% width)
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0.5;
        gbc.insets = new Insets(0, 0, 0, 10);
        filterPanel.add(createThresholdPanel(), gbc);

        // Row 1, Col 1: Debug symbols toggle (50% width)
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.weightx = 0.5;
        gbc.insets = new Insets(0, 0, 0, 0);
        filterPanel.add(createDebugSymbolsPanel(), gbc);

        return filterPanel;
    }

    protected JPanel createButtonAndFilterPanel() {
        // Match button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton matchButton = new JButton("Match Functions");

        // Add magnifying glass icon to the button
        try {
            Icon icon = ResourceManager.loadImage("images/magnifier.png");
            matchButton.setIcon(icon);
        } catch (Exception e) {
            // If icon loading fails, button will just show text without icon
        }

        matchButton.addActionListener(e -> onMatchButtonClicked());
        buttonPanel.add(matchButton);


        // Function filter panel
        JPanel functionFilterPanel = createFunctionFilterPanel();

        // Create a combined panel for button and function filter
        JPanel buttonAndFilterPanel = new JPanel(new BorderLayout());
        buttonAndFilterPanel.add(buttonPanel, BorderLayout.NORTH);
        buttonAndFilterPanel.add(functionFilterPanel, BorderLayout.CENTER);

        return buttonAndFilterPanel;
    }

    protected JPanel createResultsContainer() {
        JPanel resultsContainer = new JPanel(new BorderLayout());

        // Results table
        resultsTable = new JTable();
        resultsTable.setAutoCreateRowSorter(true);
        resultsScrollPane = new JScrollPane(resultsTable);
        resultsScrollPane.setBorder(BorderFactory.createTitledBorder("Function Matching Results"));
        resultsContainer.add(resultsScrollPane, BorderLayout.CENTER);

        // Rename buttons panel
        renameButtonsPanel = createRenameButtonsPanel();
        renameButtonsPanel.setVisible(false);
        resultsContainer.add(renameButtonsPanel, BorderLayout.SOUTH);

        return resultsContainer;
    }

    protected JPanel createRenameButtonsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        JButton renameAllButton = new JButton("Rename All");
        renameAllButton.addActionListener(e -> onRenameAllButtonClicked());
        panel.add(renameAllButton);

        JButton renameSelectedButton = new JButton("Rename Selected");
        renameSelectedButton.addActionListener(e -> onRenameSelectedButtonClicked());
        panel.add(renameSelectedButton);

        return panel;
    }

    protected JPanel createProgressPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 0, 10);
        gbc.anchor = GridBagConstraints.WEST;

        // Progress bar
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(taskMonitorComponent, gbc);

        // Status label
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        statusLabel = new JLabel("Initializing...");
        panel.add(statusLabel, gbc);

        return panel;
    }

    protected JPanel createCollectionSelectorPanel() {
        collectionSelector = new CollectionSelectionPanel(
                query -> revengService.searchCollectionsWithIds(query, analysisBasicInfo.getModelName()),
                3
        );
        collectionSelector.addCollectionSelectionListener(this::onCollectionSelectionChanged);

        return collectionSelector;
    }

    protected JPanel createBinarySelectorPanel() {
        binarySelector = new BinarySelectionPanel(
                query -> revengService.searchBinariesWithIds(query, analysisBasicInfo.getModelName()),
                3
        );
        binarySelector.addBinarySelectionListener(this::onBinarySelectionChanged);

        return binarySelector;
    }

    protected JPanel createThresholdPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Minimum similarity"));

        thresholdSlider = new JSlider(0, 100, 70);
        thresholdSlider.setMajorTickSpacing(25);
        thresholdSlider.setMinorTickSpacing(5);
        thresholdSlider.setPaintTicks(true);
        thresholdSlider.setPaintLabels(true);

        thresholdValueLabel = new JLabel("70%", SwingConstants.CENTER);
        thresholdValueLabel.setFont(thresholdValueLabel.getFont().deriveFont(Font.BOLD, 14f));

        thresholdSlider.addChangeListener(e -> {
            int value = thresholdSlider.getValue();
            thresholdValueLabel.setText(value + "%");
            if (!thresholdSlider.getValueIsAdjusting()) {
                onThresholdChanged(value);
            }
        });

        JPanel sliderPanel = new JPanel(new BorderLayout());
        sliderPanel.add(thresholdSlider, BorderLayout.CENTER);
        sliderPanel.add(thresholdValueLabel, BorderLayout.EAST);

        panel.add(sliderPanel, BorderLayout.CENTER);

        return panel;
    }

    protected JPanel createDebugSymbolsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Debug symbols"));

        JPanel checkboxPanel = new JPanel();
        checkboxPanel.setLayout(new BoxLayout(checkboxPanel, BoxLayout.Y_AXIS));
        checkboxPanel.setPreferredSize(new Dimension(0, 52));
        checkboxPanel.setMinimumSize(new Dimension(0, 52));

        debugSymbolsCheckBox = new JCheckBox("Only include functions with debug symbols", false);
        debugSymbolsCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        debugSymbolsCheckBox.addActionListener(e -> {
            boolean selected = debugSymbolsCheckBox.isSelected();
            userSubmittedDebugSymbolsCheckBox.setVisible(selected);
            onDebugSymbolsChanged(selected);
        });

        userSubmittedDebugSymbolsCheckBox = new JCheckBox("Include user submitted debug symbols", false);
        userSubmittedDebugSymbolsCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        userSubmittedDebugSymbolsCheckBox.setVisible(false);
        userSubmittedDebugSymbolsCheckBox.addActionListener(e -> onUserSubmittedDebugSymbolsChanged(userSubmittedDebugSymbolsCheckBox.isSelected()));

        JPanel indentedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        indentedPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        indentedPanel.add(userSubmittedDebugSymbolsCheckBox);

        checkboxPanel.add(debugSymbolsCheckBox);
        checkboxPanel.add(indentedPanel);
        checkboxPanel.add(Box.createVerticalGlue());

        panel.add(checkboxPanel, BorderLayout.CENTER);

        return panel;
    }

    protected JPanel createFunctionFilterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Filter matches by function virtual address, name, hash or binary"));

        functionFilterField = new JTextField();
        functionFilterField.setPreferredSize(new Dimension(0, 30));
        functionFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                onFunctionFilterChanged();
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                onFunctionFilterChanged();
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                onFunctionFilterChanged();
            }
        });

        panel.add(functionFilterField, BorderLayout.CENTER);

        return panel;
    }

    // Event handler methods
    protected void onCollectionSelectionChanged(Set<SelectableItem> selectedCollections) {
        Set<Integer> collectionIds = selectedCollections.stream()
                .map(SelectableItem::getId)
                .collect(Collectors.toSet());
        Set<String> collectionNames = selectedCollections.stream()
                .map(SelectableItem::getName)
                .collect(Collectors.toSet());

        Msg.info(this, "Selected collections: " + collectionNames + " (IDs: " + collectionIds + ")");
    }

    protected void onBinarySelectionChanged(Set<SelectableItem> selectedBinaries) {
        Set<Integer> binaryIds = selectedBinaries.stream()
                .map(SelectableItem::getId)
                .collect(Collectors.toSet());
        Set<String> binaryNames = selectedBinaries.stream()
                .map(SelectableItem::getName)
                .collect(Collectors.toSet());

        Msg.info(this, "Selected binaries: " + binaryNames + " (IDs: " + binaryIds + ")");
    }

    protected void onThresholdChanged(int threshold) {
        Msg.info(this, "Threshold changed to: " + threshold);
    }

    protected void onDebugSymbolsChanged(boolean includeDebugSymbols) {
        Msg.info(this, "Debug symbols filter changed to: " + includeDebugSymbols);
    }

    protected void onUserSubmittedDebugSymbolsChanged(boolean includeUserSubmittedDebugSymbols) {
        Msg.info(this, "User submitted debug symbols filter changed to: " + includeUserSubmittedDebugSymbols);
    }

    protected void onFunctionFilterChanged() {
        String filterText = functionFilterField.getText().trim().toLowerCase();

        filteredFunctionMatchResults.clear();
        if (!filterText.isEmpty()) {
            filteredFunctionMatchResults.addAll(
                functionMatchResults.stream()
                    .filter(this::matchesFilter)
                    .toList()
            );
        }

        updateResultsTable();
    }

    protected abstract boolean matchesFilter(GhidraFunctionMatchWithSignature result);

    // Utility methods
    public int getThreshold() {
        return thresholdSlider != null ? thresholdSlider.getValue() : 50;
    }

    public boolean isDebugSymbolsEnabled() {
        return debugSymbolsCheckBox != null && debugSymbolsCheckBox.isSelected();
    }

    public boolean isUserSubmittedDebugSymbolsEnabled() {
        return userSubmittedDebugSymbolsCheckBox != null && userSubmittedDebugSymbolsCheckBox.isSelected();
    }

    protected void filterResults() {
        Set<Integer> selectedCollectionIds = collectionSelector.getSelectedCollectionIds();
        Set<Integer> selectedBinaryIds = binarySelector.getSelectedBinaryIds();
        Set<String> selectedCollectionNames = collectionSelector.getSelectedCollectionNames();
        Set<String> selectedBinaryNames = binarySelector.getSelectedBinaryNames();
        int threshold = getThreshold();
        boolean includeDebugSymbols = isDebugSymbolsEnabled();
        boolean includeUserSubmittedDebugSymbols = isUserSubmittedDebugSymbolsEnabled();

        stopPolling();
        functionMatchResults.clear();
        updateResultsTable();
        hideError();

        Msg.info(this, "Starting function matching with filters - collection names: " + selectedCollectionNames +
                         " (IDs: " + selectedCollectionIds +
                         "), binary names: " + selectedBinaryNames +
                         " (IDs: " + selectedBinaryIds +
                         "), threshold: " + threshold +
                         ", debug symbols: " + includeDebugSymbols +
                         ", user submitted debug symbols: " + includeUserSubmittedDebugSymbols);

        taskMonitorComponent.setVisible(true);
        startFunctionMatching();
    }

    protected void onMatchButtonClicked() {
        filterResults();
    }


    protected void onRenameAllButtonClicked() {
        batchRenameFunctions(functionMatchResults);
        importFunctionNames(functionMatchResults);
    }

    protected void onRenameSelectedButtonClicked() {
        int[] selectedRows = resultsTable.getSelectedRows();
        if (selectedRows.length == 0) {
            showError("Please select one or more rows to rename.");
            return;
        } else {
            hideError();
        }

        List<GhidraFunctionMatchWithSignature> resultsToShow = filteredFunctionMatchResults.isEmpty() ?
            functionMatchResults : filteredFunctionMatchResults;

        List<GhidraFunctionMatchWithSignature> selectedMatches = new ArrayList<>();
        for (int row : selectedRows) {
            if (row < resultsToShow.size()) {
                selectedMatches.add(resultsToShow.get(row));
            }
        }

        batchRenameFunctions(selectedMatches);
        importFunctionNames(selectedMatches);
    }

    protected void batchRenameFunctions(List<GhidraFunctionMatchWithSignature> functionMatches) {
        try {
            revengService.batchRenamingGhidraMatchesWithSignatures(functionMatches);
        } catch (Exception e) {
            showError("Failed to rename functions: " + e.getMessage());
        }
    }

    protected void importFunctionNames(List<GhidraFunctionMatchWithSignature> functionMatches) {
        var program = analyzedProgram.program();

        program.withTransaction("Apply Function Matching Renames", () -> {
                    for (GhidraFunctionMatchWithSignature match : functionMatches) {
                        // We don't pass a service, because we don't need to update individual functions on the portal
                        // batchRenameFunctions already does that for us
                        var cmd = new ApplyMatchCmd(null, analyzedProgram, match, false);
                        cmd.applyTo(program);
                    }
                }
        );
        SwingUtilities.invokeLater(this::updateResultsTable);
    }

    @Override
    protected void cancelCallback() {
        stopPolling();
        close();
    }
}

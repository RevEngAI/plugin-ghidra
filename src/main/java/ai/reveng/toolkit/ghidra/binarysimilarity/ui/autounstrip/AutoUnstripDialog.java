package ai.reveng.toolkit.ghidra.binarysimilarity.ui.autounstrip;

import ai.reveng.model.AutoUnstripResponse;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.task.TaskMonitorComponent;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.Objects;

public class AutoUnstripDialog extends RevEngDialogComponentProvider {
    private final GhidraRevengService.AnalysedProgram analysedProgram;
    private final GhidraRevengService revengService;

    // UI components
    private JLabel statusLabel;
    private JTextArea errorArea;
    private JScrollPane errorScrollPane;
    private JPanel contentPanel;
    private Timer pollTimer;
    private final TaskMonitorComponent taskMonitorComponent;
    private JTable resultsTable;
    private JScrollPane resultsScrollPane;

    // Polling configuration
    private static final int POLL_INTERVAL_MS = 2000; // Poll every 2 seconds

    public AutoUnstripDialog(PluginTool tool, GhidraRevengService.AnalysedProgram analysedProgram) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "Auto Unstrip", true);

        this.analysedProgram = analysedProgram;
        this.revengService = tool.getService(GhidraRevengService.class);
        this.taskMonitorComponent = new TaskMonitorComponent(false, true);

        // Initialize UI
        addDismissButton();

        addWorkPanel(buildMainPanel());

        // Set dialog size to be wider
        setPreferredSize(800, 680);

        // Start the auto unstrip process
        startAutoUnstrip();
    }

    private void startAutoUnstrip() {
        // Show initial status
        statusLabel.setText("Starting auto unstrip...");
        taskMonitorComponent.initialize(100);

        // Start polling timer
        pollTimer = new Timer(POLL_INTERVAL_MS, e -> pollAutoUnstripStatus());
        pollTimer.start();

        // Make initial call
        pollAutoUnstripStatus();
    }

    private void pollAutoUnstripStatus() {
        SwingUtilities.invokeLater(() -> {
            try {
                var autoUnstripResponse = revengService.autoUnstrip(analysedProgram).autoUnstripResponse();
                updateUI(autoUnstripResponse);

                // Check if we're done
                if (autoUnstripResponse.getProgress() >= 100 || Objects.equals(autoUnstripResponse.getStatus(), "COMPLETED")) {
                    stopPolling();
                    // Pull function information (names and types) from the server, instead of dealing with matches
                    // in the auto unstrip response
                    var changes = revengService.pullFunctionInfoFromAnalysis(analysedProgram, taskMonitorComponent);
                    taskMonitorComponent.setVisible(false);

                    SwingUtilities.invokeLater(() -> updateResultsTable(changes));
                }
            } catch (Exception e) {
                handleError("Failed to poll auto unstrip status: " + e.getMessage());
                stopPolling();
            }
        });
    }

    private void updateUI(AutoUnstripResponse autoUnstripResponse) {
        if (autoUnstripResponse == null) return;

        // Update progress bar
        taskMonitorComponent.setProgress(autoUnstripResponse.getProgress());
        taskMonitorComponent.setMessage(autoUnstripResponse.getProgress() + "%");

        // Update status
        statusLabel.setText("Status: " + getFriendlyStatusMessage(autoUnstripResponse.getStatus()));

        // Handle error message - dynamically add/remove error panel
        if (autoUnstripResponse.getErrorMessage() != null && !autoUnstripResponse.getErrorMessage().isEmpty()) {
            showError(autoUnstripResponse.getErrorMessage());
        } else {
            hideError();
        }

        final var map = analysedProgram.getFunctionMap();
        var currentRenameResults = autoUnstripResponse.getMatches().stream().map(match -> {
            // This functionID is for the local/origin function and not the matched/neighbour function!
            var functionId = new TypedApiInterface.FunctionID(match.getFunctionId());
            var function = map.get(functionId);
            if (function == null) {
                return null;
            }
            return new GhidraRevengService.RenameResult(function, function.getName(), match.getSuggestedName());
        }).filter(Objects::nonNull).toList();
        // Update results table
        updateResultsTable(currentRenameResults);
    }

    /**
     * Convert API status values to user-friendly messages
     */
    private String getFriendlyStatusMessage(String apiStatus) {
        if (apiStatus == null) {
            return "Unknown";
        }

        return switch (apiStatus) {
            case "STARTED" -> "started auto unstrip...";
            case "IN_PROGRESS" -> "running auto unstrip...";
            case "COMPLETED" -> "completed auto unstrip";
            case "ERROR", "NOT_FOUND" -> "auto unstrip failed";
            case "CANCELLED" -> "auto unstrip was cancelled";
            default -> apiStatus; // Fallback to original if unknown
        };
    }

    private void updateResultsTable(java.util.List<GhidraRevengService.RenameResult> renameResults) {
        DefaultTableModel model = new DefaultTableModel(new Object[]{"Virtual Address", "Original Name", "New Name"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                //all cells false
                return false;
            }
        };
        for (GhidraRevengService.RenameResult result : renameResults) {
            model.addRow(new Object[]{result.virtualAddress(), result.originalName(), result.newName()});
        }
        resultsTable.setModel(model);

        // Update the dynamic title
        int renameCount = renameResults.size();
        String title = "Renamed " + renameCount + " functions identified by the RevEng.AI dataset";
        resultsScrollPane.setBorder(BorderFactory.createTitledBorder(title));

        // Fix table header appearance
        resultsTable.getTableHeader().setOpaque(false);
        resultsTable.getTableHeader().setBackground(UIManager.getColor("TableHeader.background"));
        resultsTable.getTableHeader().setForeground(UIManager.getColor("TableHeader.foreground"));

        // Set column widths and fonts
        if (resultsTable.getColumnCount() > 0) {
            // Set monospace font for Virtual Address column
            resultsTable.getColumnModel().getColumn(0).setCellRenderer(new javax.swing.table.DefaultTableCellRenderer() {
                @Override
                public java.awt.Component getTableCellRendererComponent(javax.swing.JTable table, Object value,
                                                                     boolean isSelected, boolean hasFocus, int row, int column) {
                    java.awt.Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                    c.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
                    return c;
                }
            });

            // Set column widths - Virtual Address smaller, others larger
            resultsTable.getColumnModel().getColumn(0).setPreferredWidth(10);  // Virtual Address
            resultsTable.getColumnModel().getColumn(1).setPreferredWidth(200);  // Original Name
            resultsTable.getColumnModel().getColumn(2).setPreferredWidth(200);  // New Name

            // Allow columns to be resized but set minimum widths
            resultsTable.getColumnModel().getColumn(0).setMinWidth(10);
            resultsTable.getColumnModel().getColumn(1).setMinWidth(150);
            resultsTable.getColumnModel().getColumn(2).setMinWidth(150);
        }
    }

    private void handleError(String message) {
        statusLabel.setText("Error occurred");
        showError(message);
        taskMonitorComponent.setMessage("Error");
    }

    private void showError(String message) {
        errorArea.setText(message);
        // Only add the error panel if it's not already added
        if (errorScrollPane.getParent() == null) {
            contentPanel.add(errorScrollPane, BorderLayout.SOUTH);
            contentPanel.revalidate();
            contentPanel.repaint();
        }
    }

    private void hideError() {
        // Only remove the error panel if it's currently added
        if (errorScrollPane.getParent() != null) {
            contentPanel.remove(errorScrollPane);
            contentPanel.revalidate();
            contentPanel.repaint();
        }
    }

    private void stopPolling() {
        if (pollTimer != null) {
            pollTimer.stop();
            pollTimer = null;
        }
    }

    private JComponent buildMainPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // Create title panel
        JPanel titlePanel = createTitlePanel("Automatically rename unknown functions");
        panel.add(titlePanel, BorderLayout.NORTH);

        // Create content panel for description and progress
        contentPanel = new JPanel(new BorderLayout());

        // Progress panel in the center
        JPanel progressPanel = createProgressPanel();
        contentPanel.add(progressPanel, BorderLayout.CENTER);

        // Initialize error area but don't add it to the panel yet
        errorArea = new JTextArea(5, 60);
        errorArea.setLineWrap(true);
        errorArea.setWrapStyleWord(true);
        errorArea.setEditable(false);
        errorArea.setBackground(Color.PINK);
        errorArea.setBorder(BorderFactory.createTitledBorder("Error Details"));
        errorScrollPane = new JScrollPane(errorArea);
        // Note: Error panel is not added here - it will be added dynamically when needed

        // Results table
        resultsTable = new JTable();
        resultsScrollPane = new JScrollPane(resultsTable);
        resultsScrollPane.setBorder(BorderFactory.createTitledBorder("Rename Results"));
        contentPanel.add(resultsScrollPane, BorderLayout.SOUTH);

        panel.add(contentPanel, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createProgressPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
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

    @Override
    protected void cancelCallback() {
        stopPolling();
        close();
    }
}

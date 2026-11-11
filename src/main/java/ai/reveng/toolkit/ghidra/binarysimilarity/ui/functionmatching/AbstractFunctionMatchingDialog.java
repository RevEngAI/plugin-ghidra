package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching;

import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.binarysimilarity.cmds.ApplyMatchCmd;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.CollectionSelectionPanel;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.BinarySelectionPanel;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.SelectableItem;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.UserSelectionPanel;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import docking.widgets.textfield.HintTextField;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.util.task.Task;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;
import resources.ResourceManager;
import generic.theme.GThemeDefaults.Colors.Messages;
import generic.theme.GColor;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public abstract class AbstractFunctionMatchingDialog extends RevEngDialogComponentProvider {
    protected final PluginTool tool;
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
    protected UserSelectionPanel userSelector;
    // Nothing ticked means any platform / architecture, as in the portal
    protected final Map<MatchFilters.PlatformsEnum, JCheckBox> platformCheckBoxes = new LinkedHashMap<>();
    protected final Map<MatchFilters.ArchitecturesEnum, JCheckBox> architectureCheckBoxes = new LinkedHashMap<>();
    protected JLabel statusLabel;
    protected JProgressBar matchingProgressBar;
    protected JButton matchButton;
    private Icon matchIcon;
    protected JLabel resultsCountLabel;
    protected JTextArea errorArea;
    protected JScrollPane errorScrollPane;
    /// The thread of the current matching run; null when idle or cancelled. A run whose thread is no
    /// longer this one has been superseded, and must not touch the UI.
    protected volatile Thread matchingThread;
    protected JPanel transferButtonsPanel;

    // Assembly comparison panel
    protected AssemblyDiffPanel assemblyDiffPanel;
    private final JPopupMenu portalPopup = new JPopupMenu();

    // Data
    protected AnalysisBasicInfoOutputBody analysisBasicInfo;
    protected final List<GhidraFunctionMatchWithSignature> functionMatchResults;
    protected final List<GhidraFunctionMatchWithSignature> filteredFunctionMatchResults;

    // Polling configuration
    protected static final int POLL_INTERVAL_MS = 2000; // Poll every 2 seconds

    protected AbstractFunctionMatchingDialog(String title, Boolean isModal, PluginTool tool,
                                           GhidraRevengService.AnalysedProgram analyzedProgram) {
        super(title, isModal);
        this.tool = tool;
        this.revengService = tool.getService(GhidraRevengService.class);
        this.analyzedProgram = analyzedProgram;
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
        setPreferredSize(1200, 1000);

        // Don't start function matching automatically - wait for user to click Match button
        statusLabel.setText("Ready: adjust the filters and press Match Functions");
    }

    protected void startFunctionMatching() {
        // All network work runs on a background thread so the UI stays responsive
        statusLabel.setText("Starting function matching...");
        matchingProgressBar.setIndeterminate(true);
        setMatchingInProgress(true);

        matchingThread = new Thread(this::runMatchingLoop, "RevEngAI function matching");
        matchingThread.setDaemon(true);
        matchingThread.start();
    }

    /// Shows or hides the progress bar, and turns the Match button into Cancel while a run is going
    protected void setMatchingInProgress(boolean inProgress) {
        matchingProgressBar.setVisible(inProgress);
        matchButton.setText(inProgress ? "Cancel" : "Match Functions");
        matchButton.setIcon(inProgress ? null : matchIcon);
    }

    /// Runs {@code update} on the EDT, unless the run on {@code self} has been cancelled or superseded
    /// by the time it gets there
    private void onEdtIfCurrent(Thread self, Runnable update) {
        SwingUtilities.invokeLater(() -> {
            if (matchingThread == self) {
                update.run();
            }
        });
    }

    /// Normalised view of the v3 matching progress, shared by the start and status responses
    protected record MatchingProgress(String status, String step, Long stepIndex, Long stepsTotal, String errorMessage) {}

    /// Kick off matching (POST) and return its initial progress
    protected abstract MatchingProgress startMatching() throws ai.reveng.invoker.ApiException;

    /// Poll the matching status (GET) and return the current progress
    protected abstract MatchingProgress pollMatchingStatus() throws ai.reveng.invoker.ApiException;

    /// Fetch the completed matches (GET)
    protected abstract List<MatchedFunctionResult> fetchMatches() throws ai.reveng.invoker.ApiException;

    private void runMatchingLoop() {
        final Thread self = Thread.currentThread();
        try {
            MatchingProgress progress = startMatching();
            while (matchingThread == self) {
                final MatchingProgress current = progress;
                onEdtIfCurrent(self, () -> updateProgressUI(current));

                if ("FAILED".equals(progress.status())) {
                    String errorMsg = progress.errorMessage() != null && !progress.errorMessage().isEmpty()
                            ? progress.errorMessage()
                            : "Function matching returned an error status";
                    onEdtIfCurrent(self, () -> {
                        handleError(errorMsg);
                        statusLabel.setText("Function matching failed");
                    });
                    return;
                }
                if ("COMPLETED".equals(progress.status())) {
                    break;
                }
                Thread.sleep(POLL_INTERVAL_MS);
                if (matchingThread != self) return;
                progress = pollMatchingStatus();
            }
            if (matchingThread != self) return;

            // Resolving type signatures fires many requests, so keep it off the EDT too
            onEdtIfCurrent(self, () -> {
                matchingProgressBar.setIndeterminate(true);
                statusLabel.setText("Loading type information...");
            });
            var built = buildMatchResults(fetchMatches());
            // The status label is the only thing that says what this dialog is doing, so it has to be
            // told the work finished, or it sits there claiming to still be loading.
            onEdtIfCurrent(self, () -> {
                functionMatchResults.clear();
                functionMatchResults.addAll(built);
                // Apply any existing function filter, which also refreshes the table
                onFunctionFilterChanged();
                statusLabel.setText("Matching complete: %d match(es)".formatted(functionMatchResults.size()));
            });
        } catch (InterruptedException e) {
            // matching was cancelled, nothing to report
        } catch (Throwable t) {
            // Throwable rather than Exception: an Error thrown in here — a clash between a bundled
            // jar and Ghidra's own, or a large binary's type closure exhausting the heap — killed
            // this thread without a word and left the progress bar up for ever. Whatever it is,
            // the user is told.
            Msg.error(this, "Function matching failed: " + t, t);
            onEdtIfCurrent(self, () -> {
                handleError("Function matching failed: " + t);
                statusLabel.setText("Function matching failed");
            });
        } finally {
            // No path out of here may leave the progress bar spinning. A cancelled run has already
            // been reset by stopPolling, and must not hide the bar of the run that replaced it.
            onEdtIfCurrent(self, () -> {
                matchingThread = null;
                setMatchingInProgress(false);
            });
        }
    }

    /// Joins the error-level {@link ProgressMessage}s of a v3 matching response into a single string
    protected static String errorTextFrom(List<ProgressMessage> messages) {
        if (messages == null) {
            return null;
        }
        return messages.stream()
                .filter(m -> m.getLevel() == ProgressMessage.LevelEnum.ERROR)
                .map(ProgressMessage::getText)
                .filter(Objects::nonNull)
                .collect(Collectors.joining("\n"));
    }

    /// A matched function result that still needs to be associated with a local Ghidra function
    protected record MatchedFunctionResult(TypedApiInterface.FunctionID originFunctionID, MatchedFunction matchedFunction) {}

    /// Flattens a v3 {@link GetMatchesOutputBody} matches list into individual matched function results
    protected static List<MatchedFunctionResult> flattenMatches(List<ai.reveng.model.FunctionMatch> matches) {
        List<MatchedFunctionResult> results = new ArrayList<>();
        if (matches == null) {
            return results;
        }
        for (var matchResult : matches) {
            var funcId = new TypedApiInterface.FunctionID(matchResult.getFunctionId());
            if (matchResult.getMatchedFunctions() == null) {
                continue;
            }
            for (var matched : matchResult.getMatchedFunctions()) {
                results.add(new MatchedFunctionResult(funcId, matched));
            }
        }
        return results;
    }

    /// Builds the result rows. This resolves type signatures, which is the expensive part, so it is
    /// expected to run off the EDT and does not touch Swing.
    protected List<GhidraFunctionMatchWithSignature> buildMatchResults(List<MatchedFunctionResult> response) {
        List<GhidraFunctionMatch> matches = new ArrayList<>();
        final Map<TypedApiInterface.FunctionID, Function> functionMap = analyzedProgram.getFunctionMap();

        response.forEach(matchResult -> {
            // Retrieve the local function name
            var funcId = matchResult.originFunctionID();
            Function localFunction = functionMap.get(funcId);
            if (localFunction == null) {
                // If we can't find the local function, skip this match (boundaries do not match the remote ones)
                return;
            }
            FunctionMatch result = FunctionMatch.fromMatchedFunctionAPIType(matchResult.matchedFunction(), funcId);
            matches.add(new GhidraFunctionMatch(localFunction, result));
        });

        // Get the type info for all matches (fires the data-type requests; expensive)
        var ghidraResultsWithSignatures = revengService.getSignatures(matches);

        // For all matches we got, create a GhidraFunctionMatchWithSignature object (signature can be null!)
        List<GhidraFunctionMatchWithSignature> built = new ArrayList<>();
        for (GhidraFunctionMatch match : matches) {
            var sig = ghidraResultsWithSignatures.get(match);
            built.add(new GhidraFunctionMatchWithSignature(match.function(), match.functionMatch(), sig));
        }
        return built;
    }


    protected void updateProgressUI(MatchingProgress progress) {
        if (progress == null) return;

        // A determinate bar when the server reports step counters (step_index is zero-based, so the bar
        // fills by completed steps); otherwise an animated one so the user can see it is still running.
        // The step itself goes in the status text: painted on the bar it overlaps the thin macOS track.
        String step = progress.step() != null && !progress.step().isBlank() ? progress.step() : null;
        if (progress.stepsTotal() != null && progress.stepsTotal() > 0 && progress.stepIndex() != null) {
            int total = (int) Math.min(Integer.MAX_VALUE, progress.stepsTotal());
            int index = (int) Math.max(0, Math.min(total, progress.stepIndex()));
            matchingProgressBar.setIndeterminate(false);
            matchingProgressBar.setMaximum(total);
            matchingProgressBar.setValue(index);
            if (step != null) {
                step = "%s (step %d of %d)".formatted(step, Math.min(index + 1, total), total);
            }
        } else {
            matchingProgressBar.setIndeterminate(true);
        }

        if (step != null) {
            statusLabel.setText(step);
        } else if (progress.status() != null) {
            statusLabel.setText(getFriendlyStatusMessage(progress.status()));
        }

        // Handle error message - dynamically add/remove error panel
        if (progress.errorMessage() != null && !progress.errorMessage().isEmpty()) {
            showError(progress.errorMessage());
        } else {
            hideError();
        }
    }

    /// The results that back the table model, in model-row order: all results when no function filter
    /// is active, otherwise the filtered subset (which may be empty).
    protected List<GhidraFunctionMatchWithSignature> displayedResults() {
        String filterText = functionFilterField != null ? functionFilterField.getText().trim() : "";
        return filterText.isEmpty() ? functionMatchResults : filteredFunctionMatchResults;
    }

    protected void updateResultsTable() {
        String filterText = functionFilterField != null ? functionFilterField.getText().trim() : "";
        List<GhidraFunctionMatchWithSignature> resultsToShow = displayedResults();

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

        // Show how many of the matches the results filter lets through
        int totalMatchCount = functionMatchResults.size();
        int displayedMatchCount = resultsToShow.size();
        resultsCountLabel.setText(filterText.isEmpty()
                ? "%d match%s".formatted(totalMatchCount, totalMatchCount == 1 ? "" : "es")
                : "%d of %d shown".formatted(displayedMatchCount, totalMatchCount));

        // Show/hide transfer buttons based on whether we have results
        boolean hasResults = displayedMatchCount > 0;
        transferButtonsPanel.setVisible(hasResults);

        // Enable table selection model for transfer operations
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

            if (value instanceof java.math.BigDecimal percentage) {
                Color textColor = getColorForPercentage(percentage.toPlainString());

                if (!isSelected) {
                    // Set text color based on percentage value
                    c.setForeground(textColor != null ? textColor : table.getForeground());
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

        private static final Color SIMILARITY_CRITICAL = new GColor("color.fg.reveng.similarity.critical");
        private static final Color SIMILARITY_HIGH = new GColor("color.fg.reveng.similarity.high");
        private static final Color SIMILARITY_MEDIUM = new GColor("color.fg.reveng.similarity.medium");
        private static final Color SIMILARITY_LOW = new GColor("color.fg.reveng.similarity.low");

        /**
         * Get the text color based on percentage value, or null for the table's default
         */
        private Color getColorForPercentage(String percentageStr) {
            try {
                // Remove the % symbol and parse as double
                String numStr = percentageStr.replace("%", "").trim();
                if (numStr.equals("N/A")) {
                    return null;
                }

                double percentage = Double.parseDouble(numStr);

                if (percentage >= 0 && percentage <= 50) {
                    return SIMILARITY_CRITICAL;
                } else if (percentage > 50 && percentage <= 70) {
                    return SIMILARITY_HIGH;
                } else if (percentage > 70 && percentage <= 90) {
                    return SIMILARITY_MEDIUM;
                } else if (percentage > 90 && percentage <= 100) {
                    return SIMILARITY_LOW;
                } else {
                    return null;
                }
            } catch (NumberFormatException e) {
                return null;
            }
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
            java.util.Comparator<java.math.BigDecimal> percentageComparator = java.math.BigDecimal::compareTo;
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
            case "UNINITIALISED", "PENDING" -> "Starting function matching...";
            case "RUNNING" -> "Running function matching...";
            case "COMPLETED" -> "Completed function matching";
            case "FAILED" -> "Function matching failed";
            default -> apiStatus; // Fallback to original if unknown
        };
    }

    protected void handleError(String message) {
        Msg.error(this, message);
        statusLabel.setText("An error occurred, press Match Functions again to retry");
        showError(message);
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
        Thread running = matchingThread;
        matchingThread = null;
        if (running != null) {
            running.interrupt();
        }
        if (matchingProgressBar != null) {
            setMatchingInProgress(false);
        }
    }

    protected JComponent buildMainPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // Create title panel
        JPanel titlePanel = createTitlePanel(getDialogDescription());
        panel.add(titlePanel, BorderLayout.NORTH);

        // Create content panel
        contentPanel = new JPanel(new BorderLayout());
        contentPanel.setBorder(BorderFactory.createEmptyBorder(12, 16, 12, 16));

        // Top half: the filters sent with the matching request, then status and the Match button
        JPanel searchSection = new JPanel(new BorderLayout(0, 10));
        searchSection.add(createSectionHeading("Filter Search"), BorderLayout.NORTH);
        searchSection.add(createFilterPanel(), BorderLayout.CENTER);
        searchSection.add(createMatchActionPanel(), BorderLayout.SOUTH);
        contentPanel.add(searchSection, BorderLayout.NORTH);

        // Bottom half: narrowing down the results that came back
        JPanel resultsHeader = new JPanel(new BorderLayout(0, 10));
        resultsHeader.setBorder(BorderFactory.createEmptyBorder(18, 0, 0, 0));
        resultsHeader.add(createSectionHeading("Filter Results"), BorderLayout.NORTH);
        resultsHeader.add(createFunctionFilterPanel(), BorderLayout.CENTER);

        JPanel centerPanel = new JPanel(new BorderLayout(0, 8));
        centerPanel.add(resultsHeader, BorderLayout.NORTH);

        // Initialize error area but don't add it to the panel yet
        errorArea = new JTextArea(5, 60);
        errorArea.setLineWrap(true);
        errorArea.setWrapStyleWord(true);
        errorArea.setEditable(false);
        errorArea.setForeground(Messages.ERROR);
        errorArea.setBorder(BorderFactory.createTitledBorder("Error Details"));
        errorScrollPane = new JScrollPane(errorArea);

        // Results table with transfer buttons container
        JPanel resultsContainer = createResultsContainer();
        centerPanel.add(resultsContainer, BorderLayout.CENTER);

        contentPanel.add(centerPanel, BorderLayout.CENTER);
        panel.add(contentPanel, BorderLayout.CENTER);

        return panel;
    }

    protected abstract String getDialogDescription();

    /// A bold heading followed by a rule across the rest of the row, splitting the dialog into sections
    protected static JComponent createSectionHeading(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, label.getFont().getSize2D() + 1f));

        JPanel heading = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        heading.add(label, gbc);

        gbc.weightx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 8, 0, 0);
        heading.add(new JSeparator(), gbc);
        return heading;
    }

    protected JPanel createFilterPanel() {
        JPanel filterPanel = new JPanel();
        filterPanel.setLayout(new BoxLayout(filterPanel, BoxLayout.Y_AXIS));

        filterPanel.add(createFilterRow(createCollectionSelectorPanel(), createBinarySelectorPanel()));
        filterPanel.add(Box.createVerticalStrut(12));
        filterPanel.add(createFilterRow(
                createField("Minimum similarity", createThresholdPanel()),
                createField("Debug symbols", createDebugSymbolsPanel())));
        filterPanel.add(Box.createVerticalStrut(12));
        filterPanel.add(createFilterRow(
                createField("Platform & architecture", createPlatformArchitecturePanel()),
                createUserSelectorPanel()));

        return filterPanel;
    }

    /// Two filters side by side in equal-width columns, top-aligned
    private static JPanel createFilterRow(JComponent left, JComponent right) {
        JPanel row = new JPanel(new GridLayout(1, 2, 24, 0));
        row.add(topAligned(left));
        row.add(topAligned(right));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        return row;
    }

    private static JPanel topAligned(JComponent component) {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.add(component, BorderLayout.NORTH);
        return wrapper;
    }

    /// A bold caption above a filter's controls
    protected static JPanel createField(String caption, JComponent control) {
        JLabel label = new JLabel(caption);
        label.setFont(label.getFont().deriveFont(Font.BOLD));

        JPanel field = new JPanel(new BorderLayout(0, 4));
        field.add(label, BorderLayout.NORTH);
        field.add(control, BorderLayout.CENTER);
        return field;
    }

    /// Status on the left; progress and the Match button right-aligned beneath the filters they apply
    protected JPanel createMatchActionPanel() {
        JPanel panel = new JPanel(new BorderLayout(12, 0));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));

        statusLabel = new JLabel("Initializing...");
        panel.add(statusLabel, BorderLayout.CENTER);

        matchingProgressBar = new JProgressBar();
        matchingProgressBar.setPreferredSize(new Dimension(220, matchingProgressBar.getPreferredSize().height));
        matchingProgressBar.setVisible(false);

        matchButton = new JButton("Match Functions");

        // Add magnifying glass icon to the button
        try {
            matchIcon = ResourceManager.loadImage("images/magnifier.png");
            matchButton.setIcon(matchIcon);
        } catch (Exception e) {
            // If icon loading fails, button will just show text without icon
        }

        matchButton.addActionListener(e -> onMatchButtonClicked());

        // The button sets the row's height, so showing or hiding the bar beside it moves nothing
        JPanel actions = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridy = 0;
        gbc.insets = new Insets(0, 0, 0, 10);
        actions.add(matchingProgressBar, gbc);
        gbc.insets = new Insets(0, 0, 0, 0);
        actions.add(matchButton, gbc);
        panel.add(actions, BorderLayout.EAST);

        return panel;
    }

    protected JPanel createResultsContainer() {
        JPanel resultsContainer = new JPanel(new BorderLayout());

        // Results table
        resultsTable = new JTable();
        resultsTable.setAutoCreateRowSorter(true);
        resultsTable.setFillsViewportHeight(true);
        resultsTable.setRowHeight(resultsTable.getRowHeight() + 4);
        resultsTable.setShowVerticalLines(false);
        resultsScrollPane = new JScrollPane(resultsTable);
        resultsScrollPane.setPreferredSize(new Dimension(0, 200));

        // Add selection listener for assembly comparison
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onTableSelectionChanged();
            }
        });

        // Consuming the right-click keeps the dialog's docking popup, with its tool-wide actions, from appearing
        JMenuItem openInPortalItem = new JMenuItem("Open in Portal");
        openInPortalItem.addActionListener(e -> {
            var analysisID = getSelectedMatchedAnalysisID();
            if (analysisID != null) {
                revengService.openPortalFor(tool, analysisID);
            }
        });
        portalPopup.add(openInPortalItem);
        resultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                showPortalPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPortalPopup(e);
            }
        });

        // Create assembly comparison panel; its two halves are titled, so it needs no box of its own here
        assemblyDiffPanel = new AssemblyDiffPanel();
        assemblyDiffPanel.setBorder(BorderFactory.createEmptyBorder(6, 0, 0, 0));
        // Its default 300px left the table only a few rows in a dialog of the default size
        assemblyDiffPanel.setPreferredSize(new Dimension(0, 200));

        // Create vertical split pane with results table on top and assembly comparison below,
        // sized from their preferred heights and sharing any extra room
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setTopComponent(resultsScrollPane);
        mainSplitPane.setBottomComponent(assemblyDiffPanel);
        mainSplitPane.setResizeWeight(0.5);
        mainSplitPane.setBorder(null);

        resultsContainer.add(mainSplitPane, BorderLayout.CENTER);

        // Transfer buttons panel
        transferButtonsPanel = createTransferButtonsPanel();
        transferButtonsPanel.setVisible(false);
        resultsContainer.add(transferButtonsPanel, BorderLayout.SOUTH);

        return resultsContainer;
    }

    protected void onTableSelectionChanged() {
        int selectedRow = resultsTable.getSelectedRow();
        if (selectedRow < 0) {
            assemblyDiffPanel.clear();
            return;
        }

        // Convert view index to model index (in case table is sorted)
        int modelRow = resultsTable.convertRowIndexToModel(selectedRow);

        List<GhidraFunctionMatchWithSignature> resultsToShow = displayedResults();

        if (modelRow >= resultsToShow.size()) {
            return;
        }

        GhidraFunctionMatchWithSignature selectedMatch = resultsToShow.get(modelRow);
        assemblyDiffPanel.showAssemblyFor(selectedMatch, revengService);
    }

    private void showPortalPopup(MouseEvent e) {
        if (!e.isPopupTrigger()) {
            return;
        }
        e.consume();
        int row = resultsTable.rowAtPoint(e.getPoint());
        if (row >= 0) {
            resultsTable.setRowSelectionInterval(row, row);
            portalPopup.getComponent(0).setEnabled(getSelectedMatchedAnalysisID() != null);
            portalPopup.show(resultsTable, e.getX(), e.getY());
        }
    }

    private TypedApiInterface.AnalysisID getSelectedMatchedAnalysisID() {
        var selected = getSelectedMatches();
        return selected.size() == 1 ? selected.get(0).functionMatch().nearest_neighbor_analysis_id() : null;
    }

    protected JPanel createTransferButtonsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        panel.setBorder(BorderFactory.createEmptyBorder(6, 0, 0, 0));
        panel.add(createTransferButton("Transfer All", this::onTransferAll));
        panel.add(createTransferButton("Transfer Selected", this::onTransferSelected));
        return panel;
    }

    /// A button that drops down the parts of a match that can be transferred, as the portal's
    /// Transfer Symbol button does, and hands the chosen one to {@code onChosen}
    protected static JButton createTransferButton(String text, Consumer<ApplyMatchCmd.Transfer> onChosen) {
        JPopupMenu menu = new JPopupMenu();
        for (ApplyMatchCmd.Transfer transfer : ApplyMatchCmd.Transfer.values()) {
            JMenuItem item = new JMenuItem(transfer.label());
            item.addActionListener(e -> onChosen.accept(transfer));
            menu.add(item);
        }

        JButton button = new JButton(text + " \u25BE");
        button.addActionListener(e -> menu.show(button, 0, button.getHeight()));
        return button;
    }

    protected JPanel createCollectionSelectorPanel() {
        collectionSelector = new CollectionSelectionPanel(
                query -> revengService.searchCollectionsWithIds(query),
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

        thresholdSlider = new JSlider(0, 100, 70);
        thresholdSlider.setMajorTickSpacing(25);
        thresholdSlider.setMinorTickSpacing(5);
        thresholdSlider.setPaintTicks(true);
        thresholdSlider.setPaintLabels(true);

        thresholdValueLabel = new JLabel("70%", SwingConstants.RIGHT);
        thresholdValueLabel.setFont(thresholdValueLabel.getFont().deriveFont(Font.BOLD, 14f));
        // Room for "100%" so the slider doesn't shift as the value changes
        thresholdValueLabel.setPreferredSize(new Dimension(48, thresholdValueLabel.getPreferredSize().height));


        thresholdSlider.addChangeListener(e -> thresholdValueLabel.setText(thresholdSlider.getValue() + "%"));

        JPanel sliderPanel = new JPanel(new BorderLayout());
        sliderPanel.add(thresholdSlider, BorderLayout.CENTER);
        sliderPanel.add(thresholdValueLabel, BorderLayout.EAST);

        panel.add(sliderPanel, BorderLayout.CENTER);

        return panel;
    }

    protected JPanel createDebugSymbolsPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JPanel checkboxPanel = new JPanel();
        checkboxPanel.setLayout(new BoxLayout(checkboxPanel, BoxLayout.Y_AXIS));

        debugSymbolsCheckBox = new JCheckBox("Only include functions with debug symbols", false);
        debugSymbolsCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        debugSymbolsCheckBox.addActionListener(
                e -> userSubmittedDebugSymbolsCheckBox.setEnabled(debugSymbolsCheckBox.isSelected()));

        userSubmittedDebugSymbolsCheckBox = new JCheckBox("Include user submitted debug symbols", false);
        userSubmittedDebugSymbolsCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        userSubmittedDebugSymbolsCheckBox.setEnabled(false);

        // Indented under the box it depends on
        JPanel indentedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        indentedPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        indentedPanel.setBorder(BorderFactory.createEmptyBorder(0, 20, 0, 0));
        indentedPanel.add(userSubmittedDebugSymbolsCheckBox);

        checkboxPanel.add(debugSymbolsCheckBox);
        checkboxPanel.add(indentedPanel);

        panel.add(checkboxPanel, BorderLayout.CENTER);

        return panel;
    }

    protected JPanel createPlatformArchitecturePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setToolTipText("Leave unticked to match any platform or architecture");

        platformCheckBoxes.put(MatchFilters.PlatformsEnum.LINUX, new JCheckBox("Linux"));
        platformCheckBoxes.put(MatchFilters.PlatformsEnum.WINDOWS, new JCheckBox("Windows"));
        platformCheckBoxes.put(MatchFilters.PlatformsEnum.ANDROID, new JCheckBox("Android"));

        architectureCheckBoxes.put(MatchFilters.ArchitecturesEnum.X86_64, new JCheckBox("x86 (64-bit)"));
        architectureCheckBoxes.put(MatchFilters.ArchitecturesEnum.X86_32, new JCheckBox("x86 (32-bit)"));
        architectureCheckBoxes.put(MatchFilters.ArchitecturesEnum.ARM_64, new JCheckBox("ARM (64-bit)"));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 10);

        gbc.gridy = 0;
        panel.add(new JLabel("Platforms:"), gbc);
        for (JCheckBox checkBox : platformCheckBoxes.values()) {
            panel.add(checkBox, gbc);
        }

        gbc.gridy = 1;
        panel.add(new JLabel("Architectures:"), gbc);
        for (JCheckBox checkBox : architectureCheckBoxes.values()) {
            panel.add(checkBox, gbc);
        }

        // Keep the toggles left-aligned when the panel is wider than they are
        gbc.gridy = 0;
        gbc.weightx = 1;
        panel.add(Box.createHorizontalGlue(), gbc);

        return panel;
    }

    protected JPanel createUserSelectorPanel() {
        userSelector = new UserSelectionPanel(
                query -> revengService.searchUsersWithIds(query),
                3
        );

        return userSelector;
    }

    protected JPanel createFunctionFilterPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 0));
        panel.add(new JLabel("Filter:"), BorderLayout.WEST);

        functionFilterField = new HintTextField(getFunctionFilterHint());
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

        resultsCountLabel = new JLabel("No matches yet");
        panel.add(resultsCountLabel, BorderLayout.EAST);

        return panel;
    }

    /// Placeholder for the results filter, naming the columns {@link #matchesFilter} searches
    protected String getFunctionFilterHint() {
        return "Matched function name, hash or binary";
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

    public List<MatchFilters.PlatformsEnum> getSelectedPlatforms() {
        return platformCheckBoxes.entrySet().stream()
                .filter(entry -> entry.getValue().isSelected())
                .map(Map.Entry::getKey)
                .toList();
    }

    public List<MatchFilters.ArchitecturesEnum> getSelectedArchitectures() {
        return architectureCheckBoxes.entrySet().stream()
                .filter(entry -> entry.getValue().isSelected())
                .map(Map.Entry::getKey)
                .toList();
    }

    /// The filters sent with the matching request, from the current state of the filter panel
    protected MatchFilters buildMatchFilters() {
        var filters = new MatchFilters();
        filters.setCollectionIds(collectionSelector.getSelectedCollectionIds().stream()
                .map(Integer::longValue).toList());
        filters.setBinaryIds(binarySelector.getSelectedBinaryIds().stream()
                .map(Integer::longValue).toList());

        if (isDebugSymbolsEnabled()) {
            var debugTypes = new ArrayList<String>();
            debugTypes.add("SYSTEM");
            if (isUserSubmittedDebugSymbolsEnabled()) {
                debugTypes.add("USER");
            }
            filters.setDebugTypes(debugTypes);
        }

        var platforms = getSelectedPlatforms();
        if (!platforms.isEmpty()) {
            filters.setPlatforms(platforms);
        }
        var architectures = getSelectedArchitectures();
        if (!architectures.isEmpty()) {
            filters.setArchitectures(architectures);
        }
        var userIds = userSelector.getSelectedUserIds();
        if (!userIds.isEmpty()) {
            filters.setUserIds(userIds.stream().map(Integer::longValue).toList());
        }
        return filters;
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
                         ", user submitted debug symbols: " + includeUserSubmittedDebugSymbols +
                         ", platforms: " + getSelectedPlatforms() +
                         ", architectures: " + getSelectedArchitectures() +
                         ", users: " + userSelector.getSelectedUserNames() +
                         " (IDs: " + userSelector.getSelectedUserIds() + ")");

        startFunctionMatching();
    }

    /// Starts a match, or cancels the one in progress (the button reads Cancel while it runs)
    protected void onMatchButtonClicked() {
        if (matchingThread != null) {
            stopPolling();
            statusLabel.setText("Cancelled: press Match Functions to search again");
            return;
        }
        filterResults();
    }


    protected void onTransferAll(ApplyMatchCmd.Transfer transfer) {
        hideError();
        transferInBackground(functionMatchResults, transfer);
    }

    /// The results behind the currently selected table rows.
    ///
    /// The table is sortable, so the view row order need not match the order of the list backing the
    /// table model. Every selected view index is therefore converted to a model index before it is
    /// used to look up a result.
    protected List<GhidraFunctionMatchWithSignature> getSelectedMatches() {
        List<GhidraFunctionMatchWithSignature> resultsToShow = displayedResults();
        List<GhidraFunctionMatchWithSignature> selectedMatches = new ArrayList<>();
        for (int viewRow : resultsTable.getSelectedRows()) {
            int modelRow = resultsTable.convertRowIndexToModel(viewRow);
            if (modelRow >= 0 && modelRow < resultsToShow.size()) {
                selectedMatches.add(resultsToShow.get(modelRow));
            }
        }
        return selectedMatches;
    }

    protected void onTransferSelected(ApplyMatchCmd.Transfer transfer) {
        if (resultsTable.getSelectedRowCount() == 0) {
            showError("Please select one or more rows to transfer.");
            return;
        }
        hideError();

        transferInBackground(getSelectedMatches(), transfer);
    }

    private void transferInBackground(List<GhidraFunctionMatchWithSignature> matches, ApplyMatchCmd.Transfer transfer) {
        var task = new Task("Transferring " + transfer.label(), true, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                // The portal only stores names, so a signature-only transfer has nothing to push
                if (transfer.includesName()) {
                    batchRenameFunctions(matches);
                }
                int applied = applyMatches(matches, transfer);
                SwingUtilities.invokeLater(() -> statusLabel.setText("Transferred %s to %d of %d function(s)"
                        .formatted(transfer.label().toLowerCase(), applied, matches.size())));
            }
        };
        // Shown in a task dialog: the dialog's progress bar belongs to matching, and is hidden by now
        TaskBuilder.withTask(task).setParent(getComponent()).launchModal();
    }

    protected void batchRenameFunctions(List<GhidraFunctionMatchWithSignature> functionMatches) {
        try {
            revengService.batchRenamingGhidraMatchesWithSignatures(functionMatches);
        } catch (Exception e) {
            Msg.error(this, "Failed to rename functions: " + e.getMessage(), e);
            SwingUtilities.invokeLater(() -> showError("Failed to rename functions: " + e.getMessage()));
        }
    }

    /// Applies the matches to the program and returns how many functions were changed. Matches can be
    /// skipped, e.g. a signature transfer for a match the portal has no signature for.
    protected int applyMatches(List<GhidraFunctionMatchWithSignature> functionMatches, ApplyMatchCmd.Transfer transfer) {
        var program = analyzedProgram.program();
        int[] applied = {0};

        program.withTransaction("Apply Function Matching " + transfer.label(), () -> {
                    for (GhidraFunctionMatchWithSignature match : functionMatches) {
                        // We don't pass a service, because we don't need to update individual functions on the portal
                        // batchRenameFunctions already does that for us
                        var cmd = new ApplyMatchCmd(null, analyzedProgram, match, false, transfer);
                        if (cmd.applyTo(program)) {
                            applied[0]++;
                        }
                    }
                }
        );
        SwingUtilities.invokeLater(this::updateResultsTable);
        return applied[0];
    }

    @Override
    protected void cancelCallback() {
        stopPolling();
        close();
    }
}

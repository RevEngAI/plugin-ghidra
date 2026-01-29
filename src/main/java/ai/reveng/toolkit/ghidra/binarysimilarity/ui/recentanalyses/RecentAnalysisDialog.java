package ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionselection.FunctionSelectionPanel;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.LegacyAnalysisResult;
import ai.reveng.toolkit.ghidra.core.tasks.AttachToAnalysisTask;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.task.TaskBuilder;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Comparator;
import java.util.concurrent.CompletableFuture;


/**
 * Shows a dialog with a table of {@link LegacyAnalysisResult} for a given {@link TypedApiInterface.BinaryHash},
 * and fires an event when the user picks an analysis
 */
public class RecentAnalysisDialog extends RevEngDialogComponentProvider {
    private final RecentAnalysesTableModel recentAnalysesTableModel;
    private final GhidraFilterTable<LegacyAnalysisResult> recentAnalysesTable;
    private final PluginTool tool;
    private final Program program;
    private final GhidraRevengService ghidraRevengService;
    private final FunctionSelectionPanel functionSelectionPanel;
    private JButton pickMostRecentButton;
    private JButton pickSelectedButton;
    private volatile TypedApiInterface.AnalysisID lastFetchedAnalysisID = null;

    public RecentAnalysisDialog(PluginTool tool, Program program) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "Recent Analyses", true);
        this.tool = tool;
        this.program = program;
        this.ghidraRevengService = tool.getService(GhidraRevengService.class);

        var hash = new TypedApiInterface.BinaryHash(program.getExecutableSHA256());
        recentAnalysesTableModel = new RecentAnalysesTableModel(tool, hash, this.program.getImageBase());
        recentAnalysesTable = new GhidraFilterTable<>(recentAnalysesTableModel);

        functionSelectionPanel = new FunctionSelectionPanel(tool);
        functionSelectionPanel.initForProgram(program);

        buildInterface();
        setPreferredSize(1000, 700);

        // When the analyses table finishes loading, auto-select the most recent and fetch its remote functions
        recentAnalysesTableModel.addTableModelListener(e -> {
            if (lastFetchedAnalysisID == null && recentAnalysesTableModel.getRowCount() > 0) {
                selectMostRecentRow();
            }
        });
    }

    private void buildInterface() {
        JPanel mainPanel = new JPanel(new BorderLayout());

        // Create title panel
        JPanel titlePanel = createTitlePanel("Find existing analyses for this binary");
        mainPanel.add(titlePanel, BorderLayout.NORTH);

        // Create the analysis table panel
        JPanel analysisTablePanel = new JPanel(new BorderLayout());
        // Add mouse listener to handle clicks on the Analysis ID column
        recentAnalysesTable.getTable().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 1) {
                    int row = recentAnalysesTable.getTable().rowAtPoint(e.getPoint());
                    int col = recentAnalysesTable.getTable().columnAtPoint(e.getPoint());

                    if (row >= 0 && col >= 0) {
                        // Check if clicked column is "Analysis ID" (column 0)
                        String columnName = recentAnalysesTable.getTable().getColumnName(col);
                        if ("Analysis ID".equals(columnName)) {
                            LegacyAnalysisResult result = recentAnalysesTable.getModel().getRowObject(row);
                            if (result != null) {
                                var analysisID = ghidraRevengService.getApi().getAnalysisIDfromBinaryID(result.binary_id());
                                ghidraRevengService.openPortalFor(analysisID);
                            }
                        }
                    }
                }
            }
        });
        // When the user selects a different analysis row, fetch its remote functions
        recentAnalysesTable.getTable().getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            var selected = recentAnalysesTable.getSelectedRowObject();
            if (selected != null) {
                fetchRemoteFunctions(selected.analysis_id());
            }
        });

        analysisTablePanel.add(recentAnalysesTable, BorderLayout.CENTER);

        // Create split pane with analysis table on top and function selection on bottom
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, analysisTablePanel, functionSelectionPanel);
        splitPane.setResizeWeight(0.4); // Give 40% to analysis table, 60% to function selection
        splitPane.setDividerLocation(200);
        mainPanel.add(splitPane, BorderLayout.CENTER);

        pickMostRecentButton = new JButton("Pick most recent");
        pickMostRecentButton.setName("Pick most recent");
        pickMostRecentButton.addActionListener(e -> {
            var mostRecent = recentAnalysesTable.getModel().getModelData().stream().max(
                    Comparator.comparing(LegacyAnalysisResult::creation)
            ).orElseThrow();
            pickAnalysis(mostRecent);
        });
        addButton(pickMostRecentButton);

        pickSelectedButton = new JButton("Pick selected");
        pickSelectedButton.setName("Pick selected");
        pickSelectedButton.addActionListener(e -> {
            var selectedRowObject = recentAnalysesTable.getSelectedRowObject();
            pickAnalysis(selectedRowObject);
        });
        addButton(pickSelectedButton);

        functionSelectionPanel.getTableModel().addTableModelListener(e -> updatePickButtonsState());
        updatePickButtonsState();

        addWorkPanel(mainPanel);
    }

    private void updatePickButtonsState() {
        boolean hasSelection = functionSelectionPanel.getSelectedCount() > 0;
        pickMostRecentButton.setEnabled(hasSelection);
        pickSelectedButton.setEnabled(hasSelection);
    }

    private void selectMostRecentRow() {
        var modelData = recentAnalysesTableModel.getModelData();
        var mostRecent = modelData.stream()
                .max(Comparator.comparing(LegacyAnalysisResult::creation))
                .orElse(null);
        if (mostRecent == null) {
            return;
        }
        // Find the view index for this row and select it — triggers the selection listener
        var table = recentAnalysesTable.getTable();
        for (int i = 0; i < table.getRowCount(); i++) {
            if (recentAnalysesTable.getModel().getRowObject(i) == mostRecent) {
                table.setRowSelectionInterval(i, i);
                break;
            }
        }
    }

    private void fetchRemoteFunctions(TypedApiInterface.AnalysisID analysisID) {
        if (analysisID.equals(lastFetchedAnalysisID)) {
            return;
        }
        lastFetchedAnalysisID = analysisID;
        var api = ghidraRevengService.getApi();

        CompletableFuture.supplyAsync(() -> api.getFunctionInfo(analysisID))
                .thenAccept(remoteFunctions -> Swing.runLater(() -> {
                    functionSelectionPanel.applyRemoteFunctionInfo(remoteFunctions);
                    updatePickButtonsState();
                }))
                .exceptionally(ex -> {
                    Msg.warn(this, "Failed to fetch remote function info for " + analysisID + ": " + ex.getMessage());
                    return null;
                });
    }

    /// Currently [[ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses.RecentAnalysesTableModel#doLoad]]
    /// only allows selecting a complete analysis. This simplifies the logic around the function selection panel.
    ///
    private void pickAnalysis(LegacyAnalysisResult result) {
        var service = tool.getService(GhidraRevengService.class);
        var analysisID = service.getApi().getAnalysisIDfromBinaryID(result.binary_id());
        // Register the analysis ID with the program (persists to program options)
        var programWithId = service.registerAnalysisForProgram(program, analysisID);

        // Get the selected functions from the function selection panel
        var selectedFunctions = functionSelectionPanel.getSelectedFunctions();

        // Create and run the attach task modally - blocks until complete
        var task = new AttachToAnalysisTask(programWithId, selectedFunctions, service, tool);
        TaskBuilder.withTask(task)
                .setCanCancel(false)
                .setStatusTextAlignment(SwingConstants.LEADING)
                .launchModal();

        // Close the dialog after task completes
        close();
    }
}

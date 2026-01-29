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
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.task.TaskBuilder;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Comparator;


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
        setPreferredSize(600, 650);
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
        analysisTablePanel.add(recentAnalysesTable, BorderLayout.CENTER);

        // Create split pane with analysis table on top and function selection on bottom
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, analysisTablePanel, functionSelectionPanel);
        splitPane.setResizeWeight(0.4); // Give 40% to analysis table, 60% to function selection
        splitPane.setDividerLocation(200);
        mainPanel.add(splitPane, BorderLayout.CENTER);

        JButton pickMostRecentButton = new JButton("Pick most recent");
        pickMostRecentButton.setName("Pick most recent");
        pickMostRecentButton.addActionListener(e -> {
            var mostRecent = recentAnalysesTable.getModel().getModelData().stream().max(
                    Comparator.comparing(LegacyAnalysisResult::creation)
            ).orElseThrow();
            pickAnalysis(mostRecent);
        });
        addButton(pickMostRecentButton);

        JButton pickSelectedButton = new JButton("Pick selected");
        pickSelectedButton.setName("Pick selected");
        pickSelectedButton.addActionListener(e -> {
            var selectedRowObject = recentAnalysesTable.getSelectedRowObject();
            pickAnalysis(selectedRowObject);
        });
        addButton(pickSelectedButton);

        addWorkPanel(mainPanel);
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

package ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.LegacyAnalysisResult;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.table.GhidraFilterTable;

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

    public RecentAnalysisDialog(PluginTool tool, Program program) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "Recent Analyses", true);
        this.tool = tool;
        this.program = program;
        this.ghidraRevengService = tool.getService(GhidraRevengService.class);

        var hash = new TypedApiInterface.BinaryHash(program.getExecutableSHA256());
        recentAnalysesTableModel = new RecentAnalysesTableModel(tool, hash, this.program.getImageBase());
        recentAnalysesTable = new GhidraFilterTable<>(recentAnalysesTableModel);

        buildInterface();
        setPreferredSize(600, 400);
    }

    private void buildInterface() {
        JPanel mainPanel = new JPanel(new BorderLayout());

        // Create title panel
        JPanel titlePanel = createTitlePanel("Find existing analyses for this binary");
        mainPanel.add(titlePanel, BorderLayout.NORTH);

        // Create the table content
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
        mainPanel.add(recentAnalysesTable, BorderLayout.CENTER);

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

    private void pickAnalysis(LegacyAnalysisResult result) {
        var service = tool.getService(GhidraRevengService.class);
        var analysisID = service.getApi().getAnalysisIDfromBinaryID(result.binary_id());
        var programWithID = new GhidraRevengService.ProgramWithID(program, analysisID);

        tool.firePluginEvent(
                new RevEngAIAnalysisStatusChangedEvent(
                        "Recent Analysis Dialog",
                        programWithID,
                        result.status()
                )
        );
        close();
    }
}

package ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.model.AnalysisRecordBody;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Comparator;


/**
 * Shows a dialog with a table of {@link AnalysisRecordBody} for a given {@link TypedApiInterface.BinaryHash},
 * and fires an event when the user picks an analysis
 */
public class RecentAnalysisDialog extends RevEngDialogComponentProvider {
    private final RecentAnalysesTableModel recentAnalysesTableModel;
    private final GhidraFilterTable<AnalysisRecordBody> recentAnalysesTable;
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
                            AnalysisRecordBody result = recentAnalysesTable.getModel().getRowObject(row);
                            if (result != null) {
                                var analysisID = new TypedApiInterface.AnalysisID(Math.toIntExact(result.getAnalysisId()));
                                tool.execute(new Task("Open analysis in portal", false, false, false) {
                                    @Override
                                    public void run(TaskMonitor monitor) {
                                        try {
                                            ghidraRevengService.openPortalFor(analysisID);
                                        } catch (Exception ex) {
                                            Msg.error(RecentAnalysisDialog.this, "Failed to open analysis in portal: " + ex.getMessage(), ex);
                                        }
                                    }
                                }, 0);
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
                    Comparator.comparing(AnalysisRecordBody::getCreation)
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

    private void pickAnalysis(AnalysisRecordBody result) {
        var service = tool.getService(GhidraRevengService.class);
        tool.execute(new Task("Attach to analysis", true, false, false) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    var analysisID = new TypedApiInterface.AnalysisID(Math.toIntExact(result.getAnalysisId()));
                    var programWithID = service.registerAnalysisForProgram(program, analysisID);
                    SwingUtilities.invokeLater(() -> {
                        tool.firePluginEvent(
                                new RevEngAIAnalysisStatusChangedEvent(
                                        "Recent Analysis Dialog",
                                        programWithID,
                                        // The table only holds analyses the model filtered to Complete
                                        AnalysisStatus.Complete
                                )
                        );
                        close();
                    });
                } catch (Exception ex) {
                    Msg.error(RecentAnalysisDialog.this, "Failed to attach to analysis: " + ex.getMessage(), ex);
                }
            }
        }, 0);
    }
}

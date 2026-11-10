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
    private final JPopupMenu portalPopup = new JPopupMenu();

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

        // Consuming the right-click keeps the dialog's docking popup, with its tool-wide actions, from appearing
        JMenuItem openInPortalItem = new JMenuItem("Open in Portal");
        openInPortalItem.addActionListener(e -> {
            var selected = recentAnalysesTable.getSelectedRowObject();
            if (selected != null) {
                ghidraRevengService.openPortalFor(tool,
                        new TypedApiInterface.AnalysisID(Math.toIntExact(selected.getAnalysisId())));
            }
        });
        portalPopup.add(openInPortalItem);
        recentAnalysesTable.getTable().addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                showPortalPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPortalPopup(e);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
                    var selected = recentAnalysesTable.getSelectedRowObject();
                    if (selected != null) {
                        pickAnalysis(selected);
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

    private void showPortalPopup(MouseEvent e) {
        if (!e.isPopupTrigger()) {
            return;
        }
        e.consume();
        JTable table = recentAnalysesTable.getTable();
        int row = table.rowAtPoint(e.getPoint());
        if (row >= 0) {
            table.setRowSelectionInterval(row, row);
            portalPopup.show(table, e.getX(), e.getY());
        }
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

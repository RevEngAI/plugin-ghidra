package ai.reveng.toolkit.ghidra.binarysimilarity.ui.collectiondialog;

import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import docking.action.builder.ActionBuilder;
import generic.theme.GIcon;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import java.awt.*;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * This component serves as the central control for searching and selecting collections
 * <p>
 * <p>
 * <p>
 * Currently, collections are "flat", and effectively a set of {@link TypedApiInterface.AnalysisID} <br>
 * In the future they may support hierarchies/nesting<br>
 * <p>
 * This dialog allows sharing the collection choice logic between all components that need to select a collection,
 * and allows easy refactoring later, e.g. switching to a tree view when collections support nesting.
 */
public class DataSetControlPanelComponent extends ComponentProviderAdapter {
    private CollectionTableModel collectionsModel;
    private BinaryTableModel binaryTableModel;

    private GhidraFilterTable<CollectionRowObject> collectionsTable;
    private GhidraFilterTable<BinaryRowObject> binaryTable;

    private JTabbedPane tabbedPanel;
    private JPanel collectionsPanel;
    private JPanel binaryPanel;

    public DataSetControlPanelComponent(PluginTool tool, String owner) {
        super(tool, ReaiPluginPackage.WINDOW_PREFIX + "Dataset Control Panel", owner);
        setIcon(ReaiPluginPackage.REVENG_16);

        tabbedPanel = new JTabbedPane(JTabbedPane.TOP);

        collectionsPanel = buildCollectionPanel(tool);
        tabbedPanel.addTab("Collections", collectionsPanel);

        binaryPanel = buildBinaryPanel(tool);
        tabbedPanel.addTab("Binaries", binaryPanel);


        new ActionBuilder("Clear Collections", getOwner())
                .menuPath("Clear Collections")
                .toolBarIcon(new GIcon("icon.clear"))
                .onAction(ac -> {
                    collectionsModel.clearData();
                    binaryTableModel.clearData();
                    collectionsModel.storeCollectionsInService();
                    binaryTableModel.storeBinaryFiltersInService();
                })
                .buildAndInstallLocal(this);


        new ActionBuilder("Open Collection in Portal", getOwner())
                .popupMenuPath("Open Collection in Portal")
                .popupMenuIcon(ReaiPluginPackage.REVENG_16)
                .enabledWhen(ac -> tabbedPanel.getSelectedIndex() == 0 && collectionsTable.getSelectedRowObject() != null)
                .onAction(ac -> {
                    var selectedRowObject = collectionsTable.getSelectedRowObject();
                    tool.getService(GhidraRevengService.class)
                            .openPortalFor(selectedRowObject.getCollection());
                })
                .buildAndInstallLocal(this);

        new ActionBuilder("Open Analysis in Portal", getOwner())
                .popupMenuPath("Open Analysis in Portal")
                .popupMenuIcon(ReaiPluginPackage.REVENG_16)
                .enabledWhen(ac -> tabbedPanel.getSelectedIndex() == 1 && binaryTable.getSelectedRowObject() != null)
                .onAction(
                        ac -> tool
                                .getService(GhidraRevengService.class)
                                .openPortalFor(binaryTable.getSelectedRowObject().analysisResult()))
                .buildAndInstallLocal(this);


    }

    private JPanel buildCollectionPanel(PluginTool tool) {
        var collectionsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        collectionsModel = new CollectionTableModel(tool);
        collectionsPanel.setLayout(new BorderLayout(0, 0));
        collectionsTable = new GhidraFilterTable<>(collectionsModel);

        collectionsPanel.add(collectionsTable);
        var collectionSearchTextbox = new JTextField();
        collectionSearchTextbox.setColumns(10);
        var btnFetchCollections = new JButton("Load Matching Collections");
        btnFetchCollections.setEnabled(true);
        btnFetchCollections.addActionListener(e -> {
            tool.execute(new Task("Fetching Collections", false, false, false) {
                @Override
                public void run(TaskMonitor monitor) throws CancelledException {
                    var serv = tool.getService(GhidraRevengService.class);
                    // Get all rows that are already selected to be included
                    var selectedCollections = collectionsModel.getModelData().stream().filter(CollectionRowObject::isInclude).toList();

                    var selectedSet = selectedCollections.stream().map(CollectionRowObject::getCollectionName).collect(Collectors.toSet());
                    collectionsModel.clearData();

                    var searchTerm = collectionSearchTextbox.getText();
                    serv.getApi().searchCollections(searchTerm, null, 50, 0, null, null).forEach(collection -> {
                                if (!selectedSet.contains(collection.collectionName())) {
                                    collectionsModel.addObject(new CollectionRowObject(collection, false));
                                }
                            }

                    );

                    // Add the previously selected models back
                    selectedCollections.forEach(collection -> collectionsModel.addObject(collection));
                }
            }, 500);
        });

        var collectionBtnPnl = new JPanel(new FlowLayout(FlowLayout.CENTER));

        collectionBtnPnl.add(collectionSearchTextbox);
        collectionBtnPnl.add(btnFetchCollections);

        collectionsPanel.add(collectionBtnPnl, BorderLayout.SOUTH);

        return collectionsPanel;
    }

    private JPanel buildBinaryPanel(PluginTool tool) {
        var binaryPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        binaryPanel.setLayout(new BorderLayout(0, 0));
        binaryTableModel = new BinaryTableModel(tool);
        binaryTable = new GhidraFilterTable<>(binaryTableModel);
        binaryPanel.add(binaryTable, BorderLayout.CENTER);
        var analysisSearchTextBox = new JTextField();
        analysisSearchTextBox.setColumns(20);

        var btnFetchAnalyses = new JButton("Load Matching Analyses");
        btnFetchAnalyses.setEnabled(true);
        btnFetchAnalyses.addActionListener(e -> {
            tool.execute(new Task("Fetching Analysis", false, false, false) {
                @Override
                public void run(TaskMonitor monitor) throws CancelledException {
                    var serv = tool.getService(GhidraRevengService.class);
                    // Get all rows that are already selected to be included
                    var selectedBinaries = binaryTableModel.getModelData().stream().filter(BinaryRowObject::include).toList();
//
                    Set<TypedApiInterface.AnalysisID> selectedSet = selectedBinaries.stream().map(row -> row.analysisResult().analysisID() ).collect(Collectors.toSet());
                    binaryTableModel.clearData();
//
                    var searchTerm = analysisSearchTextBox.getText();
                    serv.getApi().searchBinaries(searchTerm).forEach(analysisID-> {
                                if (!selectedSet.contains(analysisID)) {
                                    var analysis = serv.getApi().getInfoForAnalysis(analysisID);
                                    binaryTableModel.addObject(new BinaryRowObject(analysis, false));
                                }
                            }

                    );
//
//                    // Add the previously selected models back
//                    selectedBinaries.forEach(collection -> collectionsModel.addObject(collection));
                }
            }, 500);
        });

        var binaryBtnPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        binaryBtnPanel.add(analysisSearchTextBox);
        binaryBtnPanel.add(btnFetchAnalyses);

        binaryPanel.add(binaryBtnPanel, BorderLayout.SOUTH);

        return binaryPanel;
    }

    public void reloadFromService() {
        collectionsModel.reload();
        binaryTableModel.reload();

        if (collectionsModel.getModelData().isEmpty() && !binaryTableModel.getModelData().isEmpty()) {
            tabbedPanel.setSelectedIndex(1);
        }

    }

    @Override
    public JComponent getComponent() {
        return tabbedPanel;
    }
}

package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching;

import ai.reveng.model.GetMatchesOutputBody;
import ai.reveng.model.GetMatchesStatusOutputBody;
import ai.reveng.model.StartMatchingForFunctionsInputBody;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ai.reveng.toolkit.ghidra.binarysimilarity.cmds.ApplyMatchCmd;
import ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.Utils;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import docking.widgets.table.GDynamicColumnTableModel;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.TableSortState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.Task;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorComponent;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import java.awt.*;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Window that automatically fetches and displays similar functions for the currently selected function.
 * Shows a table of matches on the left and an assembly diff panel on the right.
 */
public class SimilarFunctionsWindow extends ComponentProviderAdapter {

    private final JComponent component;
    private GhidraTable matchesTable;
    private SimilarFunctionsTableModel tableModel;
    private AssemblyDiffPanel assemblyDiffPanel;
    private JSplitPane splitPane;
    private JLabel statusLabel;
    private TaskMonitorComponent taskMonitorComponent;

    private GhidraRevengService.FunctionWithID currentFunctionWithID;
    private GhidraRevengService.AnalysedProgram analyzedProgram;
    private final Map<Function, List<GhidraFunctionMatchWithSignature>> matchCache = new java.util.concurrent.ConcurrentHashMap<>();

    public SimilarFunctionsWindow(PluginTool tool) {
        super(tool, ReaiPluginPackage.WINDOW_PREFIX + "Similar Functions", BinarySimilarityPlugin.class.getName());
        setIcon(ReaiPluginPackage.REVENG_16);
        component = buildComponent();
        createToolbarActions();
    }

    private JComponent buildComponent() {
        JPanel mainPanel = new JPanel(new BorderLayout());

        // Status bar at top
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusLabel = new JLabel("No function selected");
        taskMonitorComponent = new TaskMonitorComponent(false, true);
        taskMonitorComponent.setVisible(false);
        taskMonitorComponent.setIndeterminate(true);
        statusPanel.add(statusLabel, BorderLayout.CENTER);
        statusPanel.add(taskMonitorComponent, BorderLayout.EAST);
        mainPanel.add(statusPanel, BorderLayout.NORTH);

        // Split pane: matches table on left, assembly diff on right
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.4); // Give 40% to the table

        // Left side: Matches table
        JPanel tablePanel = createMatchesTablePanel();
        splitPane.setLeftComponent(tablePanel);

        // Right side: Assembly diff panel (reuse existing component)
        assemblyDiffPanel = new AssemblyDiffPanel();
        splitPane.setRightComponent(assemblyDiffPanel);

        mainPanel.add(splitPane, BorderLayout.CENTER);

        return mainPanel;
    }

    private JPanel createMatchesTablePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Similar Functions"));

        tableModel = new SimilarFunctionsTableModel(tool);
        matchesTable = new GhidraTable(tableModel);
        matchesTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        matchesTable.getSelectionModel().addListSelectionListener(this::onMatchSelected);

        // Add context menu action to open matched function in portal
        createTableActions();

        JScrollPane scrollPane = new JScrollPane(matchesTable);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Returns the currently selected match in the table, or null if no valid selection.
     */
    private GhidraFunctionMatchWithSignature getSelectedMatch() {
        int selectedRow = matchesTable.getSelectedRow();
        if (selectedRow < 0) {
            return null;
        }
        int modelRow = matchesTable.convertRowIndexToModel(selectedRow);
        return tableModel.getRowObject(modelRow);
    }

    private void createTableActions() {
        DockingAction openInPortalAction = new DockingAction("View Match in Portal", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                var match = getSelectedMatch();
                if (match != null) {
                    var service = tool.getService(GhidraRevengService.class);
                    service.openFunctionInPortal(match.functionMatch().nearest_neighbor_id());
                }
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return getSelectedMatch() != null;
            }
        };

        openInPortalAction.setPopupMenuData(new MenuData(
            new String[] { "View Match in Portal" },
            ReaiPluginPackage.REVENG_16,
            ReaiPluginPackage.MENU_GROUP_NAME
        ));

        addLocalAction(openInPortalAction);

        DockingAction applyMatchAction = new DockingAction("Apply Match", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                var match = getSelectedMatch();
                if (match != null && analyzedProgram != null) {
                    var service = tool.getService(GhidraRevengService.class);
                    var cmd = new ApplyMatchCmd(service, analyzedProgram, match, true);
                    cmd.applyWithTransaction();
                }
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return getSelectedMatch() != null && analyzedProgram != null;
            }
        };

        applyMatchAction.setPopupMenuData(new MenuData(
            new String[] { "Apply Match" },
            ReaiPluginPackage.REVENG_16,
            ReaiPluginPackage.MENU_GROUP_NAME
        ));

        addLocalAction(applyMatchAction);
    }

    private void createToolbarActions() {
        ToggleDockingAction toggleDiffPanelAction = new ToggleDockingAction("Hide Assembly Diff", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                setAssemblyDiffVisible(isSelected());
            }
        };
        toggleDiffPanelAction.setSelected(true);
        toggleDiffPanelAction.setToolBarData(new ToolBarData(new GIcon("icon.plugin.programdiff.get.diffs"), null));
        toggleDiffPanelAction.setDescription("Toggle assembly diff panel visibility");

        addLocalAction(toggleDiffPanelAction);

        DockingAction reloadAction = new DockingAction("Reload Matches", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                reloadMatches();
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return currentFunctionWithID != null;
            }
        };
        reloadAction.setToolBarData(new ToolBarData(new GIcon("icon.refresh"), null));
        reloadAction.setDescription("Reload matches for current function (bypass cache)");

        addLocalAction(reloadAction);
    }

    private void reloadMatches() {
        if (currentFunctionWithID == null) {
            return;
        }
        // Remove from cache to force a fresh fetch
        matchCache.remove(currentFunctionWithID.function());
        fetchSimilarFunctions();
    }

    private void setAssemblyDiffVisible(boolean visible) {
        if (visible) {
            splitPane.setRightComponent(assemblyDiffPanel);
            splitPane.setDividerLocation(0.4);
        } else {
            splitPane.setRightComponent(null);
        }
        splitPane.revalidate();
    }

    @Override
    public JComponent getComponent() {
        return component;
    }

    @Override
    public void componentShown() {
        // When the window becomes visible, fetch matches if we have a current function
        // but haven't fetched yet (handles race condition where location changed before window was visible)
        if (currentFunctionWithID != null && !matchCache.containsKey(currentFunctionWithID.function())) {
            fetchSimilarFunctions();
        }
    }

    /**
     * Called when the program is not analyzed with RevEng.AI
     */
    public void onNoAnalyzedProgram() {
        clear();
        statusLabel.setText("Binary not analyzed with RevEng.AI");
    }

    /**
     * Called when the cursor is not within a function
     */
    public void onNoFunction() {
        clear();
        statusLabel.setText("No function at current location");
    }

    /**
     * Called when the function exists locally but is not in the RevEng.AI analysis
     */
    public void onFunctionNotInAnalysis(Function func) {
        clear();
        statusLabel.setText("Function not found in RevEng.AI analysis");
    }

    /**
     * Called when the cursor moves to a function that is in the RevEng.AI analysis
     */
    public void onFunctionChanged(GhidraRevengService.FunctionWithID functionWithID, GhidraRevengService.AnalysedProgram newAnalyzedProgram) {
        var newFunction = functionWithID.function();
        // If we changed to a different function, fetch new matches
        var currentFunction = currentFunctionWithID != null ? currentFunctionWithID.function() : null;
        if (currentFunction != newFunction) {
            clear();
            currentFunctionWithID = functionWithID;
            analyzedProgram = newAnalyzedProgram;
            fetchSimilarFunctions();
        }
    }

    private void clear() {
        currentFunctionWithID = null;
        tableModel.setData(Collections.emptyList());
        assemblyDiffPanel.clear();
    }

    private void fetchSimilarFunctions() {
        if (!isVisible()) {
            return;
        }

        if (currentFunctionWithID == null) {
            return;
        }

        var currentFunction = currentFunctionWithID.function();

        // Check cache first
        if (matchCache.containsKey(currentFunction)) {
            displayMatches(matchCache.get(currentFunction));
            return;
        }

        statusLabel.setText("Fetching similar functions for " + currentFunction.getName() + "...");
        taskMonitorComponent.setVisible(true);

        // Start background task to fetch matches
        var task = new FetchSimilarFunctionsTask(analyzedProgram, currentFunctionWithID);
        TaskBuilder.withTask(task).launchInBackground(taskMonitorComponent);
    }

    private void displayMatches(List<GhidraFunctionMatchWithSignature> matches) {
        tableModel.setData(matches);

        // Clear the assembly diff panel when showing new matches
        assemblyDiffPanel.clear();

        var functionName = currentFunctionWithID != null ? currentFunctionWithID.function().getName() : "unknown";
        statusLabel.setText("Found " + matches.size() + " similar functions for " + functionName);
        taskMonitorComponent.setVisible(false);
    }

    private void onMatchSelected(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) {
            return;
        }

        var match = getSelectedMatch();
        if (match == null) {
            assemblyDiffPanel.clear();
            return;
        }

        // Use the AssemblyDiffPanel to show the comparison
        var service = tool.getService(GhidraRevengService.class);
        assemblyDiffPanel.showAssemblyFor(match, service);
    }

    public void locationChanged(ProgramLocation loc) {
        var service = tool.getService(GhidraRevengService.class);
        var optAnalysedProgram = service.getAnalysedProgram(loc.getProgram());
        if (optAnalysedProgram.isEmpty()) {
            clear();
            return;
        }
        var newAnalyzedProgram = optAnalysedProgram.get();

        var functionMgr = loc.getProgram().getFunctionManager();
        var func = functionMgr.getFunctionContaining(loc.getAddress());
        if (func == null) {
            onNoFunction();
            return;
        }

        var functionWithID = newAnalyzedProgram.getIDForFunction(func);
        if (functionWithID.isEmpty()) {
            onFunctionNotInAnalysis(func);
            return;
        }

        onFunctionChanged(functionWithID.get(), newAnalyzedProgram);

    }

    /**
     * Table model for displaying similar function matches.
     * Extends GDynamicColumnTableModel for dynamic column support with hidden columns.
     */
    private static class SimilarFunctionsTableModel extends GDynamicColumnTableModel<GhidraFunctionMatchWithSignature, Object> {
        private List<GhidraFunctionMatchWithSignature> data = Collections.emptyList();

        private static final int COL_SIMILARITY = 1;

        public SimilarFunctionsTableModel(ServiceProvider serviceProvider) {
            super(serviceProvider);
            // Sort by similarity (descending) by default - highest matches first
            setDefaultTableSortState(TableSortState.createDefaultSortState(COL_SIMILARITY, false));
        }

        @Override
        public String getName() {
            return "Similar Functions";
        }

        public void setData(List<GhidraFunctionMatchWithSignature> matches) {
            this.data = matches != null ? new ArrayList<>(matches) : Collections.emptyList();
            fireTableDataChanged();
        }

        @Override
        public List<GhidraFunctionMatchWithSignature> getModelData() {
            return data;
        }

        @Override
        public Void getDataSource() {
            return null;
        }

        @Override
        protected TableColumnDescriptor<GhidraFunctionMatchWithSignature> createTableColumnDescriptor() {
            TableColumnDescriptor<GhidraFunctionMatchWithSignature> descriptor = new TableColumnDescriptor<>();

            Utils.addRowToDescriptor(descriptor, "Function Name", String.class,
                m -> m.functionMatch().nearest_neighbor_function_name());
            Utils.addRowToDescriptor(descriptor, "Similarity", BigDecimal.class,
                m -> m.functionMatch().similarity());
            Utils.addRowToDescriptor(descriptor, "Confidence", BigDecimal.class,
                m -> m.functionMatch().confidence());
            Utils.addRowToDescriptor(descriptor, "Binary", String.class,
                m -> m.functionMatch().nearest_neighbor_binary_name());
            Utils.addRowToDescriptor(descriptor, "Signature", String.class,
                m -> m.signature() != null ? m.signature().getPrototypeString() : "");
            Utils.addRowToDescriptor(descriptor, "Function ID", false, Long.class,
                m -> m.functionMatch().nearest_neighbor_id().value());

            return descriptor;
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    }

    /**
     * Task to fetch similar functions from the API
     */
    private class FetchSimilarFunctionsTask extends Task {
        private final GhidraRevengService.AnalysedProgram program;
        private final GhidraRevengService.FunctionWithID functionWithID;

        public FetchSimilarFunctionsTask(GhidraRevengService.AnalysedProgram program, GhidraRevengService.FunctionWithID functionWithID) {
            super("Fetch Similar Functions", true, false, false);
            this.functionWithID = functionWithID;
            this.program = program;
        }

        @Override
        public void run(TaskMonitor monitor) {
            try {
                var service = tool.getService(GhidraRevengService.class);

                var functionIds = List.of(functionWithID.functionID().value());

                var request = new StartMatchingForFunctionsInputBody();
                request.setFunctionIds(functionIds);
                request.setMinSimilarity(70.0); // Default threshold
                request.setResultsPerFunction(25L);

                monitor.setMessage("Fetching matches from RevEng.AI...");
                service.startFunctionsMatching(request);

                while (true) {
                    if (monitor.isCancelled()) {
                        return;
                    }
                    GetMatchesStatusOutputBody statusResponse = service.getFunctionsMatchingStatus(functionIds);
                    String status = statusResponse.getStatus() == null ? null : statusResponse.getStatus().getValue();
                    if ("COMPLETED".equals(status)) {
                        break;
                    }
                    if ("FAILED".equals(status)) {
                        String errorMsg = AbstractFunctionMatchingDialog.errorTextFrom(statusResponse.getMessages());
                        throw new RuntimeException(errorMsg == null || errorMsg.isEmpty()
                                ? "Function matching failed" : errorMsg);
                    }
                    Thread.sleep(100);
                }

                GetMatchesOutputBody response = service.getFunctionsMatches(functionIds);

                // Process results
                List<GhidraFunctionMatch> matches = new ArrayList<>();
                if (response.getMatches() != null) {
                    for (var matchResult : response.getMatches()) {
                        if (matchResult.getMatchedFunctions() == null) {
                            continue;
                        }
                        for (var matched : matchResult.getMatchedFunctions()) {
                            var funcId = new TypedApiInterface.FunctionID(matchResult.getFunctionId());
                            FunctionMatch fm = FunctionMatch.fromMatchedFunctionAPIType(matched, funcId);
                            GhidraFunctionMatch match = new GhidraFunctionMatch(functionWithID.function(), fm);
                            matches.add(match);
                        }
                    }
                }
                var ghidraResultsWithSignatures = service.getSignatures(matches);
                // For all matches we got, create a GhidraFunctionMatchWithSignature object (signature can be null!)
                var result = matches.stream().map(
                        m -> m.withSignature(ghidraResultsWithSignatures.get(m))
                ).toList();
                // Cache and display
                matchCache.put(functionWithID.function(), result);

                SwingUtilities.invokeLater(() -> displayMatches(result));

            } catch (Exception e) {
                Msg.error(this, "Failed to fetch similar functions: " + e.getMessage(), e);
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Error fetching similar functions: " + e.getMessage());
                    taskMonitorComponent.setVisible(false);
                });
            }
        }
    }
}

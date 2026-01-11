package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching;

import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;

import javax.swing.*;
import java.awt.*;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Objects;

public class FunctionLevelFunctionMatchingDialog extends AbstractFunctionMatchingDialog {
    private final Function function;

    public FunctionLevelFunctionMatchingDialog(PluginTool tool, GhidraRevengService.AnalysedProgram programWithBinaryID, Function function) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "Function Matching", true,
              tool.getService(GhidraRevengService.class), programWithBinaryID);
        this.function = function;
    }

    @Override
    protected void pollFunctionMatchingStatus() {
        SwingUtilities.invokeLater(() -> {
            try {
                var request = new FunctionMatchingRequest();
                request.setMinSimilarity(BigDecimal.valueOf(getThreshold()));
                request.setResultsPerFunction(25); // TODO: Make configurable?
                request.setModelId(analysisBasicInfo.getModelId());

                var functionIDOpt = analyzedProgram.getIDForFunction(function);
                if (functionIDOpt.isEmpty()) {
                    handleError("Could not find function ID for the selected function");
                    stopPolling();
                    return;
                }

                var functionIds = new ArrayList<Long>();
                functionIds.add(functionIDOpt.get().functionID().value());

                request.setFunctionIds(functionIds);

                var filters = new FunctionMatchingFilters();
                filters.setCollectionIds(collectionSelector.getSelectedCollectionIds().stream().toList());
                filters.setBinaryIds(binarySelector.getSelectedBinaryIds().stream().toList());

                if (isDebugSymbolsEnabled()) {
                    var debugTypes = new ArrayList<FunctionMatchingFilters.DebugTypesEnum>();
                    debugTypes.add(FunctionMatchingFilters.DebugTypesEnum.SYSTEM);

                    if (isUserSubmittedDebugSymbolsEnabled()) {
                        debugTypes.add(FunctionMatchingFilters.DebugTypesEnum.USER);
                    }

                    filters.setDebugTypes(debugTypes);
                }

                request.setFilters(filters);

                functionMatchingResponse = revengService.getFunctionMatchingForFunction(request);
                updateUI();

                // Check if we hit an error status
                if (Objects.equals(functionMatchingResponse.getStatus(), "ERROR")) {
                    stopPolling();
                    taskMonitorComponent.setVisible(false);
                    String errorMsg = functionMatchingResponse.getErrorMessage() != null && !functionMatchingResponse.getErrorMessage().isEmpty()
                        ? functionMatchingResponse.getErrorMessage()
                        : "Function matching returned an error status";
                    handleError(errorMsg);
                    return;
                }

                // Check if we're done
                if (functionMatchingResponse.getProgress() != null &&
                    (functionMatchingResponse.getProgress() >= 100 || Objects.equals(functionMatchingResponse.getStatus(), "COMPLETED"))) {
                    stopPolling();
                    taskMonitorComponent.setVisible(false);
                    processFunctionMatchingResults(functionMatchingResponse);
                }
            } catch (Exception e) {
                handleError("Failed to poll function matching status: " + e.getMessage());
                stopPolling();
            }
        });
    }

    @Override
    protected String[] getTableColumnNames() {
        return new String[]{"Matched Function", "Similarity", "Confidence", "Matched Hash", "Matched Binary"};
    }

    @Override
    protected Object[] getTableRowData(GhidraFunctionMatchWithSignature result) {
        return new Object[]{
            result.functionMatch().nearest_neighbor_function_name(),
            result.functionMatch().similarity(),
            result.functionMatch().confidence(),
            result.functionMatch().nearest_neighbor_sha_256_hash().sha256(),
            result.functionMatch().nearest_neighbor_binary_name()
        };
    }

    @Override
    protected String getTableTitle() {
        return "Function Matching Results";
    }

    @Override
    protected int getTableSelectionMode() {
        return ListSelectionModel.SINGLE_SELECTION;
    }

    @Override
    protected void configureTableColumns() {
        if (resultsTable.getColumnCount() > 0) {
            // Set color-coded renderer for Similarity column (index 1)
            resultsTable.getColumnModel().getColumn(1).setCellRenderer(new PercentageColorCellRenderer());

            // Set color-coded renderer for Confidence column (index 2)
            resultsTable.getColumnModel().getColumn(2).setCellRenderer(new PercentageColorCellRenderer());

            // Configure sorting for percentage columns
            configurePercentageColumnSorting(1, 2);

            // Set column widths
            resultsTable.getColumnModel().getColumn(0).setPreferredWidth(150);  // Best Match
            resultsTable.getColumnModel().getColumn(1).setPreferredWidth(80);   // Similarity
            resultsTable.getColumnModel().getColumn(2).setPreferredWidth(80);   // Confidence
            resultsTable.getColumnModel().getColumn(3).setPreferredWidth(100);  // Matched Hash
            resultsTable.getColumnModel().getColumn(4).setPreferredWidth(120);  // Binary

            // Set minimum widths
            resultsTable.getColumnModel().getColumn(0).setMinWidth(100);
            resultsTable.getColumnModel().getColumn(1).setMinWidth(60);
            resultsTable.getColumnModel().getColumn(2).setMinWidth(60);
            resultsTable.getColumnModel().getColumn(3).setMinWidth(80);
            resultsTable.getColumnModel().getColumn(4).setMinWidth(80);
        }
    }

    @Override
    protected String getDialogDescription() {
        return "Match this function against previously seen samples";
    }

    @Override
    protected boolean matchesFilter(GhidraFunctionMatchWithSignature result) {
        String filterText = functionFilterField.getText().trim().toLowerCase();
        return result.functionMatch().nearest_neighbor_function_name().toLowerCase().contains(filterText) ||
               result.functionMatch().nearest_neighbor_sha_256_hash().sha256().toLowerCase().contains(filterText) ||
               result.functionMatch().nearest_neighbor_binary_name().toLowerCase().contains(filterText);
    }

    @Override
    protected JPanel createRenameButtonsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        // Only show "Rename Selected" button for function-level matching
        // since we're only matching a single function
        JButton renameSelectedButton = new JButton("Rename Selected");
        renameSelectedButton.addActionListener(e -> onRenameSelectedButtonClicked());
        panel.add(renameSelectedButton);

        return panel;
    }
}

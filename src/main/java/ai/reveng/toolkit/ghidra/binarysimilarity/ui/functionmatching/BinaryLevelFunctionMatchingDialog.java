package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching;

import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ghidra.framework.plugintool.PluginTool;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.program.model.listing.Function;

import javax.swing.*;
import java.awt.*;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Objects;

public class BinaryLevelFunctionMatchingDialog extends AbstractFunctionMatchingDialog {

    public BinaryLevelFunctionMatchingDialog(PluginTool tool, GhidraRevengService.AnalysedProgram programWithBinaryID) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "Function Matching", true,
              tool.getService(GhidraRevengService.class), programWithBinaryID);
    }

    @Override
    protected void pollFunctionMatchingStatus() {
        SwingUtilities.invokeLater(() -> {
            try {
                var request = new AnalysisFunctionMatchingRequest();
                request.setMinSimilarity(BigDecimal.valueOf(getThreshold()));

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

                functionMatchingResponse = revengService.getFunctionMatchingForAnalysis(analyzedProgram.analysisID(), request);
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
        return new String[]{"Virtual Address", "Function Name", "Matched Function", "Similarity", "Confidence", "Matched Hash", "Matched Binary"};
    }

    @Override
    protected Object[] getTableRowData(GhidraFunctionMatchWithSignature result) {
        return new Object[]{
            result.function().getEntryPoint().toString(),
            result.function().getName(),
            result.functionMatch().nearest_neighbor_function_name(),
            result.functionMatch().similarity(),
            result.functionMatch().confidence(),
            result.functionMatch().nearest_neighbor_sha_256_hash().sha256(),
            result.functionMatch().nearest_neighbor_binary_name()
        };
    }

    @Override
    protected String getTableTitle() {
        return "Function matching results";
    }

    @Override
    protected int getTableSelectionMode() {
        return ListSelectionModel.MULTIPLE_INTERVAL_SELECTION;
    }

    @Override
    protected void configureTableColumns() {
        if (resultsTable.getColumnCount() > 0) {
            // Set monospace font for Virtual Address column
            resultsTable.getColumnModel().getColumn(0).setCellRenderer(new javax.swing.table.DefaultTableCellRenderer() {
                @Override
                public Component getTableCellRendererComponent(JTable table, Object value,
                                                               boolean isSelected, boolean hasFocus, int row, int column) {
                    Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                    c.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
                    return c;
                }
            });

            // Set color-coded renderer for Similarity column (index 3)
            resultsTable.getColumnModel().getColumn(3).setCellRenderer(new PercentageColorCellRenderer());

            // Set color-coded renderer for Confidence column (index 4)
            resultsTable.getColumnModel().getColumn(4).setCellRenderer(new PercentageColorCellRenderer());

            // Configure sorting for percentage columns
            configurePercentageColumnSorting(3, 4);

            // Set column widths
            resultsTable.getColumnModel().getColumn(0).setPreferredWidth(100);  // Virtual Address
            resultsTable.getColumnModel().getColumn(1).setPreferredWidth(150);  // Function Name
            resultsTable.getColumnModel().getColumn(2).setPreferredWidth(150);  // Best Match
            resultsTable.getColumnModel().getColumn(3).setPreferredWidth(80);   // Similarity
            resultsTable.getColumnModel().getColumn(4).setPreferredWidth(80);   // Confidence
            resultsTable.getColumnModel().getColumn(5).setPreferredWidth(100);  // Matched Hash
            resultsTable.getColumnModel().getColumn(6).setPreferredWidth(120);  // Binary

            // Set minimum widths
            resultsTable.getColumnModel().getColumn(0).setMinWidth(80);
            resultsTable.getColumnModel().getColumn(1).setMinWidth(100);
            resultsTable.getColumnModel().getColumn(2).setMinWidth(100);
            resultsTable.getColumnModel().getColumn(3).setMinWidth(60);
            resultsTable.getColumnModel().getColumn(4).setMinWidth(60);
            resultsTable.getColumnModel().getColumn(5).setMinWidth(80);
            resultsTable.getColumnModel().getColumn(6).setMinWidth(80);
        }
    }


    @Override
    protected String getDialogDescription() {
        return "Match functions in this binary against previously seen samples";
    }

    @Override
    protected boolean matchesFilter(GhidraFunctionMatchWithSignature result) {
        String filterText = functionFilterField.getText().trim().toLowerCase();
        return result.function().getEntryPoint().toString().toLowerCase().contains(filterText) ||
               result.function().getName().toLowerCase().contains(filterText) ||
               result.functionMatch().nearest_neighbor_function_name().toLowerCase().contains(filterText) ||
               result.functionMatch().nearest_neighbor_sha_256_hash().sha256().toLowerCase().contains(filterText) ||
               result.functionMatch().nearest_neighbor_binary_name().toLowerCase().contains(filterText);
    }
}

package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class FunctionLevelFunctionMatchingDialog extends AbstractFunctionMatchingDialog {
    private final Function function;

    public FunctionLevelFunctionMatchingDialog(PluginTool tool, GhidraRevengService.AnalysedProgram programWithBinaryID, Function function) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "Function Matching", true,
              tool.getService(GhidraRevengService.class), programWithBinaryID);
        this.function = function;
    }

    private List<Long> matchingFunctionIds;

    @Override
    protected MatchingProgress startMatching() throws ApiException {
        var functionIDOpt = analyzedProgram.getIDForFunction(function);
        if (functionIDOpt.isEmpty()) {
            throw new ApiException("Could not find function ID for the selected function");
        }
        matchingFunctionIds = List.of(functionIDOpt.get().functionID().value());

        var request = new StartMatchingForFunctionsInputBody();
        request.setFunctionIds(matchingFunctionIds);
        request.setMinSimilarity((double) getThreshold());
        request.setResultsPerFunction(25L);
        request.setFilters(buildMatchFilters());

        var response = revengService.startFunctionsMatching(request);
        return new MatchingProgress(
                response.getStatus() == null ? null : response.getStatus().getValue(),
                response.getStep(), response.getStepIndex(), response.getStepsTotal(),
                errorTextFrom(response.getMessages()));
    }

    @Override
    protected MatchingProgress pollMatchingStatus() throws ApiException {
        var response = revengService.getFunctionsMatchingStatus(matchingFunctionIds);
        return new MatchingProgress(
                response.getStatus() == null ? null : response.getStatus().getValue(),
                response.getStep(), response.getStepIndex(), response.getStepsTotal(),
                errorTextFrom(response.getMessages()));
    }

    @Override
    protected List<MatchedFunctionResult> fetchMatches() throws ApiException {
        return flattenMatches(revengService.getFunctionsMatches(matchingFunctionIds).getMatches());
    }

    private MatchFilters buildMatchFilters() {
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
        return filters;
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

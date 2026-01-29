/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ai.reveng;

import static org.junit.Assert.*;

import java.awt.*;
import java.util.*;
import java.util.List;

import javax.swing.*;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.analysiscreation.RevEngAIAnalysisOptionsDialog;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionselection.FunctionSelectionPanel;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.MockApi;
import docking.DockingWindowManager;
import ghidra.program.model.listing.Function;
import org.junit.*;

import ghidra.program.database.ProgramBuilder;

public class AnalysisOptionsDialogTest extends RevEngMockableHeadedIntegrationTest {

    public AnalysisOptionsDialogTest() {
        super();
    }

    @Test
    public void testBasicOptionsDialog() throws Exception {

        var reService = new GhidraRevengService( new MockApi() {});
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        // Add some functions to the program so the function selection panel has data
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createFunction("0x401000");
        builder.createFunction("0x401100");

        var program = builder.getProgram();
        var tool = env.getTool();

        // Create dialog in the EDT since it uses ThreadedTableModel
        var dialogHolder = new RevEngAIAnalysisOptionsDialog[1];
        runSwing(() -> {
            dialogHolder[0] = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, reService, tool);
        });
        var dialog = dialogHolder[0];

        SwingUtilities.invokeLater(() -> {
            DockingWindowManager.showDialog(null, dialog);
        });
        waitForSwing();
        waitFor(
                () -> {
                    JButton okButton = (JButton) getInstanceField("okButton", dialog);
                    return okButton.isEnabled();
                }
        );
        runSwing(() -> {
            JButton okButton = (JButton) getInstanceField("okButton", dialog);
            okButton.doClick();
        });
        var options = dialog.getOptionsFromUI();
        capture(dialog.getComponent(), "upload-dialog");
        assertNotNull(options);
    }

    @Test
    public void testDialogHasFunctionSelectionPanel() throws Exception {
        var reService = new GhidraRevengService(new MockApi() {});
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createFunction("0x401000");
        builder.createFunction("0x401100");
        builder.createFunction("0x401200");

        var program = builder.getProgram();
        var tool = env.getTool();

        var dialogHolder = new RevEngAIAnalysisOptionsDialog[1];
        runSwing(() -> {
            dialogHolder[0] = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, reService, tool);
        });
        var dialog = dialogHolder[0];

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        waitForSwing();

        // Verify the function selection panel exists
        FunctionSelectionPanel functionSelectionPanel =
                (FunctionSelectionPanel) getInstanceField("functionSelectionPanel", dialog);
        assertNotNull("Function selection panel should exist", functionSelectionPanel);

        close(dialog);
    }

    @Test
    public void testFunctionSelectionDefaultsToNonExternalNonThunk() throws Exception {
        var reService = new GhidraRevengService(new MockApi() {});
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createFunction("0x401000");
        builder.createFunction("0x401100");
        // Create external function (extAddress, libName, functionName)
        builder.createExternalFunction(null, "EXTERNAL", "printf");

        var program = builder.getProgram();
        var tool = env.getTool();

        var dialogHolder = new RevEngAIAnalysisOptionsDialog[1];
        runSwing(() -> {
            dialogHolder[0] = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, reService, tool);
        });
        var dialog = dialogHolder[0];

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        waitForSwing();

        FunctionSelectionPanel functionSelectionPanel =
                (FunctionSelectionPanel) getInstanceField("functionSelectionPanel", dialog);

        // Wait for table to load
        waitForCondition(() -> functionSelectionPanel.getTotalFunctionCount() > 0,
                "Function selection panel should load functions");

        // Get selected functions - should not include external
        List<Function> selectedFunctions = functionSelectionPanel.getSelectedFunctions();
        for (Function func : selectedFunctions) {
            assertFalse("External functions should not be selected by default: " + func.getName(),
                    func.isExternal());
        }

        close(dialog);
    }

    @Test
    public void testSelectAllButtonWorksInDialog() throws Exception {
        var reService = new GhidraRevengService(new MockApi() {});
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createFunction("0x401000");
        builder.createFunction("0x401100");
        builder.createFunction("0x401200");

        var program = builder.getProgram();
        var tool = env.getTool();

        var dialogHolder = new RevEngAIAnalysisOptionsDialog[1];
        runSwing(() -> {
            dialogHolder[0] = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, reService, tool);
        });
        var dialog = dialogHolder[0];

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        waitForSwing();

        FunctionSelectionPanel functionSelectionPanel =
                (FunctionSelectionPanel) getInstanceField("functionSelectionPanel", dialog);

        // Wait for table to load
        waitForCondition(() -> functionSelectionPanel.getTotalFunctionCount() > 0,
                "Function selection panel should load functions");

        // Find and click "Select All" button
        JButton selectAllButton = findButtonByText(dialog.getComponent(), "Select All");
        assertNotNull("Select All button should exist", selectAllButton);

        pressButton(selectAllButton);
        waitForSwing();

        // All functions should now be selected
        assertEquals("All functions should be selected",
                functionSelectionPanel.getTotalFunctionCount(),
                functionSelectionPanel.getSelectedFunctions().size());

        close(dialog);
    }

    @Test
    public void testDeselectAllButtonWorksInDialog() throws Exception {
        var reService = new GhidraRevengService(new MockApi() {});
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createFunction("0x401000");
        builder.createFunction("0x401100");

        var program = builder.getProgram();
        var tool = env.getTool();

        var dialogHolder = new RevEngAIAnalysisOptionsDialog[1];
        runSwing(() -> {
            dialogHolder[0] = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, reService, tool);
        });
        var dialog = dialogHolder[0];

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        waitForSwing();

        FunctionSelectionPanel functionSelectionPanel =
                (FunctionSelectionPanel) getInstanceField("functionSelectionPanel", dialog);

        // Wait for table to load
        waitForCondition(() -> functionSelectionPanel.getTotalFunctionCount() > 0,
                "Function selection panel should load functions");

        // Find and click "Deselect All" button
        JButton deselectAllButton = findButtonByText(dialog.getComponent(), "Deselect All");
        assertNotNull("Deselect All button should exist", deselectAllButton);

        pressButton(deselectAllButton);
        waitForSwing();

        // No functions should be selected
        assertTrue("No functions should be selected",
                functionSelectionPanel.getSelectedFunctions().isEmpty());

        close(dialog);
    }

    @Test
    public void testGetOptionsFromUIIncludesSelectedFunctions() throws Exception {
        var reService = new GhidraRevengService(new MockApi() {});
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createMemory(".text", "0x401000", 0x1000);
        builder.createFunction("0x401000");
        builder.createFunction("0x401100");
        builder.createFunction("0x401200");

        var program = builder.getProgram();
        var tool = env.getTool();

        var dialogHolder = new RevEngAIAnalysisOptionsDialog[1];
        runSwing(() -> {
            dialogHolder[0] = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, reService, tool);
        });
        var dialog = dialogHolder[0];

        runSwing(() -> DockingWindowManager.showDialog(null, dialog), false);
        waitForSwing();

        FunctionSelectionPanel functionSelectionPanel =
                (FunctionSelectionPanel) getInstanceField("functionSelectionPanel", dialog);

        // Wait for table to load
        waitForCondition(() -> functionSelectionPanel.getTotalFunctionCount() > 0,
                "Function selection panel should load functions");

        // By default, all non-external functions should be selected
        int selectedCount = functionSelectionPanel.getSelectedFunctions().size();
        assertTrue("Should have at least 3 functions selected", selectedCount >= 3);

        // Get options - should include function boundaries from selected functions
        var options = dialog.getOptionsFromUI();
        assertNotNull("Options should be returned", options);

        // Convert to AnalysisCreateRequest to inspect the function boundaries
        var request = options.toAnalysisCreateRequest();
        assertNotNull("Request should be created", request);
        assertNotNull("Request should have symbols", request.getSymbols());
        assertNotNull("Symbols should have function boundaries", request.getSymbols().getFunctionBoundaries());

        var boundaries = request.getSymbols().getFunctionBoundaries();
        assertEquals("Function boundaries count should match selected functions",
                selectedCount, boundaries.size());

        // Verify the expected function addresses are present (0x401000, 0x401100, 0x401200)
        var startAddresses = boundaries.stream()
                .map(b -> b.getStartAddress())
                .toList();
        assertTrue("Should contain function at 0x401000", startAddresses.contains(0x401000L));
        assertTrue("Should contain function at 0x401100", startAddresses.contains(0x401100L));
        assertTrue("Should contain function at 0x401200", startAddresses.contains(0x401200L));

        close(dialog);
    }
}

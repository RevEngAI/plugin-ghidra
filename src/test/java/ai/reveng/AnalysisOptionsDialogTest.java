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

import javax.swing.*;

import ai.reveng.model.User;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.analysiscreation.RevEngAIAnalysisOptionsDialog;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.MockApi;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisScope;
import docking.DockingWindowManager;
import ghidra.framework.main.FrontEndTool;
import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.test.TestEnv;

public class AnalysisOptionsDialogTest extends RevEngMockableHeadedIntegrationTest {

    private TestEnv env;
    private FrontEndTool frontEndTool;

    public AnalysisOptionsDialogTest() {
        super();
    }

    @Test
    public void testBasicOptionsDialog() throws Exception {

        var reService = new GhidraRevengService( new MockApi() {});
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var program = builder.getProgram();
        var dialog = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, reService);
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
    public void testPrivateScopeDisabledForEnthusiast() throws Exception {
        var reService = new GhidraRevengService(new MockApi() {
            @Override
            public User getMe() {
                return new User().tier(User.TierEnum.ENTHUSIAST);
            }
        });
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var program = builder.getProgram();
        var dialog = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, reService);
        SwingUtilities.invokeLater(() -> {
            DockingWindowManager.showDialog(null, dialog);
        });
        waitForSwing();

        JRadioButton privateScope = (JRadioButton) getInstanceField("privateScope", dialog);
        JRadioButton publicScope = (JRadioButton) getInstanceField("publicScope", dialog);
        waitFor(() -> !privateScope.isEnabled());

        assertFalse("Private scope must be disabled for the enthusiast tier", privateScope.isEnabled());
        assertFalse(privateScope.isSelected());
        assertTrue("Public scope must be selected for the enthusiast tier", publicScope.isSelected());
        assertNotNull("A disabled private scope must explain why on hover", privateScope.getToolTipText());

        waitFor(() -> {
            JButton okButton = (JButton) getInstanceField("okButton", dialog);
            return okButton.isEnabled();
        });
        runSwing(() -> {
            JButton okButton = (JButton) getInstanceField("okButton", dialog);
            okButton.doClick();
        });
        var options = dialog.getOptionsFromUI();
        assertNotNull(options);
        assertEquals(AnalysisScope.PUBLIC, options.getScope());
    }

    @Test
    public void testPrivateScopeEnabledForNonEnthusiast() throws Exception {
        var reService = new GhidraRevengService(new MockApi() {
            @Override
            public User getMe() {
                return new User().tier(User.TierEnum.REVERSER);
            }
        });
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        var program = builder.getProgram();
        var dialog = RevEngAIAnalysisOptionsDialog.withModelsFromServer(program, reService);
        SwingUtilities.invokeLater(() -> {
            DockingWindowManager.showDialog(null, dialog);
        });
        waitForSwing();

        JRadioButton privateScope = (JRadioButton) getInstanceField("privateScope", dialog);
        waitFor(() -> {
            JButton okButton = (JButton) getInstanceField("okButton", dialog);
            return okButton.isEnabled();
        });

        assertTrue("Private scope must stay enabled for non-enthusiast tiers", privateScope.isEnabled());
        assertTrue(privateScope.isSelected());

        runSwing(() -> {
            JButton okButton = (JButton) getInstanceField("okButton", dialog);
            okButton.doClick();
        });
        var options = dialog.getOptionsFromUI();
        assertNotNull(options);
        assertEquals(AnalysisScope.PRIVATE, options.getScope());
    }
}

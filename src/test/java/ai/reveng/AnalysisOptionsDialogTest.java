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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

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

    @Test
    public void testPrivateScopeDisabledWhenTierFetchFails() throws Exception {
        var reService = new GhidraRevengService(new MockApi() {
            @Override
            public User getMe() {
                throw new RuntimeException("tier lookup failed");
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

        waitFor(() -> {
            JButton okButton = (JButton) getInstanceField("okButton", dialog);
            return okButton.isEnabled();
        });

        assertFalse("Private scope must fail safe to disabled when the tier can't be verified",
                privateScope.isEnabled());
        assertFalse(privateScope.isSelected());
        assertTrue("Public scope must be selected when the tier can't be verified",
                publicScope.isSelected());
        assertNotNull("A disabled private scope must explain why on hover", privateScope.getToolTipText());

        runSwing(() -> {
            JButton okButton = (JButton) getInstanceField("okButton", dialog);
            okButton.doClick();
        });
        var options = dialog.getOptionsFromUI();
        assertNotNull(options);
        assertEquals(AnalysisScope.PUBLIC, options.getScope());
    }

    @Test
    public void testStartAnalysisBlockedUntilTierResolves() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        var reService = new GhidraRevengService(new MockApi() {
            @Override
            public User getMe() {
                try {
                    release.await(10, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
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

        JButton okButton = (JButton) getInstanceField("okButton", dialog);
        JRadioButton privateScope = (JRadioButton) getInstanceField("privateScope", dialog);
        JLabel loadingLabel = (JLabel) getInstanceField("loadingLabel", dialog);

        // The file-size/config check resolves independently; wait for it so the only thing
        // still holding the OK button disabled is the (blocked) tier fetch.
        waitFor(() -> !loadingLabel.isVisible());

        assertFalse("Start Analysis must stay disabled until the tier fetch resolves",
                okButton.isEnabled());
        assertFalse("Private must stay disabled until the tier fetch resolves",
                privateScope.isEnabled());

        release.countDown();

        waitFor(okButton::isEnabled);
        assertTrue(okButton.isEnabled());
        assertTrue("Private becomes available once a non-enthusiast tier is confirmed",
                privateScope.isEnabled());
    }

    @Test
    public void testGetOptionsIgnoresDisabledPrivateSelection() throws Exception {
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
        waitFor(() -> !privateScope.isEnabled());

        // Force a stale private selection onto the disabled control and confirm the submit-time
        // guard still reports the analysis as public.
        runSwing(() -> privateScope.setSelected(true));
        assertTrue(privateScope.isSelected());
        assertFalse(privateScope.isEnabled());

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
}

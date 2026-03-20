package ai.reveng;

import ai.reveng.toolkit.ghidra.core.ui.wizard.CredentialValidator;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardManager;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import docking.wizard.WizardManager;
import docking.wizard.WizardState;
import org.junit.Test;

import javax.swing.*;

import static ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage.REAI_OPTIONS_CATEGORY;
import static org.junit.Assert.*;

public class SetupWizardTest extends RevEngMockableHeadedIntegrationTest {

    /**
     * Walk through the full wizard flow: fill in credentials, validate, and finish.
     * Verifies that credentials are saved to tool options.
     */
    @Test
    public void testWizardCompletesSuccessfully() throws Exception {
        var tool = env.getTool();

        var wizardState = new WizardState<SetupWizardStateKey>();
        // Inject a mock validator that always succeeds
        wizardState.put(SetupWizardStateKey.CREDENTIAL_VALIDATOR,
                (CredentialValidator) apiInfo -> {});
        // Redirect config file to a temp directory so we don't overwrite the user's real config
        var tempConfigFile = createTempDirectory("reai-wizard-test").toPath().resolve("reai.json");
        wizardState.put(SetupWizardStateKey.CONFIGFILE, tempConfigFile.toString());

        SetupWizardManager setupManager = new SetupWizardManager(wizardState, tool);
        WizardManager wizardManager = new WizardManager("RevEng.AI: Configuration", true, setupManager);
        runSwing(() -> wizardManager.showWizard(tool.getToolFrame()), false);
        var dialog = waitForDialogComponent("RevEng.AI: Configuration");
        assertNotNull(dialog);

        // Find text fields by name and fill them in
        JTextField apiKeyField = (JTextField) findComponentByName(dialog.getComponent(), "apiKey");
        JTextField hostnameField = (JTextField) findComponentByName(dialog.getComponent(), "apiHostname");
        JTextField portalField = (JTextField) findComponentByName(dialog.getComponent(), "portalHostname");

        assertNotNull("API key field should exist", apiKeyField);
        assertNotNull("Hostname field should exist", hostnameField);
        assertNotNull("Portal hostname field should exist", portalField);

        // Fill in credentials
        setText(apiKeyField, "test-api-key-12345");
        setText(hostnameField, "https://api.test.example.com");
        setText(portalField, "https://portal.test.example.com");

        // Finish button should be disabled before validation
        JButton finishButton = findButtonByText(dialog.getComponent(), "Finish");
        assertNotNull("Finish button should exist", finishButton);
        assertFalse("Finish should be disabled before validation", finishButton.isEnabled());

        // Click Validate Credentials
        JButton validateButton = findButtonByText(dialog.getComponent(), "Validate Credentials");
        assertNotNull("Validate button should exist", validateButton);
        pressButton(validateButton);
        waitForSwing();

        // Finish button should now be enabled
        assertTrue("Finish should be enabled after successful validation", finishButton.isEnabled());

        // Click Finish
        pressButton(finishButton);
        waitForSwing();

        // Verify credentials were saved to tool options
        assertEquals("test-api-key-12345",
                tool.getOptions(REAI_OPTIONS_CATEGORY).getString(ReaiPluginPackage.OPTION_KEY_APIKEY, null));
        assertEquals("https://api.test.example.com",
                tool.getOptions(REAI_OPTIONS_CATEGORY).getString(ReaiPluginPackage.OPTION_KEY_HOSTNAME, null));
        assertEquals("https://portal.test.example.com",
                tool.getOptions(REAI_OPTIONS_CATEGORY).getString(ReaiPluginPackage.OPTION_KEY_PORTAL_HOSTNAME, null));

        // Verify config file was written to the temp path, not the user's home directory
        assertTrue("Config file should be written to temp path", java.nio.file.Files.exists(tempConfigFile));
    }

    /**
     * Verify that failed validation prevents the wizard from finishing.
     */
    @Test
    public void testValidationFailurePreventsFinish() throws Exception {
        var tool = env.getTool();

        var wizardState = new WizardState<SetupWizardStateKey>();
        // Inject a validator that always fails
        wizardState.put(SetupWizardStateKey.CREDENTIAL_VALIDATOR,
                (CredentialValidator) apiInfo -> {
                    throw new InvalidAPIInfoException("Invalid API key");
                });

        SetupWizardManager setupManager = new SetupWizardManager(wizardState, tool);
        WizardManager wizardManager = new WizardManager("RevEng.AI: Configuration", true, setupManager);
        runSwing(() -> wizardManager.showWizard(tool.getToolFrame()), false);
        var dialog = waitForDialogComponent("RevEng.AI: Configuration");

        // Fill in all fields
        JTextField apiKeyField = (JTextField) findComponentByName(dialog.getComponent(), "apiKey");
        JTextField hostnameField = (JTextField) findComponentByName(dialog.getComponent(), "apiHostname");
        JTextField portalField = (JTextField) findComponentByName(dialog.getComponent(), "portalHostname");
        setText(apiKeyField, "bad-key");
        setText(hostnameField, "https://api.test.example.com");
        setText(portalField, "https://portal.test.example.com");

        // Click Validate — should fail
        JButton validateButton = findButtonByText(dialog.getComponent(), "Validate Credentials");
        pressButton(validateButton);
        waitForSwing();

        // Finish button should remain disabled
        JButton finishButton = findButtonByText(dialog.getComponent(), "Finish");
        assertFalse("Finish should remain disabled after failed validation", finishButton.isEnabled());

        // Close the dialog
        close(dialog);
    }

    /**
     * Verify that editing a field after validation resets the validated state,
     * requiring re-validation before Finish is enabled.
     */
    @Test
    public void testEditingAfterValidationResetsState() throws Exception {
        var tool = env.getTool();

        var wizardState = new WizardState<SetupWizardStateKey>();
        wizardState.put(SetupWizardStateKey.CREDENTIAL_VALIDATOR,
                (CredentialValidator) apiInfo -> {});
        var tempConfigFile = createTempDirectory("reai-wizard-test").toPath().resolve("reai.json");
        wizardState.put(SetupWizardStateKey.CONFIGFILE, tempConfigFile.toString());

        SetupWizardManager setupManager = new SetupWizardManager(wizardState, tool);
        WizardManager wizardManager = new WizardManager("RevEng.AI: Configuration", true, setupManager);
        runSwing(() -> wizardManager.showWizard(tool.getToolFrame()), false);
        var dialog = waitForDialogComponent("RevEng.AI: Configuration");

        JTextField apiKeyField = (JTextField) findComponentByName(dialog.getComponent(), "apiKey");
        JTextField hostnameField = (JTextField) findComponentByName(dialog.getComponent(), "apiHostname");
        JTextField portalField = (JTextField) findComponentByName(dialog.getComponent(), "portalHostname");
        setText(apiKeyField, "test-api-key");
        setText(hostnameField, "https://api.test.example.com");
        setText(portalField, "https://portal.test.example.com");

        // Validate successfully
        JButton validateButton = findButtonByText(dialog.getComponent(), "Validate Credentials");
        pressButton(validateButton);
        waitForSwing();

        JButton finishButton = findButtonByText(dialog.getComponent(), "Finish");
        assertTrue("Finish should be enabled after validation", finishButton.isEnabled());

        // Edit the API key — should reset validation
        setText(apiKeyField, "modified-key");
        waitForSwing();

        assertFalse("Finish should be disabled after editing a field", finishButton.isEnabled());

        // Re-validate and finish
        pressButton(validateButton);
        waitForSwing();
        assertTrue("Finish should be re-enabled after re-validation", finishButton.isEnabled());

        pressButton(finishButton);
        waitForSwing();

        // Verify the modified key was saved
        assertEquals("modified-key",
                tool.getOptions(REAI_OPTIONS_CATEGORY).getString(ReaiPluginPackage.OPTION_KEY_APIKEY, null));
    }

    @Test
    public void testUserCredentialsPanel() throws Exception {
        var tool = env.getTool();

        var wizardState = new WizardState<SetupWizardStateKey>();
        wizardState.put(SetupWizardStateKey.API_KEY, "my-api-key");
        SetupWizardManager setupManager = new SetupWizardManager(wizardState, tool);
        WizardManager wizardManager = new WizardManager("RevEng.AI: Configuration", true, setupManager);
        runSwing(() -> wizardManager.showWizard(tool.getToolFrame()), false);
        var dialog = waitForDialogComponent("RevEng.AI: Configuration");

        waitForSwing();
        capture(dialog.getComponent(), "configuration-window");
    }
}

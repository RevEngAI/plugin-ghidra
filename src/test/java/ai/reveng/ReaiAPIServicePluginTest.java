package ai.reveng;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ghidra.framework.plugintool.util.PluginException;
import org.junit.After;
import org.junit.Test;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.*;

/**
 * Tests for {@link ai.reveng.toolkit.ghidra.plugins.ReaiAPIServicePlugin} initialization
 * under different config file states.
 */
public class ReaiAPIServicePluginTest extends RevEngMockableHeadedIntegrationTest {

    @After
    public void clearOverride() {
        TestableReaiAPIServicePlugin.clearConfigPathOverride();
    }

    /**
     * When no config file exists and no tool options are set, the plugin should
     * fail to load with a PluginException — not a NullPointerException.
     * Previously this crashed because the logging service was unavailable during
     * the constructor.
     */
    @Test
    public void testPluginFailsToLoadWithoutConfigFile() throws Exception {
        var tool = env.getTool();

        Path nonExistent = createTempDirectory("reai-test").toPath().resolve("nonexistent").resolve("reai.json");
        assertFalse("Precondition: config file must not exist", Files.exists(nonExistent));

        TestableReaiAPIServicePlugin.setConfigPathOverride(nonExistent);

        try {
            tool.addPlugin(TestableReaiAPIServicePlugin.class.getName());
        } catch (PluginException e) {
            // Expected — plugin should fail because no credentials were provided
            assertNull("GhidraRevengService should not be registered", tool.getService(GhidraRevengService.class));
            return;
        }
        fail("Expected PluginException when no config file exists and wizard is cancelled");
    }

    /**
     * When a valid config file exists, the plugin should load credentials from it
     * and register a configured service.
     */
    @Test
    public void testPluginLoadsWithValidConfigFile() throws Exception {
        var tool = env.getTool();

        Path configFile = createTempDirectory("reai-test").toPath().resolve("reai.json");
        Files.writeString(configFile, """
                {
                    "pluginSettings": {
                        "apiKey": "test-api-key",
                        "hostname": "https://api.test.reveng.ai",
                        "portalHostname": "https://portal.test.reveng.ai"
                    }
                }
                """);

        TestableReaiAPIServicePlugin.setConfigPathOverride(configFile);
        tool.addPlugin(TestableReaiAPIServicePlugin.class.getName());

        var service = tool.getService(GhidraRevengService.class);
        assertNotNull("GhidraRevengService should be registered", service);
        assertEquals("Service should be configured with the provided hostname",
                URI.create("https://api.test.reveng.ai"), service.getServer());
    }

    /**
     * When the config file contains malformed JSON, the plugin should show an
     * error dialog and then fail to load (not crash with NPE).
     */
    @Test
    public void testPluginFailsToLoadWithMalformedConfigFile() throws Exception {
        // Malformed config will show an error dialog, so allow error GUIs for this test
        setErrorGUIEnabled(true);
        var tool = env.getTool();

        Path configFile = createTempDirectory("reai-test").toPath().resolve("reai.json");
        Files.writeString(configFile, "{ not valid json }}}");

        TestableReaiAPIServicePlugin.setConfigPathOverride(configFile);

        // addPlugin will block on Msg.showError's modal dialog, so run it non-blocking
        runSwing(() -> {
            try {
                tool.addPlugin(TestableReaiAPIServicePlugin.class.getName());
            } catch (Exception e) {
                // Expected — plugin should fail after showing error dialog
            }
        }, false);

        // Wait for the error dialog to appear, then dismiss it
        var errorDialog = waitForDialogComponent("Load Config");
        assertNotNull("Error dialog should appear for malformed config", errorDialog);
        close(errorDialog);
        waitForSwing();

        var service = tool.getService(GhidraRevengService.class);
        assertNull("GhidraRevengService should not be registered with bad config", service);
    }
}

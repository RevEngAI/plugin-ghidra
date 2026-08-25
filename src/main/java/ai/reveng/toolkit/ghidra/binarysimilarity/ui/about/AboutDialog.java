package ai.reveng.toolkit.ghidra.binarysimilarity.ui.about;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.framework.plugintool.PluginTool;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import ai.reveng.invoker.Configuration;

/**
 * Shows a dialog with about information.
 */
public class AboutDialog extends RevEngDialogComponentProvider {
    public AboutDialog(PluginTool tool) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "About", true);

        buildInterface(getPluginVersion());
        setPreferredSize(300, 210);
    }

    private String getPluginVersion() {
        String pluginVersion = "unknown";
        try {
            // This resource is written by the release workflow, so it is absent from a local build
            // and the stream is then null.
            var inputStream = ResourceManager.getResourceAsStream("reai_ghidra_plugin_version.txt");
            if (inputStream != null) {
                pluginVersion = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).trim();
                inputStream.close();
            }
        } catch (IOException e) {
            // ignore — fall back to "unknown"
        }

        return pluginVersion;
    }

    private void buildInterface(String pluginVersion) {
        JPanel mainPanel = new JPanel(new BorderLayout());

        // Create title panel
        JPanel titlePanel = createTitlePanel("Information about the plugin");
        mainPanel.add(titlePanel, BorderLayout.NORTH);

        // Create the about content
        JPanel contentPanel = createAboutContent(pluginVersion);
        mainPanel.add(contentPanel, BorderLayout.CENTER);

        addWorkPanel(mainPanel);
        addDismissButton();
    }

    private JPanel createAboutContent(String pluginVersion) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        // Add padding at the top
        panel.add(Box.createVerticalStrut(15));

        // Plugin version label
        JLabel pluginLabel = new JLabel("Plugin version: " + pluginVersion);
        pluginLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(pluginLabel);

        panel.add(Box.createVerticalStrut(5));

        // SDK version label
        JLabel sdkLabel = new JLabel("SDK version: " + Configuration.VERSION);
        sdkLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        panel.add(sdkLabel);

        return panel;
    }
}

package ai.reveng.toolkit.ghidra.binarysimilarity.ui.about;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.core.services.update.UpdateChecker;
import ai.reveng.toolkit.ghidra.core.services.update.UpdateChecker.UpdateInfo;
import ai.reveng.toolkit.ghidra.core.ui.WebBrowser;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.framework.plugintool.PluginTool;

import javax.swing.*;
import java.awt.*;
import java.net.URI;
import java.util.Optional;
import ai.reveng.invoker.Configuration;

/**
 * Shows a dialog with about information.
 */
public class AboutDialog extends RevEngDialogComponentProvider {
    private final Optional<UpdateInfo> update;

    public AboutDialog(PluginTool tool, Optional<UpdateInfo> update) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "About", true);
        this.update = update;

        buildInterface(UpdateChecker.currentVersion());
        setPreferredSize(300, update.isPresent() ? 250 : 210);
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

        update.ifPresent(u -> {
            panel.add(Box.createVerticalStrut(10));
            JButton updateButton = new JButton("Update available: " + u.version());
            updateButton.setAlignmentX(Component.CENTER_ALIGNMENT);
            updateButton.addActionListener(e -> WebBrowser.open(URI.create(u.releaseUrl())));
            panel.add(updateButton);
        });

        return panel;
    }
}

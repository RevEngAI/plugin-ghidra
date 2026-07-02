package ai.reveng.toolkit.ghidra.binarysimilarity.ui.help;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import docking.widgets.label.GLabel;
import ghidra.framework.plugintool.PluginTool;

import javax.swing.*;

import java.awt.*;
import java.net.URI;

/**
 * Shows a dialog with help information.
 */
public class HelpDialog extends RevEngDialogComponentProvider {
    public HelpDialog(PluginTool tool) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "Help", true);

        buildInterface();
        setPreferredSize(700, 600);
    }

    private void buildInterface() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create title panel
        JPanel titlePanel = createTitlePanel("Help on using the plugin");
        mainPanel.add(titlePanel, BorderLayout.NORTH);

        // Create the help content
        JPanel contentPanel = createHelpContent();

        // Make it scrollable
        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        mainPanel.add(scrollPane, BorderLayout.CENTER);

        // Add contact links panel at the bottom
        JPanel contactPanel = createContactPanel();
        mainPanel.add(contactPanel, BorderLayout.SOUTH);

        addWorkPanel(mainPanel);
        addDismissButton();
    }

    private JPanel createHelpContent() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 5));

        // MenuBar section
        panel.add(createSectionHeader("Menu Bar"));
        panel.add(createDescription("Documentation for the options in the menu bar", null));
        panel.add(Box.createVerticalStrut(10));

        // RevEng.AI menu
        panel.add(createMenuHeader("RevEng.AI"));

        // Analysis submenu
        panel.add(createSubmenuHeader("Analysis"));
        panel.add(
                createDescription(
                            """
                            To use the RevEng.AI platform we need to run an analysis on the binary you are currently
                            working with in our portal. Use this section to create and manage this analysis.
                            This section is only available after the plugin has been configured.""",
                        20
                )
        );
        panel.add(createMenuItem("Create new", "Creates a new analysis in the RevEng.AI portal and attaches to it", 20));
        panel.add(createMenuItem("Attach to existing", "List matching portal analyses and allow selecting one to attach to", 20));
        panel.add(createMenuItem("Detach", "Detach from portal analysis", 20));
        panel.add(createMenuItem("Check status", "Checks the status of a running analysis", 20));
        panel.add(createMenuItem("View in portal", "View this analysis in the portal", 20));

        panel.add(Box.createVerticalStrut(10));

        // Other menu items
        panel.add(
                createMenuItem(
                        "Function Matching",
                        """
                        Run a function match against the RevEng.AI API to identify functions that were not
                        renamed during the automatic unstrip process. This option is configurable to run
                        against specific target binaries by using specific filters. This option is only available
                        when an analysis is attached and has completed processing.""",
                        null
                )
        );
        panel.add(createMenuItem("Configure", "Configure the API endpoint and API key", null));
        panel.add(createMenuItem("Help", "Display this page", null));
        panel.add(createMenuItem("About", "Display plugin version", null));

        panel.add(Box.createVerticalStrut(20));

        // Context menu section
        panel.add(createSectionHeader("Secondary click on a function"));
        panel.add(createDescription("Documentation for the options available on secondary click on a specific function", null));
        panel.add(Box.createVerticalStrut(10));

        panel.add(createMenuItem(
                "AI Decompilation",
                """
                Decompile function using the RevEng.AI proprietary decompiler.
                """,
                null
            )
        );
        panel.add(createMenuItem(
                "Match function",
                """
                Run a match against the RevEng.AI API for this function. Only available for non-debug functions.
                """,
                null
            )
        );
        panel.add(createMenuItem(
                "View function in portal",
                """
                View this function in the RevEng.AI portal.
                """,
                null
            )
        );

        return panel;
    }

    private JPanel createContactPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        panel.setBorder(BorderFactory.createTitledBorder("Support & Contact"));

        // Discord link
        JButton discordButton = new JButton("Join Discord");
        discordButton.addActionListener(e -> openWebpage("https://discord.com/invite/ZwQTvzfSbA"));

        // Email link
        JButton emailButton = new JButton("Email Support");
        emailButton.addActionListener(e -> openEmail("support@reveng.ai"));

        panel.add(new GLabel("Need help? "));
        panel.add(discordButton);
        panel.add(new GLabel(" or "));
        panel.add(emailButton);

        return panel;
    }

    private JLabel createSectionHeader(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 16f));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    private JLabel createMenuHeader(String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 14f));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
        return label;
    }

    private JLabel createSubmenuHeader(String text) {
        JLabel label = new JLabel("> " + text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 13f));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setBorder(BorderFactory.createEmptyBorder(5, 10, 2, 0));
        return label;
    }

    private JPanel createMenuItem(String name, String description, Integer leftPadding) {
        int paddingLeft = (leftPadding != null) ? leftPadding : 0;

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.setBorder(BorderFactory.createEmptyBorder(2, paddingLeft, 2, 0));

        JLabel nameLabel = new JLabel("  > " + name);
        nameLabel.setFont(nameLabel.getFont().deriveFont(Font.BOLD));
        nameLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Convert \n to HTML line breaks for proper rendering
        String htmlDescription = "<html>" + description.replace("\n", "<br>") + "</html>";

        JLabel descLabel = new JLabel(htmlDescription);
        descLabel.setFont(descLabel.getFont().deriveFont(Font.ITALIC));
        descLabel.setForeground(Color.GRAY);
        descLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        descLabel.setBorder(BorderFactory.createEmptyBorder(0, 20, 0, 0));

        panel.add(nameLabel);
        panel.add(descLabel);

        return panel;
    }

    private JLabel createDescription(String text, Integer leftPadding) {
        int paddingLeft = (leftPadding != null) ? leftPadding : 0;

        // Convert \n to HTML line breaks for proper rendering
        String htmlText = "<html>" + text.replace("\n", "<br>") + "</html>";

        JLabel label = new JLabel(htmlText);
        label.setFont(label.getFont().deriveFont(Font.ITALIC));
        label.setForeground(Color.GRAY);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setBorder(BorderFactory.createEmptyBorder(0, paddingLeft, 5, 0));
        return label;
    }

    private void openWebpage(String url) {
        try {
            Desktop.getDesktop().browse(new URI(url));
        } catch (Exception e) {
            // Fallback - show the URL in a message
            JOptionPane.showMessageDialog(this.getComponent(),
                    "Please visit: " + url,
                    "Discord Link",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void openEmail(String email) {
        try {
            Desktop.getDesktop().mail(new URI("mailto:" + email));
        } catch (Exception e) {
            // Fallback - show the email in a message
            JOptionPane.showMessageDialog(this.getComponent(),
                    "Please email: " + email,
                    "Email Support",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }
}

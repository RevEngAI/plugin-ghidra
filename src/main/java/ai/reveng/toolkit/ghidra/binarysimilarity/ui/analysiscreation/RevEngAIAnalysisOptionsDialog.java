package ai.reveng.toolkit.ghidra.binarysimilarity.ui.analysiscreation;

import ai.reveng.model.ConfigResponse;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisScope;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;

import javax.annotation.Nullable;
import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public class RevEngAIAnalysisOptionsDialog extends RevEngDialogComponentProvider {
    private JCheckBox advancedAnalysisCheckBox;
    private JCheckBox dynamicExecutionCheckBox;
    private final Program program;
    private final GhidraRevengService service;
    private JRadioButton privateScope;
    private JRadioButton publicScope;
    private JTextField tagsTextBox;
    private JCheckBox scrapeExternalTagsBox;
    private JCheckBox identifyCapabilitiesCheckBox;
    private JCheckBox identifyCVECheckBox;
    private JCheckBox generateSBOMCheckBox;
    private JComboBox<String> architectureComboBox;
    private boolean okPressed = false;

    private JLabel fileSizeWarningLabel;
    private JLabel loadingLabel;

    public static RevEngAIAnalysisOptionsDialog withModelsFromServer(Program program, GhidraRevengService reService) {
        return new RevEngAIAnalysisOptionsDialog(program, reService);
    }

    public RevEngAIAnalysisOptionsDialog(Program program, GhidraRevengService service) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "Configure Analysis for %s".formatted(program.getName()), true);
        this.program = program;
        this.service = service;

        buildInterface();
        setPreferredSize(320, 420);

        fetchConfigAsync();
    }

    private void buildInterface() {
        var workPanel = new JPanel();
        workPanel.setLayout(new BoxLayout(workPanel, BoxLayout.Y_AXIS));

        addWorkPanel(workPanel);

        // Create title panel
        JPanel titlePanel = createTitlePanel("Create new analysis for this binary");
        workPanel.add(titlePanel, BorderLayout.NORTH);

        // File size warning label (hidden by default)
        fileSizeWarningLabel = new JLabel();
        fileSizeWarningLabel.setForeground(Color.RED);
        fileSizeWarningLabel.setHorizontalAlignment(SwingConstants.CENTER);
        fileSizeWarningLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        fileSizeWarningLabel.setVisible(false);
        fileSizeWarningLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        workPanel.add(fileSizeWarningLabel);

        // Add Platform Drop Down
        var platformComboBox = new JComboBox<>(new String[]{
                "Auto", "windows", "linux",
        });
        platformComboBox.setEditable(false);
        // Center the text
        platformComboBox.setAlignmentX(Component.CENTER_ALIGNMENT);
        platformComboBox.setMaximumSize(platformComboBox.getPreferredSize());
        var platformLabel = new JLabel("Select Platform");
        platformLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        workPanel.add(platformLabel);
        workPanel.add(platformComboBox);

        // Add Drop down for AnalysisScope
        // Currently just public and private, but in the future this will include teams
        var scopePanel = new JPanel();
        scopePanel.setLayout(new BoxLayout(scopePanel, BoxLayout.X_AXIS));
        privateScope = new JRadioButton("Private to you");
        publicScope = new JRadioButton("Public access");
        privateScope.setSelected(true);

        var group = new ButtonGroup();
        group.add(privateScope);
        group.add(publicScope);
        scopePanel.add(privateScope);
        scopePanel.add(publicScope);

        workPanel.add(new JSeparator(SwingConstants.HORIZONTAL));

        var scopeLabel = new JLabel("Select Analysis Scope");
        scopeLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        workPanel.add(scopeLabel);
        workPanel.add(scopePanel);

        workPanel.add(new JSeparator(SwingConstants.HORIZONTAL));

        // Add ISA Drop Down
        // Add drop Down menu for the architecture
        architectureComboBox = new JComboBox<>(new String[]{
                "Auto", "x86", "x86_64", "arm",
        });
        architectureComboBox.setEditable(false);
        architectureComboBox.setMaximumSize(architectureComboBox.getPreferredSize());
        var architectureLabel = new JLabel("Select Architecture");
        architectureLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        workPanel.add(architectureLabel);
        workPanel.add(architectureComboBox);

        workPanel.add(new JSeparator(SwingConstants.HORIZONTAL));

        // Add Two Check boxes for Dynamic Execution and Advanced Analysis next to each other (horizantally)
        var checkBoxPanel = new JPanel();
        checkBoxPanel.setLayout(new GridLayout(0, 2));
        dynamicExecutionCheckBox = new JCheckBox("Dynamic Execution");
        dynamicExecutionCheckBox.setToolTipText("Include Dynamic Execution inside a Sandbox Environment with the Analysis");

        advancedAnalysisCheckBox = new JCheckBox("Advanced Analysis");
        advancedAnalysisCheckBox.setToolTipText("Run dataflow analysis for advanced analysis. Can increase analysis cost by 500%");


        // Add a check box for quick mode
        scrapeExternalTagsBox = new JCheckBox("Get External Tags");
        scrapeExternalTagsBox.setToolTipText("Scrape external tags from VirusTotal (requires configured API key)");

        // Add check box for identifiying capabilities
        identifyCapabilitiesCheckBox = new JCheckBox("Identify Capabilities");
        identifyCapabilitiesCheckBox.setToolTipText("Identify capabilities of the binary");

        // Add Check box for identifying CVEs
        identifyCVECheckBox = new JCheckBox("Identify CVEs");
        identifyCVECheckBox.setToolTipText("Identify CVEs in the binary");

        // Add Check box for generating the SBOM
        generateSBOMCheckBox = new JCheckBox("Generate SBOM");
        generateSBOMCheckBox.setToolTipText("Generate a Software Bill of Materials (SBOM) for the binary");

//        checkBoxPanel.add(dynamicExecutionCheckBox);
//        checkBoxPanel.add(advancedAnalysisCheckBox);
//        checkBoxPanel.add(scrapeExternalTagsBox);
//        checkBoxPanel.add(identifyCapabilitiesCheckBox);
//        checkBoxPanel.add(identifyCVECheckBox);
//        checkBoxPanel.add(generateSBOMCheckBox);
//        workPanel.add(checkBoxPanel);

        // Add custom tags field
        tagsTextBox = new JTextField();
        tagsTextBox.setToolTipText("Custom tags for the analysis, as comma separated list");
        tagsTextBox.setColumns(20);
        tagsTextBox.setMaximumSize(new Dimension(200, 20));
        var tagsLabel = new JLabel("Custom Tags");
        tagsLabel.setToolTipText("Custom tags for the analysis, as comma separated list");
        tagsLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        tagsTextBox.setAlignmentX(Component.CENTER_ALIGNMENT);
        workPanel.add(tagsLabel);
        workPanel.add(tagsTextBox);

        // Loading indicator (shown while fetching config)
        loadingLabel = new JLabel("Checking file size limits...");
        loadingLabel.setForeground(Color.GRAY);
        loadingLabel.setHorizontalAlignment(SwingConstants.CENTER);
        loadingLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        loadingLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        workPanel.add(loadingLabel);

        addCancelButton();
        addOKButton();

        okButton.setText("Start Analysis");
        okButton.setEnabled(false); // Disabled until config check completes
    }

    public @Nullable AnalysisOptionsBuilder getOptionsFromUI() {
        if (!okPressed) {
            return null;
        }
        var options = AnalysisOptionsBuilder.forProgram(program);

        options.skipScraping(!scrapeExternalTagsBox.isSelected());
        options.skipCapabilities(!identifyCapabilitiesCheckBox.isSelected());

        options.skipSBOM(!generateSBOMCheckBox.isSelected());
        options.skipCVE(!identifyCVECheckBox.isSelected());

        options.advancedAnalysis(advancedAnalysisCheckBox.isSelected());
        options.dynamicExecution(dynamicExecutionCheckBox.isSelected());

        if (publicScope.isEnabled()) {
            options.scope(AnalysisScope.PUBLIC);
        } else {
            options.scope(AnalysisScope.PRIVATE);
        }

        options.addTags(List.of(tagsTextBox.getText().split(",")));
        options.architecture((String) architectureComboBox.getSelectedItem());
        return options;
    }

    @Override
    protected void okCallback() {
        // Close dialog
        okPressed = true;
        close();
    }

    @Override
    public JComponent getComponent() {
        return super.getComponent();
    }

    private void fetchConfigAsync() {
        CompletableFuture.supplyAsync(() -> {
            try {
                return service.getApi().getConfig();
            } catch (Exception e) {
                Msg.warn(this, "Failed to fetch server config: " + e.getMessage());
                return null;
            }
        }).thenAccept(config -> {
            Swing.runNow(() -> handleConfigResponse(config));
        });
    }

    private void handleConfigResponse(@Nullable ConfigResponse config) {
        loadingLabel.setVisible(false);

        if (config == null) {
            // Config fetch failed, allow upload attempt (server will reject if too large)
            okButton.setEnabled(true);
            return;
        }

        long maxFileSizeBytes = config.getMaxFileSizeBytes().longValue();
        validateFileSize(maxFileSizeBytes);
    }

    private void validateFileSize(long maxFileSizeBytes) {
        long fileSize = getProgramFileSize();
        if (fileSize < 0) {
            // Could not determine file size, allow upload attempt
            okButton.setEnabled(true);
            return;
        }

        if (fileSize > maxFileSizeBytes) {
            String fileSizeStr = formatBytes(fileSize);
            String maxSizeStr = formatBytes(maxFileSizeBytes);
            fileSizeWarningLabel.setText(
                    "<html><center>File size (%s) exceeds<br>server limit (%s)</center></html>"
                            .formatted(fileSizeStr, maxSizeStr));
            fileSizeWarningLabel.setVisible(true);
            okButton.setEnabled(false);
        } else {
            fileSizeWarningLabel.setVisible(false);
            okButton.setEnabled(true);
        }
    }

    private long getProgramFileSize() {
        try {
            Path filePath;
            try {
                filePath = Path.of(program.getExecutablePath());
            } catch (InvalidPathException e) {
                // Windows paths may have leading slash like "/C:/file.dll"
                filePath = Path.of(program.getExecutablePath().substring(1));
            }
            return Files.size(filePath);
        } catch (IOException | InvalidPathException e) {
            Msg.warn(this, "Could not determine file size: " + e.getMessage());
            return -1;
        }
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return "%.1f KB".formatted(bytes / 1024.0);
        } else if (bytes < 1024 * 1024 * 1024) {
            return "%.1f MB".formatted(bytes / (1024.0 * 1024));
        } else {
            return "%.1f GB".formatted(bytes / (1024.0 * 1024 * 1024));
        }
    }
}

package ai.reveng.toolkit.ghidra.binarysimilarity.ui.analysiscreation;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionselection.FunctionSelectionPanel;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisScope;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import javax.annotation.Nullable;
import javax.swing.*;
import java.awt.*;
import java.util.List;

public class RevEngAIAnalysisOptionsDialog extends RevEngDialogComponentProvider {
    private JCheckBox advancedAnalysisCheckBox;
    private JCheckBox dynamicExecutionCheckBox;
    private final Program program;
    private final PluginTool tool;
    private JRadioButton privateScope;
    private JRadioButton publicScope;
    private JTextField tagsTextBox;
    private JCheckBox scrapeExternalTagsBox;
    private JCheckBox identifyCapabilitiesCheckBox;
    private JCheckBox identifyCVECheckBox;
    private JCheckBox generateSBOMCheckBox;
    private JComboBox<String> architectureComboBox;
    private FunctionSelectionPanel functionSelectionPanel;
    private boolean okPressed = false;

    public static RevEngAIAnalysisOptionsDialog withModelsFromServer(Program program, GhidraRevengService reService, PluginTool tool) {
        return new RevEngAIAnalysisOptionsDialog(program, tool);
    }

    public RevEngAIAnalysisOptionsDialog(Program program, PluginTool tool) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "Configure Analysis for %s".formatted(program.getName()), true);
        this.program = program;
        this.tool = tool;

        buildInterface();
        setPreferredSize(600, 550);
    }

    private void buildInterface() {
        var workPanel = new JPanel();
        workPanel.setLayout(new BoxLayout(workPanel, BoxLayout.Y_AXIS));

        addWorkPanel(workPanel);

        // Create title panel
        JPanel titlePanel = createTitlePanel("Create new analysis for this binary");
        workPanel.add(titlePanel, BorderLayout.NORTH);

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

        workPanel.add(new JSeparator(SwingConstants.HORIZONTAL));

        // Add function selection panel
        functionSelectionPanel = new FunctionSelectionPanel(tool);
        functionSelectionPanel.initForProgram(program);
        workPanel.add(functionSelectionPanel);

        addCancelButton();
        addOKButton();

        okButton.setText("Start Analysis");
    }

    public AnalysisOptionsBuilder getOptionsFromUI() {
        // Use the selected functions from the function selection panel
        var selectedFunctions = functionSelectionPanel.getSelectedFunctions();
        var options = AnalysisOptionsBuilder.forProgramWithFunctions(program, selectedFunctions);

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

    public boolean isOkPressed() {
        return okPressed;
    }

    @Override
    public JComponent getComponent() {
        return super.getComponent();
    }
}

package ai.reveng.toolkit.ghidra.devplugin;

import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryID;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionID;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

import javax.swing.*;
import java.util.Optional;

public class RevEngMetadataProvider extends ComponentProviderAdapter {
    private final JPanel panel;
    private final JTextField serverField;
    AnalysisID analysisID;
    FunctionID functionID;
    Function function;

    JTextField binaryIDField;
    JTextField analysisIDField;
    JTextField functionIDField;
    JTextField functionField;


    public RevEngMetadataProvider(PluginTool tool, String owner) {
        super(tool, "RevEng.AI Metadata Widget", owner);
        setIcon(ReaiPluginPackage.REVENG_16);

        // Build component: Just a JPanel with labels and read only text boxes
        this.panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        serverField = new JTextField();
        serverField.setEditable(false);

        binaryIDField = new JTextField();
        binaryIDField.setEditable(false);
        analysisIDField = new JTextField();
        analysisIDField.setEditable(false);
        functionIDField = new JTextField();
        functionIDField.setEditable(false);
        functionField = new JTextField();
        functionField.setEditable(false);


        panel.add(new JLabel("Server"));
        panel.add(serverField);
        panel.add(new JLabel("Binary ID"));
        panel.add(binaryIDField);
        panel.add(new JLabel("Analysis ID"));
        panel.add(analysisIDField);
        panel.add(new JLabel("Function ID"));
        panel.add(functionIDField);
        panel.add(new JLabel("Function"));
        panel.add(functionField);


    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    private void clear() {
        analysisID = null;
        functionID = null;
        function = null;
        refresh();
    }

    public void setProgram(Program program) {
        clear();
        var api = tool.getService(GhidraRevengService.class);

        var kProg = api.getKnownProgram(program);
        kProg.ifPresent(p -> {
            analysisID = p.analysisID();
        });
        refresh();

    }

    /**
     * Updates the component with the latest information
     */
    private void refresh() {
        analysisIDField.setText(analysisID == null ? "" : analysisID.toString());
        functionIDField.setText(functionID == null ? "" : functionID.toString());
        functionField.setText(function == null ? "" : function.toString());
    }

    public void locationChanged(ProgramLocation loc) {
        functionID = null;
        if (loc != null) {
            var revengService = tool.getService(GhidraRevengService.class);
            serverField.setText(revengService.getServer().toString());
            var func = loc.getProgram().getFunctionManager().getFunctionContaining(loc.getAddress());
            if (func != null) {
                function = func;
                var kProg = revengService.getAnalysedProgram(loc.getProgram());
                kProg.ifPresent(p -> {
                    Optional<GhidraRevengService.FunctionWithID> f = p.getIDForFunction(func);
                    f.ifPresent(functionID -> {
                        this.functionID = functionID.functionID();
                    });
                });
            }
        }
        refresh();

    }
}

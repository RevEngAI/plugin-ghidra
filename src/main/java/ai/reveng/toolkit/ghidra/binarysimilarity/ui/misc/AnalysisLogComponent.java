package ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc;

import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.AnalysisLogConsumer;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskBuilder;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorComponent;

import javax.swing.*;

import java.awt.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AnalysisLogComponent extends ComponentProviderAdapter implements AnalysisLogConsumer {
    private final JTextArea textArea;
    private final JScrollPane scroll;
    private TaskMonitorComponent taskMonitorComponent;
    private final JPanel mainPanel;
    private final Map<Program, Task> trackedPrograms =  new ConcurrentHashMap<>();
    private final Map<Program, String> storedLogs = new ConcurrentHashMap<>();

    public static String NAME = ReaiPluginPackage.WINDOW_PREFIX + "Analysis Log";
    private Program activeProgram;

    public AnalysisLogComponent(PluginTool tool) {
        super(tool, NAME, ReaiPluginPackage.NAME);
        setIcon(ReaiPluginPackage.REVENG_16);

        // Simple text area for now
        textArea = new JTextArea();
        textArea.setEditable(false);

        taskMonitorComponent = new TaskMonitorComponent(false, true);
        taskMonitorComponent.setIndeterminate(true);
        taskMonitorComponent.setVisible(false);

        scroll = new JScrollPane(textArea);
        
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(scroll, BorderLayout.CENTER);
        mainPanel.add(taskMonitorComponent, BorderLayout.SOUTH);

        // Set a default size for the dialog
        mainPanel.setPreferredSize(new Dimension(600, 400));
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    public void setLogs(String logs) {
        textArea.setText(logs);
        JScrollBar vertical = scroll.getVerticalScrollBar();
        vertical.setValue( vertical.getMaximum() );
    }

    public TaskMonitor getTaskMonitor() {
        taskMonitorComponent.setVisible(true);
        return taskMonitorComponent;
    }

    public void programActivated(Program program) {
        // Switch the active log to the given program
        this.activeProgram = program;
        if (trackedPrograms.containsKey(program)) {
            // If we are tracking this program, show the task monitor
            taskMonitorComponent.setVisible(true);
        } else {
            taskMonitorComponent.setVisible(false);
        }
        setLogs(storedLogs.getOrDefault(program, "No analysis logs available for the active program."));
    }

    public void processEvent(RevEngAIAnalysisStatusChangedEvent event) {
        // We don't need to display the log window when the user selects an existing analysis because it will be an
        // already completed analysis.
        var sourceName = event.getSourceName();
        if (sourceName != null && sourceName.equals("Recent Analysis Dialog")) {
            return;
        }

        this.setVisible(true);
        switch (event.getStatus()) {
            case Complete, Error -> {}
            default -> {
                if (!trackedPrograms.containsKey(event.getProgram())){
                    // We aren't tracking this program yet, so we start a new task for it
                    var task = new AnalysisMonitoringTask(event.getProgramWithBinaryID(), this);
                    var builder = TaskBuilder.withTask(task);
                    trackedPrograms.put(event.getProgram(), task);
                    builder.launchInBackground(getTaskMonitor());
                }
            }
        }

    }

    @Override
    public void consumeLogs(String logs, GhidraRevengService.ProgramWithBinaryID programWithBinaryID) {
        storedLogs.put(programWithBinaryID.program(), logs);
        // If this is the currently active program, update the log display

        if (activeProgram == programWithBinaryID.program()) {
            setLogs(logs);
        }
    }


    class AnalysisMonitoringTask extends Task {

        private final GhidraRevengService.ProgramWithBinaryID program;
        private final AnalysisLogConsumer logConsumer;

        public AnalysisMonitoringTask(GhidraRevengService.ProgramWithBinaryID programWithBinaryID, AnalysisLogConsumer logConsumer) {
            super(programWithBinaryID.toString(), true, false, false);
            program = programWithBinaryID;
            this.logConsumer = logConsumer;
        }

        @Override
        public void run(TaskMonitor monitor) throws CancelledException {
            // Wait for the analysis
            var service = tool.getService(GhidraRevengService.class);
            service.waitForFinishedAnalysis(monitor, program, this.logConsumer, tool);
            ///  waitForFinishedAnalysis has already sent the completion event to all plugins
            /// so this task just needs to clean up the tracked programs map
            // Remove ourselves from the tracked programs when done
            trackedPrograms.remove(program.program());
            taskMonitorComponent.setVisible(false);
        }
    }

}

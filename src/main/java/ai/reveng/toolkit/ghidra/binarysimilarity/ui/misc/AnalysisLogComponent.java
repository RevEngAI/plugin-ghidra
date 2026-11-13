package ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc;

import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.AnalysisLogConsumer;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.StatusPoller;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
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
    /// How the program's analysis ended, shown below its logs; absent while it runs or when unknown
    private final Map<Program, String> terminalStatusLines = new ConcurrentHashMap<>();

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
        setLogs(displayText(program));
    }

    /// The logs last received for the program, or null when none were
    public String getStoredLogs(Program program) {
        return storedLogs.get(program);
    }

    private String displayText(Program program) {
        return withTerminalStatus(storedLogs.get(program), terminalStatusLines.get(program));
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
            case Complete, Error -> {
                // The wait has ended; say how, so the panel does not look like it is still waiting
                terminalStatusLines.put(event.getProgram(),
                        terminalStatusLine(event.getStatus(), event.getProgramWithBinaryID().analysisID().id()));
                refreshIfActive(event.getProgram());
            }
            // Unknown: the wait for it has already ended, so starting another would end at once and loop
            case Unknown -> {}
            default -> {
                // A new or resumed analysis: an earlier ending no longer applies
                if (terminalStatusLines.remove(event.getProgram()) != null) {
                    refreshIfActive(event.getProgram());
                }
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
    public void consumeLogs(String logs, GhidraRevengService.ProgramWithID programWithID) {
        storedLogs.put(programWithID.program(), logs);
        // If this is the currently active program, update the log display

        refreshIfActive(programWithID.program());
    }

    private void refreshIfActive(Program program) {
        if (activeProgram == program) {
            setLogs(displayText(program));
        }
    }

    /// The line that ends the log of an analysis that has finished, or null for a status that is not final
    public static String terminalStatusLine(AnalysisStatus status, int analysisId) {
        return switch (status) {
            case Complete -> "RevEng.AI: analysis %d completed.".formatted(analysisId);
            case Error -> ("RevEng.AI: analysis %d failed on the server. Use %s > Analysis > Detach, then create a "
                    + "new analysis or attach to an existing one.").formatted(analysisId, ReaiPluginPackage.MENU_GROUP_NAME);
            default -> null;
        };
    }

    /// The text the panel shows: the logs, followed by how the analysis ended when it has
    public static String withTerminalStatus(String logs, String statusLine) {
        boolean noLogs = logs == null || logs.isBlank();
        if (statusLine == null) {
            return noLogs ? NO_LOGS : logs;
        }
        return noLogs ? statusLine : logs.stripTrailing() + "\n\n" + statusLine;
    }

    public static final String NO_LOGS = "No analysis logs available for the active program.";


    /// What to tell the user when the wait for an analysis ended without it finishing, or null when
    /// there is nothing to tell (it finished, or the user cancelled the wait).
    public static String unfinishedWaitMessage(StatusPoller.Result<AnalysisStatus> result,
                                        GhidraRevengService.ProgramWithID program) {
        return switch (result.ending()) {
            case UNRECOGNISED -> ("RevEng.AI: analysis %d of %s reports a status this plugin does not recognise; "
                    + "stopped waiting for it. Reopen the program to check it again, or use View in portal.")
                    .formatted(program.analysisID().id(), program.program().getName());
            case TIMED_OUT -> ("RevEng.AI: analysis %d of %s has not finished after %s (status: %s); stopped waiting. "
                    + "It keeps running on the server: reopen the program to resume waiting, or use View in portal.")
                    .formatted(program.analysisID().id(), program.program().getName(),
                            StatusPoller.describe(result.waited()), result.status());
            case DONE, CANCELLED -> null;
        };
    }

    class AnalysisMonitoringTask extends Task {

        private final GhidraRevengService.ProgramWithID program;
        private final AnalysisLogConsumer logConsumer;

        public AnalysisMonitoringTask(GhidraRevengService.ProgramWithID programWithID, AnalysisLogConsumer logConsumer) {
            super(programWithID.toString(), true, false, false);
            program = programWithID;
            this.logConsumer = logConsumer;
        }

        @Override
        public void run(TaskMonitor monitor) throws CancelledException {
            // Wait for the analysis
            var service = tool.getService(GhidraRevengService.class);
            try {
                var result = service.waitForAnalysis(monitor, program, this.logConsumer, tool);
                var message = unfinishedWaitMessage(result, program);
                if (message != null) {
                    tool.getService(ReaiLoggingService.class).warn(message);
                    SwingUtilities.invokeLater(() -> tool.setStatusInfo(message, true));
                }
            } finally {
                ///  waitForFinishedAnalysis has already sent the completion event to all plugins
                /// so this task just needs to clean up the tracked programs map
                // Remove ourselves from the tracked programs when done
                trackedPrograms.remove(program.program());
                taskMonitorComponent.setVisible(false);
            }
        }
    }

}

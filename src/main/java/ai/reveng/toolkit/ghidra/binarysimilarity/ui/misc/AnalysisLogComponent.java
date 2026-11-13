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
import ghidra.util.task.WrappingTaskMonitor;

import javax.swing.*;

import java.awt.*;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AnalysisLogComponent extends ComponentProviderAdapter implements AnalysisLogConsumer {
    private final JTextArea textArea;
    private final JScrollPane scroll;
    private TaskMonitorComponent taskMonitorComponent;
    private final JPanel mainPanel;
    /// The task waiting for each program's analysis. At most one per program: a new analysis replaces the
    /// wait for an earlier one, which the program is no longer attached to.
    private final Map<Program, AnalysisMonitoringTask> trackedPrograms =  new ConcurrentHashMap<>();
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
        if (program != null && trackedPrograms.containsKey(program)) {
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
                var tracked = trackedPrograms.get(event.getProgram());
                if (tracked != null && tracked.program.equals(event.getProgramWithBinaryID())) {
                    // Already waiting for this analysis
                    return;
                }
                if (tracked != null) {
                    // Waiting for an analysis the program has since been detached from
                    tracked.stop();
                }
                var task = new AnalysisMonitoringTask(event.getProgramWithBinaryID(), this);
                trackedPrograms.put(event.getProgram(), task);
                TaskBuilder.withTask(task).launchInBackground(task.waitMonitor);
            }
        }

    }

    /// Stop waiting for the program's analysis, e.g. because the program was detached from it. The wait ends
    /// without firing any further status events for it.
    public void stopMonitoring(Program program) {
        var task = trackedPrograms.remove(program);
        if (task != null) {
            task.stop();
        }
        updateMonitorVisibility();
    }

    /// Forget everything about a program that was closed, and stop waiting for its analysis
    public void programClosed(Program program) {
        stopMonitoring(program);
        storedLogs.remove(program);
        terminalStatusLines.remove(program);
        if (activeProgram == program) {
            activeProgram = null;
        }
    }

    private void updateMonitorVisibility() {
        var active = activeProgram;
        var show = active != null && trackedPrograms.containsKey(active);
        if (!show && trackedPrograms.isEmpty()) {
            // Nothing uses the shared monitor any more, so a Cancel pressed on it must not cancel the next wait
            taskMonitorComponent.clearCanceled();
        }
        taskMonitorComponent.setVisible(show);
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

    /// Shows its progress on the shared monitor component, and is cancelled either by the Cancel button there
    /// (which cancels every wait shown on it) or on its own, without cancelling the shared component.
    private static class StoppableMonitor extends WrappingTaskMonitor {
        private volatile boolean stopped;

        StoppableMonitor(TaskMonitor display) {
            super(display);
        }

        @Override
        public boolean isCancelled() {
            return stopped || super.isCancelled();
        }

        @Override
        public void checkCancelled() throws CancelledException {
            if (isCancelled()) {
                throw new CancelledException();
            }
        }

        @Override
        public void cancel() {
            stopped = true;
        }

        @Override
        public void clearCanceled() {
            stopped = false;
        }
    }

    class AnalysisMonitoringTask extends Task {

        private final GhidraRevengService.ProgramWithID program;
        private final AnalysisLogConsumer logConsumer;
        private final StoppableMonitor waitMonitor = new StoppableMonitor(getTaskMonitor());

        public AnalysisMonitoringTask(GhidraRevengService.ProgramWithID programWithID, AnalysisLogConsumer logConsumer) {
            super(programWithID.toString(), true, false, false);
            program = programWithID;
            this.logConsumer = logConsumer;
        }

        void stop() {
            waitMonitor.cancel();
        }

        @Override
        public void run(TaskMonitor monitor) throws CancelledException {
            // Wait for the analysis
            var service = tool.getService(GhidraRevengService.class);
            // Logs fetched just before the wait was stopped belong to an analysis the program has left
            AnalysisLogConsumer logs = (text, programWithID) -> {
                if (!waitMonitor.isCancelled()) {
                    logConsumer.consumeLogs(text, programWithID);
                }
            };
            try {
                var result = service.waitForAnalysis(monitor, program, logs, tool);
                var message = unfinishedWaitMessage(result, program);
                if (message != null) {
                    tool.getService(ReaiLoggingService.class).warn(message);
                    SwingUtilities.invokeLater(() -> tool.setStatusInfo(message, true));
                }
            } finally {
                ///  waitForFinishedAnalysis has already sent the completion event to all plugins
                /// so this task just needs to clean up the tracked programs map
                // Remove ourselves from the tracked programs when done, and only our own entry: a newer analysis of the same program may have replaced it
                trackedPrograms.remove(program.program(), this);
                updateMonitorVisibility();
            }
        }
    }

}

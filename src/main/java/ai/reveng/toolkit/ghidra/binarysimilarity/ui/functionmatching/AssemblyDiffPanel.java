package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import com.github.difflib.DiffUtils;
import com.github.difflib.patch.AbstractDelta;
import com.github.difflib.patch.DeltaType;
import com.github.difflib.patch.Patch;
import ghidra.util.Msg;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/// A panel that displays side-by-side assembly comparison with diff highlighting.
/// Supports synchronized scrolling between the two panes.
/// The panel requires a [GhidraFunctionMatchWithSignature] so it can be easily extended into a general diffing panel
public class AssemblyDiffPanel extends JPanel {
    private static final String PLACEHOLDER_TEXT = "Select a row to view assembly comparison";

    // Diff highlighting colors
    private static final Color DIFF_COLOR_CHANGED = new Color(255, 255, 180);  // Light yellow
    private static final Color DIFF_COLOR_DELETED = new Color(255, 200, 200);  // Light red
    private static final Color DIFF_COLOR_INSERTED = new Color(200, 255, 200); // Light green
    private static final Color DIFF_COLOR_PLACEHOLDER = new Color(240, 240, 240); // Light gray

    private final RSyntaxTextArea localAssemblyTextArea;
    private final RSyntaxTextArea matchedAssemblyTextArea;
    private final RTextScrollPane localAssemblyScrollPane;
    private final RTextScrollPane matchedAssemblyScrollPane;

    private boolean isSyncingScroll = false;

    public AssemblyDiffPanel() {
        super(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Assembly Comparison"));

        // Create text areas
        localAssemblyTextArea = createAssemblyTextArea();
        matchedAssemblyTextArea = createAssemblyTextArea();

        // Create scroll panes
        localAssemblyScrollPane = new RTextScrollPane(localAssemblyTextArea);
        localAssemblyScrollPane.setBorder(BorderFactory.createTitledBorder("Local Function Assembly"));

        matchedAssemblyScrollPane = new RTextScrollPane(matchedAssemblyTextArea);
        matchedAssemblyScrollPane.setBorder(BorderFactory.createTitledBorder("Matched Function Assembly"));

        // Set up synchronized scrolling
        setupSynchronizedScrolling();

        // Create horizontal split pane for side-by-side comparison
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setLeftComponent(localAssemblyScrollPane);
        splitPane.setRightComponent(matchedAssemblyScrollPane);
        splitPane.setResizeWeight(0.5);
        splitPane.setDividerLocation(0.5);

        add(splitPane, BorderLayout.CENTER);

        // Set size to show approximately 10 lines of assembly by default
        setPreferredSize(new Dimension(0, 300));
        setMinimumSize(new Dimension(0, 200));
    }

    private RSyntaxTextArea createAssemblyTextArea() {
        RSyntaxTextArea textArea = new RSyntaxTextArea();
        textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_ASSEMBLER_X86);
        textArea.setCodeFoldingEnabled(false);
        textArea.setEditable(false);
        textArea.setLineWrap(false);
        textArea.setHighlightCurrentLine(false);
        textArea.setText(PLACEHOLDER_TEXT);
        return textArea;
    }

    private void setupSynchronizedScrolling() {
        syncScrollBars(localAssemblyScrollPane.getVerticalScrollBar(),
                       matchedAssemblyScrollPane.getVerticalScrollBar());
        syncScrollBars(matchedAssemblyScrollPane.getVerticalScrollBar(),
                       localAssemblyScrollPane.getVerticalScrollBar());
        syncScrollBars(localAssemblyScrollPane.getHorizontalScrollBar(),
                       matchedAssemblyScrollPane.getHorizontalScrollBar());
        syncScrollBars(matchedAssemblyScrollPane.getHorizontalScrollBar(),
                       localAssemblyScrollPane.getHorizontalScrollBar());
    }

    private void syncScrollBars(JScrollBar source, JScrollBar target) {
        source.addAdjustmentListener(e -> {
            if (!isSyncingScroll) {
                isSyncingScroll = true;
                target.setValue(e.getValue());
                isSyncingScroll = false;
            }
        });
    }

    /**
     * Clear the assembly panels and show placeholder text.
     */
    public void clear() {
        localAssemblyTextArea.removeAllLineHighlights();
        matchedAssemblyTextArea.removeAllLineHighlights();
        localAssemblyTextArea.setText(PLACEHOLDER_TEXT);
        matchedAssemblyTextArea.setText(PLACEHOLDER_TEXT);
    }

    /**
     * Fetch and display assembly comparison for the given function match.
     * Fetching is done in a background thread.
     */
    public void showAssemblyFor(GhidraFunctionMatchWithSignature match, GhidraRevengService revengService) {
        TypedApiInterface.FunctionID localFunctionId = match.functionMatch().origin_function_id();
        TypedApiInterface.FunctionID matchedFunctionId = match.functionMatch().nearest_neighbor_id();

        // Clear existing highlights
        localAssemblyTextArea.removeAllLineHighlights();
        matchedAssemblyTextArea.removeAllLineHighlights();

        // Show loading state
        localAssemblyTextArea.setText("Loading assembly for " + match.function().getName() + "...");
        matchedAssemblyTextArea.setText("Loading assembly for " + match.functionMatch().nearest_neighbor_function_name() + "...");

        // Fetch assembly in background thread
        new AssemblyFetchWorker(localFunctionId, matchedFunctionId, revengService).execute();
    }

    private void displayAssemblyWithDiff(List<String> localAssembly, List<String> matchedAssembly, Patch<String> patch) {
        // Build aligned content with placeholders for proper side-by-side comparison
        List<String> alignedLocal = new ArrayList<>();
        List<String> alignedMatched = new ArrayList<>();
        List<DiffLineType> localLineTypes = new ArrayList<>();
        List<DiffLineType> matchedLineTypes = new ArrayList<>();

        int localIndex = 0;
        int matchedIndex = 0;

        // Process each delta in the patch
        for (AbstractDelta<String> delta : patch.getDeltas()) {
            int sourceStart = delta.getSource().getPosition();
            int targetStart = delta.getTarget().getPosition();

            // Add unchanged lines before this delta
            while (localIndex < sourceStart && matchedIndex < targetStart) {
                alignedLocal.add(localAssembly.get(localIndex++));
                alignedMatched.add(matchedAssembly.get(matchedIndex++));
                localLineTypes.add(DiffLineType.EQUAL);
                matchedLineTypes.add(DiffLineType.EQUAL);
            }

            // Handle the delta based on its type
            List<String> sourceLines = delta.getSource().getLines();
            List<String> targetLines = delta.getTarget().getLines();

            switch (delta.getType()) {
                case DELETE -> {
                    for (String line : sourceLines) {
                        alignedLocal.add(line);
                        alignedMatched.add("");
                        localLineTypes.add(DiffLineType.DELETED);
                        matchedLineTypes.add(DiffLineType.PLACEHOLDER);
                    }
                    localIndex += sourceLines.size();
                }
                case INSERT -> {
                    for (String line : targetLines) {
                        alignedLocal.add("");
                        alignedMatched.add(line);
                        localLineTypes.add(DiffLineType.PLACEHOLDER);
                        matchedLineTypes.add(DiffLineType.INSERTED);
                    }
                    matchedIndex += targetLines.size();
                }
                case CHANGE -> {
                    int maxLines = Math.max(sourceLines.size(), targetLines.size());
                    for (int i = 0; i < maxLines; i++) {
                        alignedLocal.add(i < sourceLines.size() ? sourceLines.get(i) : "");
                        localLineTypes.add(i < sourceLines.size() ? DiffLineType.CHANGED : DiffLineType.PLACEHOLDER);
                        alignedMatched.add(i < targetLines.size() ? targetLines.get(i) : "");
                        matchedLineTypes.add(i < targetLines.size() ? DiffLineType.CHANGED : DiffLineType.PLACEHOLDER);
                    }
                    localIndex += sourceLines.size();
                    matchedIndex += targetLines.size();
                }
                default -> {}
            }
        }

        // Add remaining unchanged lines after the last delta
        while (localIndex < localAssembly.size() && matchedIndex < matchedAssembly.size()) {
            alignedLocal.add(localAssembly.get(localIndex++));
            alignedMatched.add(matchedAssembly.get(matchedIndex++));
            localLineTypes.add(DiffLineType.EQUAL);
            matchedLineTypes.add(DiffLineType.EQUAL);
        }

        // Handle any trailing lines
        while (localIndex < localAssembly.size()) {
            alignedLocal.add(localAssembly.get(localIndex++));
            alignedMatched.add("");
            localLineTypes.add(DiffLineType.DELETED);
            matchedLineTypes.add(DiffLineType.PLACEHOLDER);
        }
        while (matchedIndex < matchedAssembly.size()) {
            alignedLocal.add("");
            alignedMatched.add(matchedAssembly.get(matchedIndex++));
            localLineTypes.add(DiffLineType.PLACEHOLDER);
            matchedLineTypes.add(DiffLineType.INSERTED);
        }

        // Set text content
        localAssemblyTextArea.setText(String.join("\n", alignedLocal));
        matchedAssemblyTextArea.setText(String.join("\n", alignedMatched));
        localAssemblyTextArea.setCaretPosition(0);
        matchedAssemblyTextArea.setCaretPosition(0);

        // Apply line highlights
        applyDiffHighlights(localAssemblyTextArea, localLineTypes);
        applyDiffHighlights(matchedAssemblyTextArea, matchedLineTypes);
    }

    private void applyDiffHighlights(RSyntaxTextArea textArea, List<DiffLineType> lineTypes) {
        textArea.removeAllLineHighlights();

        for (int i = 0; i < lineTypes.size(); i++) {
            Color highlightColor = getColorForLineType(lineTypes.get(i));
            if (highlightColor != null) {
                try {
                    textArea.addLineHighlight(i, highlightColor);
                } catch (Exception e) {
                    // Line index out of bounds - ignore
                }
            }
        }
    }

    private Color getColorForLineType(DiffLineType lineType) {
        return switch (lineType) {
            case DELETED -> DIFF_COLOR_DELETED;
            case INSERTED -> DIFF_COLOR_INSERTED;
            case CHANGED -> DIFF_COLOR_CHANGED;
            case PLACEHOLDER -> DIFF_COLOR_PLACEHOLDER;
            case EQUAL -> null;
        };
    }

    private enum DiffLineType {
        EQUAL,
        DELETED,
        INSERTED,
        CHANGED,
        PLACEHOLDER
    }

    /**
     * SwingWorker to fetch assembly in the background and update the UI when done.
     */
    private class AssemblyFetchWorker extends SwingWorker<Void, Void> {
        private final TypedApiInterface.FunctionID localFunctionId;
        private final TypedApiInterface.FunctionID matchedFunctionId;
        private final GhidraRevengService revengService;

        private List<String> localAssembly;
        private List<String> matchedAssembly;
        private String localError;
        private String matchedError;
        private Patch<String> patch;

        AssemblyFetchWorker(TypedApiInterface.FunctionID localFunctionId,
                           TypedApiInterface.FunctionID matchedFunctionId,
                           GhidraRevengService revengService) {
            this.localFunctionId = localFunctionId;
            this.matchedFunctionId = matchedFunctionId;
            this.revengService = revengService;
        }

        @Override
        protected Void doInBackground() {
            // Fetch local function assembly
            try {
                localAssembly = revengService.getApi().getAssembly(localFunctionId);
            } catch (Exception e) {
                localError = "Failed to fetch assembly: " + e.getMessage();
                Msg.error(this, "Failed to fetch local function assembly", e);
            }

            // Fetch matched function assembly
            try {
                matchedAssembly = revengService.getApi().getAssembly(matchedFunctionId);
            } catch (Exception e) {
                matchedError = "Failed to fetch assembly: " + e.getMessage();
                Msg.error(this, "Failed to fetch matched function assembly", e);
            }

            // Compute diff if both assemblies were fetched successfully
            if (localAssembly != null && matchedAssembly != null) {
                patch = DiffUtils.diff(localAssembly, matchedAssembly);
            }

            return null;
        }

        @Override
        protected void done() {
            if (localError != null) {
                localAssemblyTextArea.setText(localError);
                return;
            }
            if (matchedError != null) {
                matchedAssemblyTextArea.setText(matchedError);
                return;
            }

            if (localAssembly != null && matchedAssembly != null) {
                displayAssemblyWithDiff(localAssembly, matchedAssembly, patch);
            }
        }
    }
}
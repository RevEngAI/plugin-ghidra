package ai.reveng.toolkit.ghidra.chat.model;

import org.commonmark.Extension;
import org.commonmark.ext.gfm.tables.TablesExtension;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;

import java.util.List;

/**
 * Renders CommonMark to HTML for display in the chat panel's {@code JEditorPane}, which understands
 * HTML but not markdown. The IDA plugin gets this for free from Qt's {@code setMarkdown}; here we
 * convert the agent's markdown ourselves. GFM tables are enabled because the agent uses them to lay
 * out parameters, stack variables, etc.
 */
public final class MarkdownRenderer {

    private MarkdownRenderer() {}

    // Parser and HtmlRenderer are thread-safe once built and are reused across renders.
    private static final List<Extension> EXTENSIONS = List.of(TablesExtension.create());
    private static final Parser PARSER = Parser.builder().extensions(EXTENSIONS).build();
    private static final HtmlRenderer RENDERER = HtmlRenderer.builder().extensions(EXTENSIONS).build();

    public static String toHtml(String markdown) {
        if (markdown == null || markdown.isEmpty()) {
            return "";
        }
        return RENDERER.render(PARSER.parse(ensureBlankLineBeforeTables(markdown)));
    }

    /**
     * The agent commonly writes a label directly above a table ("Parameters:\n| ... |") with no blank
     * line between them. CommonMark then treats the table rows as a lazy continuation of the label
     * paragraph and does not render a table. Insert a blank line before a table header (a line
     * followed by a delimiter row) so it parses as a table.
     */
    static String ensureBlankLineBeforeTables(String markdown) {
        String[] lines = markdown.split("\n", -1);
        var out = new StringBuilder(markdown.length() + 16);
        for (int i = 0; i < lines.length; i++) {
            boolean isHeader = i + 1 < lines.length
                    && lines[i].contains("|")
                    && !isDelimiterRow(lines[i])
                    && isDelimiterRow(lines[i + 1]);
            if (isHeader && out.length() > 0 && !endsWithBlankLine(out)) {
                out.append('\n');
            }
            out.append(lines[i]);
            if (i < lines.length - 1) {
                out.append('\n');
            }
        }
        return out.toString();
    }

    private static boolean isDelimiterRow(String line) {
        String trimmed = line.strip();
        if (trimmed.isEmpty()) {
            return false;
        }
        boolean hasDash = false;
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (c == '-') {
                hasDash = true;
            } else if (c != '|' && c != ':' && c != ' ') {
                return false;
            }
        }
        return hasDash;
    }

    private static boolean endsWithBlankLine(StringBuilder out) {
        int len = out.length();
        if (len == 0 || out.charAt(len - 1) != '\n') {
            return false;
        }
        // Two trailing newlines (possibly with a preceding one at start) means the last line is blank.
        return len == 1 || out.charAt(len - 2) == '\n';
    }
}

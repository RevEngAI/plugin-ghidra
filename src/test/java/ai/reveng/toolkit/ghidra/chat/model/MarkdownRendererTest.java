package ai.reveng.toolkit.ghidra.chat.model;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

/** Unit tests for {@link MarkdownRenderer}, including GFM table support. */
public class MarkdownRendererTest {

    @Test
    public void rendersInlineFormatting() {
        String html = MarkdownRenderer.toHtml("Call **main** then `printf`");
        assertTrue(html.contains("<strong>main</strong>"));
        assertTrue(html.contains("<code>printf</code>"));
    }

    @Test
    public void rendersGfmTables() {
        String md = String.join("\n",
                "| Offset | Name | Type |",
                "|--------|------|------|",
                "| 0 | sizes | usize |",
                "| 8 | align | Alignment |");
        String html = MarkdownRenderer.toHtml(md);
        assertTrue("GFM table should render as an HTML table, was: " + html, html.contains("<table>"));
        assertTrue(html.contains("<th>Offset</th>"));
        assertTrue(html.contains("<td>sizes</td>"));
    }

    @Test
    public void rendersTableWhenLabelDirectlyPrecedesItWithoutBlankLine() {
        // The agent writes "Parameters:" directly above the table with no blank line between.
        String md = String.join("\n",
                "Parameters:",
                "| Offset | Name | Type |",
                "|--------|------|------|",
                "| 0 | sizes | usize |");
        String html = MarkdownRenderer.toHtml(md);
        assertTrue("table should render even without a blank line after the label, was: " + html,
                html.contains("<table>"));
        assertTrue(html.contains("<td>sizes</td>"));
    }

    @Test
    public void leavesProseUnchangedWhenNoTablePresent() {
        String html = MarkdownRenderer.toHtml("Just a sentence with a | pipe in it.");
        assertTrue(html.contains("Just a sentence"));
        assertTrue("a lone pipe must not become a table, was: " + html, !html.contains("<table>"));
    }
}

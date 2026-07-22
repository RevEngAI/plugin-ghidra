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
}

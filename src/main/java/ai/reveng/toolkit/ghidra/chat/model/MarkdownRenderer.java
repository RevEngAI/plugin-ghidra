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
        return RENDERER.render(PARSER.parse(markdown));
    }
}

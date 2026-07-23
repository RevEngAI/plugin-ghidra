package ai.reveng.toolkit.ghidra.chat.model;

import ai.reveng.toolkit.ghidra.chat.model.ChatItem.AssistantMessage;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.ContextCompacted;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.FunctionRef;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.Step;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.ToolCall;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.ToolConfirmation;
import ai.reveng.toolkit.ghidra.chat.model.ChatItem.UserMessage;

import java.util.List;

/**
 * Pure presentation helpers for the Agent Chat panel. Turns a {@link ChatState} into an HTML
 * transcript for a {@code JEditorPane}. Port of the IDA plugin's {@code components/tabs/chat_render.py}
 * (which renders markdown for Qt); adapted to HTML because Ghidra panels render HTML, not markdown.
 * No Swing/Ghidra imports, so it is unit-testable.
 */
public final class ChatTranscriptRenderer {

    private ChatTranscriptRenderer() {}

    /// Href scheme for the function-jump links embedded in the transcript.
    public static final String JUMP_SCHEME = "reai://jump/";

    public static String jumpHref(long address) {
        return JUMP_SCHEME + address;
    }

    /// Parse a jump href back to its address offset, or {@code null} if it is not a jump link.
    public static Long parseJumpHref(String url) {
        if (url == null || !url.startsWith(JUMP_SCHEME)) {
            return null;
        }
        try {
            return Long.parseLong(url.substring(JUMP_SCHEME.length()));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public static String titleCase(String name) {
        String pretty = (name == null ? "" : name).replace("_", " ").strip();
        if (pretty.isEmpty()) {
            return name == null || name.isEmpty() ? "tool" : name;
        }
        var sb = new StringBuilder(pretty.length());
        boolean startOfWord = true;
        for (char c : pretty.toCharArray()) {
            if (Character.isWhitespace(c)) {
                startOfWord = true;
                sb.append(c);
            } else if (startOfWord) {
                sb.append(Character.toUpperCase(c));
                startOfWord = false;
            } else {
                sb.append(Character.toLowerCase(c));
            }
        }
        return sb.toString();
    }

    private static final String CHECK = "&#10003;";
    private static final String CROSS = "&#10007;";
    private static final String ELLIPSIS = "&#8230;";
    private static final String CURSOR = "&#9613;";
    private static final String WARNING = "&#9888;";
    private static final String ARROW = "&#8618;";
    private static final String MIDDOT = "&#183;";
    private static final String EMDASH = "&#8212;";

    private static String toolMarker(boolean isError, String status) {
        if (isError) {
            return CROSS;
        }
        return "finished".equals(status) ? CHECK : ELLIPSIS;
    }

    /// Build a single HTML document from the chat items.
    public static String renderTranscriptHtml(ChatState state) {
        var sb = new StringBuilder("<html><body>");
        for (ChatItem item : state.items()) {
            switch (item) {
                case UserMessage m ->
                        sb.append("<p><b>You:</b> ").append(withBreaks(m.content())).append("</p>");
                case AssistantMessage m -> {
                    String content = m.content() == null ? "" : m.content();
                    if (content.isBlank()) {
                        sb.append("<p><i>").append(ELLIPSIS).append("</i></p>");
                    } else {
                        sb.append(MarkdownRenderer.toHtml(content));
                        if (m.isStreaming()) {
                            sb.append("<p>").append(CURSOR).append("</p>");
                        }
                    }
                }
                case ToolCall c -> {
                    sb.append("<p><code>").append(toolMarker(c.isError(), c.status())).append(' ')
                            .append(escape(titleCase(c.name()))).append("</code>");
                    String links = functionLinks(c.functions());
                    if (!links.isEmpty()) {
                        sb.append("<br>").append(links);
                    }
                    sb.append("</p>");
                }
                case Step s -> {
                    if ("running".equals(s.status())) {
                        sb.append("<p><i>").append(escape(s.stepName())).append(ELLIPSIS).append("</i></p>");
                    }
                }
                case ToolConfirmation c -> {
                    String tool = escape(titleCase(c.toolName()));
                    sb.append("<blockquote>");
                    switch (c.status()) {
                        case "pending" -> sb.append(WARNING).append(" <b>Approval needed</b> ").append(EMDASH)
                                .append(" <code>").append(tool).append("</code>");
                        case "approved" -> sb.append(CHECK).append(" Approved ").append(EMDASH)
                                .append(" <code>").append(tool).append("</code>");
                        default -> sb.append(CROSS).append(" Rejected ").append(EMDASH)
                                .append(" <code>").append(tool).append("</code>");
                    }
                    sb.append("</blockquote>");
                }
                case ContextCompacted ignored ->
                        sb.append("<p><i>").append(EMDASH).append(" context compacted ").append(EMDASH).append("</i></p>");
            }
        }

        if ("running".equals(state.runStatus())) {
            ChatItem last = state.items().isEmpty() ? null : state.items().get(state.items().size() - 1);
            if (last == null || last instanceof UserMessage) {
                sb.append("<p><i>Thinking").append(ELLIPSIS).append("</i></p>");
            }
        }

        if ("error".equals(state.runStatus()) && state.runError() != null) {
            sb.append("<blockquote>").append(WARNING).append(" <b>Error:</b> ")
                    .append(escape(state.runError().message())).append("</blockquote>");
        }

        return sb.append("</body></html>").toString();
    }

    private static String functionLinks(List<FunctionRef> functions) {
        if (functions == null || functions.isEmpty()) {
            return "";
        }
        var parts = new StringBuilder();
        for (FunctionRef f : functions) {
            if (f.name() == null || f.name().isEmpty()) {
                continue;
            }
            if (parts.length() > 0) {
                parts.append(" ").append(MIDDOT).append(" ");
            }
            parts.append("<a href=\"").append(jumpHref(f.address())).append("\">")
                    .append(escape(f.name())).append("</a>");
        }
        return parts.length() == 0 ? "" : ARROW + " " + parts;
    }

    /// The last pending tool confirmation, or {@code null} if none is awaiting a decision.
    public static ToolConfirmation findPendingConfirmation(ChatState state) {
        var items = state.items();
        for (int i = items.size() - 1; i >= 0; i--) {
            if (items.get(i) instanceof ToolConfirmation c && "pending".equals(c.status())) {
                return c;
            }
        }
        return null;
    }

    private static String withBreaks(String text) {
        return escape(text).replace("\n", "<br>");
    }

    private static String escape(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }
}

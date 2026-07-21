package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.model.DecompilationData;
import ai.reveng.model.WorkflowProgress;

import javax.annotation.Nullable;
import java.util.List;

/**
 * Polled view of the v3 AI decompilation pipeline for a single function.
 *
 * The v2 task endpoint returned status, decompilation, summary, predicted
 * name and inline comments in one payload. v3 splits those across separate
 * endpoints; this record stitches them back together so callers can treat
 * polling as a single operation.
 *
 * Summary/inline-comments fields are only populated once `status` reaches
 * `COMPLETED`. The server rejects an inline-comments trigger until the
 * summary has been generated, so consumers must gate that POST on
 * `summaryStatus == COMPLETED`.
 */
public record AIDecompilationStatus(
        DecompilationData.StatusEnum status,
        @Nullable String decompilation,
        @Nullable String summary,
        @Nullable String predictedFunctionName,
        @Nullable WorkflowProgress.StatusEnum summaryStatus,
        @Nullable WorkflowProgress.StatusEnum inlineCommentsStatus,
        List<InlineCommentEntry> inlineComments,
        @Nullable WorkflowProgress decompilationProgress
) {
    public record InlineCommentEntry(long line, String comment) {}
}

package ai.reveng.toolkit.ghidra.core.tasks;

import ai.reveng.invoker.ApiException;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

/// A rejected analysis request shows the server's `error.message`, not the raw error body.
public class StartAnalysisTaskDescribeTest {

    private static final ApiException REJECTED = new ApiException(402, Map.of("content-type", List.of("application/json")),
            "{\"error\":{\"code\":\"INSUFFICIENT_CREDITS\",\"message\":\"Not enough credits\"}}");

    @Test
    public void showsServerMessage() {
        assertEquals("HTTP 402 — Not enough credits", StartAnalysisTask.describe(REJECTED));
    }

    @Test
    public void showsServerMessageWhenWrapped() {
        assertEquals("HTTP 402 — Not enough credits", StartAnalysisTask.describe(new RuntimeException(REJECTED)));
    }
}

package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiException;
import org.junit.Test;

import java.net.SocketTimeoutException;

import static org.junit.Assert.assertEquals;

public class PushFailureTest {

    private static ApiException status(int code) {
        return new ApiException(code, "status " + code);
    }

    @Test
    public void noAnswerOrAServerSideErrorMayPass() {
        assertEquals(PushFailure.TRANSIENT, PushFailure.of(new ApiException(new SocketTimeoutException("timeout"))));
        assertEquals(PushFailure.TRANSIENT, PushFailure.of(new ApiException("no answer")));
        for (int code : new int[] {408, 429, 500, 502, 503, 504}) {
            assertEquals("status " + code, PushFailure.TRANSIENT, PushFailure.of(status(code)));
        }
    }

    @Test
    public void aRefusedKeyNeedsTheAnalyst() {
        assertEquals(PushFailure.AUTH, PushFailure.of(status(401)));
        assertEquals(PushFailure.AUTH, PushFailure.of(status(403)));
    }

    @Test
    public void anyOtherClientErrorOrALocalFailureIsFinal() {
        for (int code : new int[] {400, 404, 409, 422}) {
            assertEquals("status " + code, PushFailure.REJECTED, PushFailure.of(status(code)));
        }
        assertEquals(PushFailure.REJECTED, PushFailure.of(new IllegalStateException("renamed 0 of 1")));
        assertEquals(PushFailure.REJECTED, PushFailure.of(new IllegalArgumentException("cannot encode")));
    }

    /// The typed API wraps some failures in a plain RuntimeException.
    @Test
    public void looksThroughWrappers() {
        assertEquals(PushFailure.REJECTED, PushFailure.of(new RuntimeException(status(404))));
        assertEquals(PushFailure.TRANSIENT, PushFailure.of(new RuntimeException(status(503))));
        assertEquals(PushFailure.AUTH, PushFailure.of(new RuntimeException(status(401))));
    }
}

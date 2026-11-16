package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.ApiException;

import java.io.IOException;

/// Why pushing a local edit failed, as far as it decides whether trying again can help.
public enum PushFailure {
    /// The portal could not be reached or could not answer right now: no connection, a timeout, a
    /// 5xx, a 408 or a 429. The same push can succeed later.
    TRANSIENT,
    /// The portal refused the credentials (401 or 403). Nothing succeeds until the API key is fixed.
    AUTH,
    /// The portal turned this particular edit down — another 4xx, or a rename it accepted but did not
    /// apply — or the plugin failed to build the request. Sending it again gets the same answer.
    REJECTED;

    /// Classify a failure by the first HTTP status or I/O error in its cause chain. The typed API
    /// wraps some {@link ApiException}s in a plain RuntimeException, so the chain is searched rather
    /// than the exception itself.
    public static PushFailure of(Throwable failure) {
        boolean unanswered = false;
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof IOException) {
                return TRANSIENT;
            }
            if (cause instanceof ApiException api) {
                int code = api.getCode();
                if (code == 0) {
                    // The client reports a request that never got an answer as code 0, usually
                    // with the I/O error as its cause.
                    unanswered = true;
                } else if (code == 401 || code == 403) {
                    return AUTH;
                } else if (code == 408 || code == 429 || code >= 500) {
                    return TRANSIENT;
                } else {
                    return REJECTED;
                }
            }
        }
        return unanswered ? TRANSIENT : REJECTED;
    }
}

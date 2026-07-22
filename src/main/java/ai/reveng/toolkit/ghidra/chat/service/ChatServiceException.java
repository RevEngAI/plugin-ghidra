package ai.reveng.toolkit.ghidra.chat.service;

/// A user-facing failure from a chat network operation.
public class ChatServiceException extends Exception {
    public ChatServiceException(String message) {
        super(message);
    }

    public ChatServiceException(String message, Throwable cause) {
        super(message, cause);
    }
}

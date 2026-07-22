package ai.reveng.toolkit.ghidra.chat.service;

import ai.reveng.api.ConversationsApi;
import ai.reveng.invoker.ApiClient;
import ai.reveng.invoker.ApiException;
import ai.reveng.invoker.Configuration;
import ai.reveng.invoker.auth.ApiKeyAuth;
import ai.reveng.model.ConfirmToolInputBody;
import ai.reveng.model.Conversation;
import ai.reveng.model.ConversationWithEvents;
import ai.reveng.model.CreateConversationRequest;
import ai.reveng.model.Event;
import ai.reveng.model.SendMessageRequest;
import ai.reveng.toolkit.ghidra.chat.model.ChatEvent;
import ai.reveng.toolkit.ghidra.chat.model.SseParser;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationContext;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationReplay;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.ConversationSummary;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.StoredEvent;
import ai.reveng.toolkit.ghidra.chat.model.Conversations.UserMessageReplay;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * {@link ChatService} backed by the SDK's {@link ConversationsApi}. Short requests reuse the shared,
 * already-authenticated {@link Configuration#getDefaultApiClient() default client}; the SSE stream
 * uses a dedicated client cloned from it with a long read timeout, since the default 15s read timeout
 * would cut a live agent run short.
 */
public class ConversationsApiChatService implements ChatService {

    private static final long STREAM_READ_TIMEOUT_MINUTES = 5;

    private volatile okhttp3.Call activeStreamCall;

    private ConversationsApi shortCallApi() {
        return new ConversationsApi(Configuration.getDefaultApiClient());
    }

    /// A conversations client whose HTTP read timeout is long enough to hold a live SSE stream open.
    private ConversationsApi streamingApi() {
        ApiClient shared = Configuration.getDefaultApiClient();
        ApiClient streamClient = new ApiClient();
        streamClient.setBasePath(shared.getBasePath());
        streamClient.setHttpClient(shared.getHttpClient().newBuilder()
                .readTimeout(STREAM_READ_TIMEOUT_MINUTES, TimeUnit.MINUTES)
                .build());
        if (shared.getAuthentication("APIKey") instanceof ApiKeyAuth sharedKey
                && streamClient.getAuthentication("APIKey") instanceof ApiKeyAuth streamKey) {
            streamKey.setApiKey(sharedKey.getApiKey());
        }
        return new ConversationsApi(streamClient);
    }

    @Override
    public String createConversation(ConversationContext context, String title) throws ChatServiceException {
        var req = new CreateConversationRequest().context(toSdkContext(context)).title(title);
        try {
            Conversation conv = shortCallApi().createConversation(req);
            return conv.getConversationUuid();
        } catch (ApiException e) {
            throw apiError("create conversation", e);
        }
    }

    @Override
    public void sendMessage(String conversationId, String content, ConversationContext context)
            throws ChatServiceException {
        var req = new SendMessageRequest().content(content).context(toSdkContext(context));
        try {
            shortCallApi().sendMessage(UUID.fromString(conversationId), req);
        } catch (ApiException e) {
            // 409 means a run is already in progress for this conversation — treat as success.
            if (e.getCode() == 409) {
                return;
            }
            throw apiError("send message", e);
        }
    }

    @Override
    public void confirmTool(String conversationId, boolean approved) throws ChatServiceException {
        try {
            shortCallApi().confirmTool(UUID.fromString(conversationId),
                    new ConfirmToolInputBody().approved(approved));
        } catch (ApiException e) {
            if (e.getCode() == 404) {
                return;
            }
            throw apiError("confirm tool", e);
        }
    }

    @Override
    public void cancelRun(String conversationId) throws ChatServiceException {
        try {
            shortCallApi().cancelRun(UUID.fromString(conversationId));
        } catch (ApiException e) {
            if (e.getCode() == 404) {
                return;
            }
            throw apiError("cancel run", e);
        }
    }

    @Override
    public List<ConversationSummary> listConversations() throws ChatServiceException {
        try {
            List<Conversation> convs = shortCallApi().listConversations();
            var out = new ArrayList<ConversationSummary>();
            if (convs != null) {
                for (Conversation c : convs) {
                    out.add(new ConversationSummary(c.getConversationUuid(), c.getTitle(),
                            c.getUpdatedAt() == null ? null : c.getUpdatedAt().toString()));
                }
            }
            return out;
        } catch (ApiException e) {
            throw apiError("list conversations", e);
        }
    }

    @Override
    public ConversationReplay getConversation(String conversationId) throws ChatServiceException {
        try {
            ConversationWithEvents conv = shortCallApi().getConversation(UUID.fromString(conversationId));
            return new ConversationReplay(conv.getConversationUuid(), conv.getTitle(),
                    replayEvents(conv.getEvents()));
        } catch (ApiException e) {
            throw apiError("load conversation", e);
        }
    }

    @Override
    public void stream(String conversationId, Long lastEventId, BooleanSupplier isCancelled,
                       Consumer<ChatEvent> onEvent) throws ChatServiceException {
        okhttp3.Call call;
        try {
            call = streamingApi().streamEventsCall(UUID.fromString(conversationId), lastEventId, null);
        } catch (ApiException e) {
            throw apiError("open stream", e);
        }
        activeStreamCall = call;
        try (okhttp3.Response response = call.execute()) {
            if (!response.isSuccessful()) {
                throw new ChatServiceException("Streaming failed: HTTP " + response.code());
            }
            okhttp3.ResponseBody body = response.body();
            if (body == null) {
                return;
            }
            try (BufferedReader reader = new BufferedReader(body.charStream())) {
                SseParser.parse(reader, isCancelled, onEvent);
            }
        } catch (IOException e) {
            // A closed/dropped connection ends the stream; only surface it if we did not cancel.
            if (!isCancelled.getAsBoolean() && !call.isCanceled()) {
                throw new ChatServiceException("Stream ended: " + e.getMessage(), e);
            }
        } finally {
            activeStreamCall = null;
        }
    }

    @Override
    public void closeActiveStream() {
        okhttp3.Call call = activeStreamCall;
        if (call != null) {
            call.cancel();
        }
    }

    private static ai.reveng.model.ConversationContext toSdkContext(ConversationContext context) {
        if (context == null || context.isEmpty()) {
            return null;
        }
        return new ai.reveng.model.ConversationContext()
                .analysisId(context.analysisId())
                .functionId(context.functionId());
    }

    /**
     * Reconstruct stored events for history replay. Mirrors {@code _replay_events}: role-USER
     * TEXT_MESSAGE_* events collapse into a single {@link UserMessageReplay}; everything else is
     * normalized like a live frame.
     */
    @SuppressWarnings("unchecked")
    private static List<StoredEvent> replayEvents(List<Event> events) {
        var out = new ArrayList<StoredEvent>();
        if (events == null) {
            return out;
        }
        var emittedUserIds = new java.util.HashSet<String>();
        String currentUserId = null;
        var currentUserContent = new StringBuilder();

        for (Event ev : events) {
            String etype = ChatEvent.resolveType(ev.getType());
            Integer role = ev.getRole();
            Map<String, Object> data = ev.getData() instanceof Map ? (Map<String, Object>) ev.getData() : Map.of();

            if (role != null && role == ChatEvent.ROLE_USER) {
                if ("TEXT_MESSAGE_START".equals(etype)) {
                    Object msgId = data.get("message_id");
                    String id = msgId != null ? msgId.toString()
                            : (ev.getEventId() != null ? ev.getEventId().toString() : "");
                    if (!emittedUserIds.contains(id)) {
                        currentUserId = id;
                        currentUserContent.setLength(0);
                    } else {
                        currentUserId = null;
                    }
                } else if ("TEXT_MESSAGE_CONTENT".equals(etype)) {
                    if (currentUserId != null && data.get("delta") != null) {
                        currentUserContent.append(data.get("delta"));
                    }
                } else if ("TEXT_MESSAGE_END".equals(etype)) {
                    if (currentUserId != null) {
                        out.add(StoredEvent.of(new UserMessageReplay(currentUserId, currentUserContent.toString())));
                        emittedUserIds.add(currentUserId);
                        currentUserId = null;
                        currentUserContent.setLength(0);
                    }
                }
                continue;
            }

            ChatEvent norm = ChatEvent.normalize(ev.getType(), data, null);
            if (norm != null) {
                out.add(StoredEvent.of(norm));
            }
        }
        return out;
    }

    private static ChatServiceException apiError(String action, ApiException e) {
        String detail = e.getResponseBody();
        if (detail == null || detail.isBlank()) {
            detail = e.getMessage();
        }
        return new ChatServiceException("Failed to %s: %s".formatted(action, detail), e);
    }
}

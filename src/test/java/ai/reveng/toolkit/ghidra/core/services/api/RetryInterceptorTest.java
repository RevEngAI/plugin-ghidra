package ai.reveng.toolkit.ghidra.core.services.api;

import com.sun.net.httpserver.HttpServer;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/// Exercised through a real {@link OkHttpClient} against a loopback server, with the waits recorded
/// instead of slept.
public class RetryInterceptorTest {

    /// One canned answer: a status code and, optionally, a `Retry-After`.
    private record Answer(int code, String retryAfter) {
        static Answer of(int code) {
            return new Answer(code, null);
        }
    }

    private HttpServer server;
    private final ConcurrentLinkedQueue<Answer> answers = new ConcurrentLinkedQueue<>();
    private final List<String> methods = new ArrayList<>();
    private final List<Duration> sleeps = new ArrayList<>();
    private OkHttpClient client;

    @Before
    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            synchronized (methods) {
                methods.add(exchange.getRequestMethod());
            }
            var answer = answers.isEmpty() ? Answer.of(200) : answers.poll();
            if (answer.retryAfter() != null) {
                exchange.getResponseHeaders().add("Retry-After", answer.retryAfter());
            }
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(answer.code(), -1);
            exchange.close();
        });
        server.start();
        client = new OkHttpClient.Builder()
                .addInterceptor(new RetryInterceptor(4, Duration.ofSeconds(1), Duration.ofSeconds(30), sleeps::add))
                .build();
    }

    @After
    public void stop() {
        server.stop(0);
    }

    private int send(String method) throws IOException {
        var body = method.equals("GET") ? null : RequestBody.create("{}", MediaType.get("application/json"));
        var request = new Request.Builder()
                .url("http://127.0.0.1:" + server.getAddress().getPort() + "/v2/anything")
                .method(method, body)
                .build();
        try (var response = client.newCall(request).execute()) {
            return response.code();
        }
    }

    private void answer(Answer... canned) {
        answers.addAll(List.of(canned));
    }

    @Test
    public void retriesAServerErrorAndReturnsTheEventualSuccess() throws IOException {
        answer(Answer.of(503));

        assertEquals(200, send("GET"));
        assertEquals(2, methods.size());
        assertEquals(List.of(Duration.ofSeconds(1)), sleeps);
    }

    @Test
    public void backsOffExponentiallyAndGivesUpAfterTheLastAttempt() throws IOException {
        answer(Answer.of(500), Answer.of(502), Answer.of(503), Answer.of(504));

        assertEquals("the last answer reaches the caller", 504, send("GET"));
        assertEquals(4, methods.size());
        assertEquals(List.of(Duration.ofSeconds(1), Duration.ofSeconds(2), Duration.ofSeconds(4)), sleeps);
    }

    @Test
    public void waitsAsLongAsRetryAfterAsks() throws IOException {
        answer(new Answer(429, "3"));

        assertEquals(200, send("GET"));
        assertEquals(List.of(Duration.ofSeconds(3)), sleeps);
    }

    /// Blocking a Ghidra task for minutes is worse than reporting the rate limit.
    @Test
    public void doesNotWaitOutARetryAfterBeyondTheCap() throws IOException {
        answer(new Answer(429, "120"));

        assertEquals(429, send("GET"));
        assertEquals(1, methods.size());
        assertTrue(sleeps.isEmpty());
    }

    /// The first attempt may already have taken effect.
    @Test
    public void neverRetriesPostOrPatch() throws IOException {
        answer(Answer.of(503), Answer.of(503));

        assertEquals(503, send("POST"));
        assertEquals(503, send("PATCH"));
        assertEquals(List.of("POST", "PATCH"), methods);
        assertTrue(sleeps.isEmpty());
    }

    @Test
    public void retriesPutAndDelete() throws IOException {
        answer(Answer.of(503));
        assertEquals(200, send("PUT"));
        answer(Answer.of(503));
        assertEquals(200, send("DELETE"));
        assertEquals(List.of("PUT", "PUT", "DELETE", "DELETE"), methods);
    }

    @Test
    public void leavesClientErrorsAlone() throws IOException {
        for (int code : new int[] {400, 401, 404, 422}) {
            answer(Answer.of(code));
            assertEquals(code, send("GET"));
        }
        assertEquals(4, methods.size());
        assertTrue(sleeps.isEmpty());
    }

    @Test
    public void readsRetryAfterAsSecondsOrAnHttpDate() {
        assertEquals(Duration.ofSeconds(7), RetryInterceptor.retryAfter("7").orElseThrow());
        assertTrue(RetryInterceptor.retryAfter("soon").isEmpty());
        assertTrue(RetryInterceptor.retryAfter(null).isEmpty());

        var inTenSeconds = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(10)
                .format(DateTimeFormatter.RFC_1123_DATE_TIME);
        var wait = RetryInterceptor.retryAfter(inTenSeconds).orElseThrow();
        assertTrue(wait + " should be about ten seconds",
                wait.compareTo(Duration.ofSeconds(8)) >= 0 && wait.compareTo(Duration.ofSeconds(10)) <= 0);

        var past = ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(1).format(DateTimeFormatter.RFC_1123_DATE_TIME);
        assertEquals(Duration.ZERO, RetryInterceptor.retryAfter(past).orElseThrow());
    }
}

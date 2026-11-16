package ai.reveng.toolkit.ghidra.core.services.api;

import okhttp3.Dns;
import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Covers {@link TimeoutDns}, which stops a hanging DNS lookup (e.g. with no network) from
 * blocking a request past OkHttp's connect timeout.
 */
public class TimeoutDnsTest {

    @Test
    public void returnsTheDelegatesAddresses() throws Exception {
        var addresses = List.of(InetAddress.getByAddress("api.reveng.ai", new byte[]{10, 0, 0, 1}));
        var dns = new TimeoutDns(hostname -> addresses, Duration.ofSeconds(1));

        assertEquals(addresses, dns.lookup("api.reveng.ai"));
    }

    @Test
    public void failsWhenTheLookupHangs() {
        var neverReleased = new CountDownLatch(1);
        Dns hanging = hostname -> {
            try {
                neverReleased.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return List.of();
        };
        var dns = new TimeoutDns(hanging, Duration.ofMillis(200));

        long start = System.nanoTime();
        var e = assertThrows(UnknownHostException.class, () -> dns.lookup("api.reveng.ai"));
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;

        assertTrue(e.getMessage(), e.getMessage().contains("timed out"));
        assertTrue("lookup should give up near the timeout, took " + elapsedMillis + "ms", elapsedMillis < 2000);
    }

    @Test
    public void passesThroughUnknownHost() {
        var unknown = new UnknownHostException("no such host");
        var dns = new TimeoutDns(hostname -> { throw unknown; }, Duration.ofSeconds(1));

        assertSame(unknown, assertThrows(UnknownHostException.class, () -> dns.lookup("nope.invalid")));
    }
}

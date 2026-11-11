package ai.reveng.toolkit.ghidra.core.services.api;

import okhttp3.Dns;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/// A {@link Dns} that gives up on a lookup after {@code timeout}.
///
/// OkHttp's connect timeout only starts once an address is resolved. Without a working network
/// the system resolver can block for far longer than that, so every request, and any thread
/// waiting on one, hangs until the OS gives up on DNS.
public record TimeoutDns(Dns delegate, Duration timeout) implements Dns {

    private static final ExecutorService RESOLVER = Executors.newCachedThreadPool(runnable -> {
        var thread = new Thread(runnable, "RevEng.AI-DNS");
        thread.setDaemon(true);
        return thread;
    });

    @Override
    public List<InetAddress> lookup(String hostname) throws UnknownHostException {
        var lookup = RESOLVER.submit(() -> delegate.lookup(hostname));
        try {
            return lookup.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            lookup.cancel(true);
            throw new UnknownHostException("DNS lookup for %s timed out after %ds".formatted(hostname, timeout.toSeconds()));
        } catch (ExecutionException e) {
            if (e.getCause() instanceof UnknownHostException unknownHost) {
                throw unknownHost;
            }
            var unknownHost = new UnknownHostException("DNS lookup for %s failed".formatted(hostname));
            unknownHost.initCause(e.getCause());
            throw unknownHost;
        } catch (InterruptedException e) {
            lookup.cancel(true);
            Thread.currentThread().interrupt();
            throw new UnknownHostException("DNS lookup for %s was interrupted".formatted(hostname));
        }
    }
}

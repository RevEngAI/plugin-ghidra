package ai.reveng.toolkit.ghidra.core.services.update;

import org.json.JSONException;
import org.json.JSONObject;
import resources.ResourceManager;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Checks GitHub for a plugin release newer than the installed one.
 */
public class UpdateChecker {
    public static final String UNKNOWN_VERSION = "unknown";
    private static final String LATEST_RELEASE_URL =
            "https://api.github.com/repos/RevEngAI/plugin-ghidra/releases/latest";

    public record UpdateInfo(String version, String releaseUrl, String downloadUrl) {}

    /**
     * The installed plugin's release tag, or {@link #UNKNOWN_VERSION} for local builds.
     */
    public static String currentVersion() {
        // This resource is written by the release workflow, so it is absent from a local build
        // and the stream is then null.
        try (var inputStream = ResourceManager.getResourceAsStream("reai_ghidra_plugin_version.txt")) {
            if (inputStream != null) {
                return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).trim();
            }
        } catch (IOException e) {
            // ignore — fall back to "unknown"
        }
        return UNKNOWN_VERSION;
    }

    /**
     * Fetches the latest release. Completes empty when up to date, when no build exists for
     * {@code ghidraVersion}, or on any failure.
     */
    public static CompletableFuture<Optional<UpdateInfo>> check(String currentVersion, String ghidraVersion) {
        var request = HttpRequest.newBuilder(URI.create(LATEST_RELEASE_URL))
                .header("Accept", "application/vnd.github+json")
                .timeout(Duration.ofSeconds(10))
                .build();
        return HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build()
                .sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> response.statusCode() == 200
                        ? findUpdate(currentVersion, ghidraVersion, response.body())
                        : Optional.<UpdateInfo>empty())
                .exceptionally(e -> Optional.empty());
    }

    static Optional<UpdateInfo> findUpdate(String currentVersion, String ghidraVersion, String releaseJson) {
        try {
            var release = new JSONObject(releaseJson);
            var latest = release.getString("tag_name");
            if (!isNewer(latest, currentVersion)) {
                return Optional.empty();
            }
            var assetName = "ghidra_" + ghidraVersion + "_plugin-ghidra.zip";
            var assets = release.getJSONArray("assets");
            for (int i = 0; i < assets.length(); i++) {
                var asset = assets.getJSONObject(i);
                if (assetName.equals(asset.getString("name"))) {
                    return Optional.of(new UpdateInfo(latest, release.getString("html_url"),
                            asset.getString("browser_download_url")));
                }
            }
        } catch (JSONException ignored) {
        }
        return Optional.empty();
    }

    static boolean isNewer(String candidate, String current) {
        var a = parse(candidate);
        var b = parse(current);
        if (a.isEmpty() || b.isEmpty()) {
            return false;
        }
        for (int i = 0; i < 3; i++) {
            if (a.get()[i] != b.get()[i]) {
                return a.get()[i] > b.get()[i];
            }
        }
        return false;
    }

    private static Optional<int[]> parse(String version) {
        var parts = version.strip().replaceFirst("^v", "").split("\\.");
        if (parts.length != 3) {
            return Optional.empty();
        }
        try {
            var numbers = new int[3];
            for (int i = 0; i < 3; i++) {
                numbers[i] = Integer.parseInt(parts[i]);
            }
            return Optional.of(numbers);
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }
}

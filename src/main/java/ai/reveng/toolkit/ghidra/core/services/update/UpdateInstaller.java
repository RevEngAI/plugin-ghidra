package ai.reveng.toolkit.ghidra.core.services.update;

import ai.reveng.toolkit.ghidra.core.services.update.UpdateChecker.UpdateInfo;
import ghidra.framework.Application;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.zip.ZipInputStream;

import static ai.reveng.toolkit.ghidra.core.services.update.ExtensionSwapper.EXTENSION_DIR;
import static ai.reveng.toolkit.ghidra.core.services.update.ExtensionSwapper.READY_FILE;

/**
 * Downloads a plugin release in the background and installs it when Ghidra closes.
 * <p>
 * The release is unpacked into a staging folder in the user settings directory, outside
 * {@code Extensions/} so Ghidra does not load it as a second copy. As Ghidra shuts down, a shutdown
 * hook starts {@link ExtensionSwapper} in its own JVM, which waits for Ghidra to exit and then moves
 * the staged folder over the installed one.
 */
public final class UpdateInstaller {
    private static final String STAGING_DIR = "reai-plugin-update";
    private static final String DOWNLOAD_FILE = "download.zip";
    // The swapper runs from a copy, so it doesn't hold the jar it is about to replace open.
    private static final String UPDATER_JAR = "updater.jar";
    private static final String LOG_FILE = "update.log";
    private static final String PLUGIN_JAR = "lib/plugin-ghidra.jar";

    // Every CodeBrowser runs its own update check; these keep it to one download and one hook per JVM.
    private static final Map<String, CompletableFuture<Void>> downloads = new HashMap<>();
    private static boolean startupHandled = false;
    private static Thread shutdownHook;

    private UpdateInstaller() {}

    /**
     * The folder this plugin runs from, if it is one this user can replace: a {@code plugin-ghidra}
     * folder in the user's own {@code Extensions/} directory. Empty for a local build or an
     * extension installed into the Ghidra installation.
     */
    public static Optional<Path> installedExtension() {
        try {
            var installed = Application.getMyModuleRootDirectory().getFile(false).toPath().toRealPath();
            var extensions = Application.getUserSettingsDirectory().toPath().resolve("Extensions").toRealPath();
            if (extensions.equals(installed.getParent())
                    && installed.getFileName().toString().equals(EXTENSION_DIR)
                    && Files.isRegularFile(installed.resolve(PLUGIN_JAR))) {
                return Optional.of(installed);
            }
        } catch (IOException | RuntimeException e) {
            Msg.debug(UpdateInstaller.class, "Cannot locate the installed extension", e);
        }
        return Optional.empty();
    }

    /**
     * Logs the result of the last install and then either keeps a staged release newer than
     * {@code currentVersion} (so it installs when this session closes, even offline) or removes
     * whatever is staged. Only the first call per JVM does anything.
     */
    public static synchronized void handleStartup(String currentVersion, Optional<Path> installed) {
        if (startupHandled) {
            return;
        }
        startupHandled = true;
        var staging = stagingDir();
        try {
            var log = staging.resolve(LOG_FILE);
            if (Files.exists(log)) {
                Msg.info(UpdateInstaller.class, "RevEng.AI plugin update: " + Files.readString(log).strip());
                Files.delete(log);
            }
            var staged = stagedVersion(staging);
            if (installed.isPresent() && staged.isPresent() && UpdateChecker.isNewer(staged.get(), currentVersion)) {
                registerShutdownHook(installed.get(), staging);
            } else {
                ExtensionSwapper.deleteRecursively(staging);
            }
        } catch (IOException e) {
            Msg.warn(UpdateInstaller.class, "Cannot clean up the RevEng.AI update folder " + staging, e);
        }
    }

    /**
     * Downloads, verifies and unpacks {@code update}, then arranges for it to be installed over
     * {@code installed} when Ghidra exits. Completes exceptionally if any step fails, leaving
     * nothing staged.
     */
    public static synchronized CompletableFuture<Void> stage(UpdateInfo update, Path installed) {
        return downloads.computeIfAbsent(update.version(), version -> CompletableFuture.runAsync(() -> {
            var staging = stagingDir();
            try {
                if (!stagedVersion(staging).orElse("").equals(version)) {
                    download(update, installed, staging);
                }
            } catch (IOException e) {
                deleteQuietly(staging);
                throw new UncheckedIOException(e);
            } catch (InterruptedException e) {
                deleteQuietly(staging);
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
            registerShutdownHook(installed, staging);
        }));
    }

    /** Drops the staged release so nothing is installed on exit. */
    public static synchronized void cancel() {
        downloads.clear();
        deleteQuietly(stagingDir());
    }

    private static void download(UpdateInfo update, Path installed, Path staging) throws IOException, InterruptedException {
        ExtensionSwapper.deleteRecursively(staging);
        Files.createDirectories(staging);

        var zip = staging.resolve(DOWNLOAD_FILE);
        var request = HttpRequest.newBuilder(URI.create(update.downloadUrl()))
                .timeout(Duration.ofMinutes(5))
                .build();
        var response = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(10))
                .build()
                .send(request, HttpResponse.BodyHandlers.ofFile(zip));
        if (response.statusCode() != 200) {
            throw new IOException("Downloading " + update.downloadUrl() + " returned HTTP " + response.statusCode());
        }
        verifySha256(zip, update.sha256());
        extract(zip, staging);
        Files.delete(zip);

        Files.copy(installed.resolve(PLUGIN_JAR), staging.resolve(UPDATER_JAR));
        Files.writeString(staging.resolve(READY_FILE), update.version());
    }

    static void verifySha256(Path file, String expected) throws IOException {
        if (expected == null) {
            throw new IOException("The release does not publish a checksum for " + file.getFileName());
        }
        try (var in = Files.newInputStream(file)) {
            var digest = MessageDigest.getInstance("SHA-256");
            var buffer = new byte[64 * 1024];
            for (int n; (n = in.read(buffer)) != -1; ) {
                digest.update(buffer, 0, n);
            }
            var actual = HexFormat.of().formatHex(digest.digest());
            if (!actual.equalsIgnoreCase(expected)) {
                throw new IOException("Checksum mismatch for " + file.getFileName() + ": expected " + expected + ", got " + actual);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Unpacks the {@code plugin-ghidra/} folder of a release zip into {@code staging}. */
    static void extract(Path zip, Path staging) throws IOException {
        var root = staging.resolve(EXTENSION_DIR).normalize();
        try (var in = new ZipInputStream(Files.newInputStream(zip))) {
            for (var entry = in.getNextEntry(); entry != null; entry = in.getNextEntry()) {
                var target = staging.resolve(entry.getName()).normalize();
                if (!target.startsWith(root)) {
                    throw new IOException("Unexpected entry in release zip: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(target);
                } else {
                    Files.createDirectories(target.getParent());
                    // Release zips list some files twice.
                    Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
        if (!Files.isRegularFile(root.resolve("extension.properties")) || !Files.isRegularFile(root.resolve(PLUGIN_JAR))) {
            throw new IOException(zip.getFileName() + " is not a " + EXTENSION_DIR + " build");
        }
    }

    private static synchronized void registerShutdownHook(Path installed, Path staging) {
        if (shutdownHook != null) {
            return;
        }
        shutdownHook = new Thread(() -> launchSwapper(installed, staging), "RevEng.AI plugin update");
        Runtime.getRuntime().addShutdownHook(shutdownHook);
    }

    private static void launchSwapper(Path installed, Path staging) {
        if (!Files.exists(staging.resolve(READY_FILE))) {
            return;
        }
        var bin = Path.of(System.getProperty("java.home"), "bin");
        // javaw has no console window, so nothing flashes up on Windows after Ghidra closes.
        var java = Files.exists(bin.resolve("javaw.exe")) ? bin.resolve("javaw.exe")
                : Files.exists(bin.resolve("java.exe")) ? bin.resolve("java.exe")
                : bin.resolve("java");
        try {
            new ProcessBuilder(java.toString(), "-cp", staging.resolve(UPDATER_JAR).toString(),
                    ExtensionSwapper.class.getName(),
                    Long.toString(ProcessHandle.current().pid()), installed.toString(), staging.toString())
                    .redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.appendTo(staging.resolve(LOG_FILE).toFile()))
                    .start();
        } catch (IOException e) {
            // Ghidra is shutting down, so stderr is the only place left to report this.
            System.err.println("RevEng.AI: cannot start the plugin updater: " + e);
        }
    }

    private static Path stagingDir() {
        return Application.getUserSettingsDirectory().toPath().resolve(STAGING_DIR);
    }

    static Optional<String> stagedVersion(Path staging) {
        try {
            var ready = staging.resolve(READY_FILE);
            return Files.exists(ready) ? Optional.of(Files.readString(ready).strip()) : Optional.empty();
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            ExtensionSwapper.deleteRecursively(path);
        } catch (IOException e) {
            Msg.warn(UpdateInstaller.class, "Cannot delete " + path, e);
        }
    }
}

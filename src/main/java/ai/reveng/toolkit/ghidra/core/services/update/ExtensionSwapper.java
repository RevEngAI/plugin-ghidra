package ai.reveng.toolkit.ghidra.core.services.update;

import java.io.IOException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Comparator;

/**
 * Moves a staged update into the Extensions folder once Ghidra has exited.
 * <p>
 * Ghidra keeps the installed jars open for as long as it runs (and Windows locks open files), so the
 * running plugin cannot replace itself. {@link UpdateInstaller} starts this class in a separate JVM as
 * Ghidra shuts down. Its classpath is a copy of the plugin jar and nothing else, so it must only use
 * the JDK and must not touch {@link UpdateInstaller} or any Ghidra class.
 */
public final class ExtensionSwapper {
    /** Folder name of the extension, both installed and inside the release zip. */
    static final String EXTENSION_DIR = "plugin-ghidra";
    /** Holds the staged release tag. Written last when staging and removed on install or skip. */
    static final String READY_FILE = "ready";
    static final String PREVIOUS_DIR = "previous";

    private static final int MOVE_ATTEMPTS = 10;

    private ExtensionSwapper() {}

    /** Arguments: Ghidra's process id, the installed extension folder, the staging folder. */
    public static void main(String[] args) throws Exception {
        long ghidraPid = Long.parseLong(args[0]);
        var installed = Path.of(args[1]);
        var staging = Path.of(args[2]);

        ProcessHandle.of(ghidraPid).ifPresent(ghidra -> ghidra.onExit().join());
        try {
            System.out.println(Instant.now() + " " + swap(installed, staging));
        } catch (Exception e) {
            System.out.println(Instant.now() + " Update failed, the previous version is still installed");
            e.printStackTrace(System.out);
        }
    }

    /**
     * Replaces {@code installed} with the extension staged under {@code staging}, restoring the old
     * one if the new one cannot be moved in. Returns a line for the update log.
     */
    static String swap(Path installed, Path staging) throws IOException, InterruptedException {
        var ready = staging.resolve(READY_FILE);
        if (!Files.exists(ready)) {
            return "No staged update (skipped by the user)";
        }
        var version = Files.readString(ready).strip();
        // Ghidra's uninstall renames extension.properties away; don't bring back what the user removed.
        if (!Files.exists(installed.resolve("extension.properties"))) {
            Files.delete(ready);
            return "Not installing " + version + ": the extension is no longer installed at " + installed;
        }

        var previous = staging.resolve(PREVIOUS_DIR);
        deleteRecursively(previous);
        move(installed, previous);
        try {
            move(staging.resolve(EXTENSION_DIR), installed);
        } catch (IOException e) {
            move(previous, installed);
            throw e;
        }
        Files.delete(ready);
        deleteRecursively(previous);
        return "Installed " + version + " into " + installed;
    }

    /** Renames {@code from} to {@code to}, retrying while Windows still holds handles from Ghidra. */
    private static void move(Path from, Path to) throws IOException, InterruptedException {
        for (int attempt = 1; ; attempt++) {
            try {
                Files.move(from, to);
                return;
            } catch (NoSuchFileException e) {
                throw e;
            } catch (FileSystemException e) {
                if (attempt == MOVE_ATTEMPTS) {
                    throw e;
                }
                Thread.sleep(1000);
            }
        }
    }

    static void deleteRecursively(Path path) throws IOException {
        if (!Files.exists(path)) {
            return;
        }
        try (var paths = Files.walk(path)) {
            for (var p : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(p);
            }
        }
    }
}

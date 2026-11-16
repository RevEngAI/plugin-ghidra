package ai.reveng;

import org.junit.platform.launcher.LauncherSession;
import org.junit.platform.launcher.LauncherSessionListener;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/// Gives each test JVM its own Ghidra temp dir. Ghidra clears and restores write permission on that
/// dir whenever a JVM initialises, so forks sharing one fail file creation with "Permission denied".
public class ForkTempDir implements LauncherSessionListener {

    static final String PROPERTY = "application.tempdir";

    @Override
    public void launcherSessionOpened(LauncherSession session) {
        if (System.getProperty(PROPERTY) != null) {
            return;
        }
        try {
            String root = System.getProperty("reveng.test.fork.tmproot");
            var dir = root == null
                    ? Files.createTempDirectory("ghidra-test-fork")
                    : Files.createTempDirectory(Path.of(root), "fork");
            System.setProperty(PROPERTY, dir.toString());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}

package ai.reveng;

import ghidra.framework.Application;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/// Ghidra briefly drops write permission on its user temp dir whenever a JVM starts, so parallel
/// test forks sharing one dir fail to create files at random. Each fork must get its own.
public class ForkTempDirTest extends AbstractGhidraHeadlessIntegrationTest {

    @Test
    public void ghidraTempDirIsPrivateToThisFork() {
        String forkTempDir = System.getProperty("application.tempdir");
        assertNotNull("per-fork temp dir must be set", forkTempDir);
        File userTempDir = Application.getUserTempDirectory();
        assertTrue(userTempDir + " should be under " + forkTempDir,
                userTempDir.toPath().startsWith(new File(forkTempDir).toPath()));
    }
}

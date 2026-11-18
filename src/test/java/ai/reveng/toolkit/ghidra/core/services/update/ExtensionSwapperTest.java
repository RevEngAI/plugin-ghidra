package ai.reveng.toolkit.ghidra.core.services.update;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/** Unit tests for {@link ExtensionSwapper#swap}. */
public class ExtensionSwapperTest {
    @Rule
    public TemporaryFolder temp = new TemporaryFolder();

    private Path installed;
    private Path staging;

    @Before
    public void setUp() throws IOException {
        installed = temp.newFolder("Extensions", "plugin-ghidra").toPath();
        Files.writeString(installed.resolve("extension.properties"), "old");
        staging = temp.newFolder("reai-plugin-update").toPath();
        Files.createDirectories(staging.resolve("plugin-ghidra"));
        Files.writeString(staging.resolve("plugin-ghidra/extension.properties"), "new");
        Files.writeString(staging.resolve(ExtensionSwapper.READY_FILE), "v1.3.0");
    }

    @Test
    public void installsStagedExtension() throws Exception {
        var result = ExtensionSwapper.swap(installed, staging);

        assertTrue(result, result.startsWith("Installed v1.3.0"));
        assertEquals("new", Files.readString(installed.resolve("extension.properties")));
        assertFalse(Files.exists(staging.resolve(ExtensionSwapper.READY_FILE)));
        assertFalse(Files.exists(staging.resolve(ExtensionSwapper.PREVIOUS_DIR)));
    }

    @Test
    public void doesNothingWhenSkipped() throws Exception {
        Files.delete(staging.resolve(ExtensionSwapper.READY_FILE));

        ExtensionSwapper.swap(installed, staging);

        assertEquals("old", Files.readString(installed.resolve("extension.properties")));
    }

    @Test
    public void doesNotReinstallAnUninstalledExtension() throws Exception {
        Files.move(installed.resolve("extension.properties"), installed.resolve("extension.properties.uninstalled"));

        ExtensionSwapper.swap(installed, staging);

        assertFalse(Files.exists(installed.resolve("extension.properties")));
        assertFalse(Files.exists(staging.resolve(ExtensionSwapper.READY_FILE)));
    }

    @Test
    public void restoresPreviousVersionWhenStagedFolderIsMissing() throws Exception {
        ExtensionSwapper.deleteRecursively(staging.resolve("plugin-ghidra"));

        assertThrows(IOException.class, () -> ExtensionSwapper.swap(installed, staging));

        assertEquals("old", Files.readString(installed.resolve("extension.properties")));
    }
}

package ai.reveng.toolkit.ghidra.core.services.update;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/** Unit tests for the file handling in {@link UpdateInstaller}. */
public class UpdateInstallerTest {
    @Rule
    public TemporaryFolder temp = new TemporaryFolder();

    private Path zip(String... namesAndContents) throws IOException {
        var zip = temp.newFile("release.zip").toPath();
        try (var out = new ZipOutputStream(Files.newOutputStream(zip))) {
            for (int i = 0; i < namesAndContents.length; i += 2) {
                out.putNextEntry(new ZipEntry(namesAndContents[i]));
                out.write(namesAndContents[i + 1].getBytes(StandardCharsets.UTF_8));
                out.closeEntry();
            }
        }
        return zip;
    }

    @Test
    public void extractsReleaseZip() throws IOException {
        var zip = zip("plugin-ghidra/extension.properties", "name=plugin-ghidra",
                "plugin-ghidra/lib/plugin-ghidra.jar", "jar");
        var staging = temp.newFolder("staging").toPath();

        UpdateInstaller.extract(zip, staging);

        assertEquals("name=plugin-ghidra", Files.readString(staging.resolve("plugin-ghidra/extension.properties")));
        assertEquals("jar", Files.readString(staging.resolve("plugin-ghidra/lib/plugin-ghidra.jar")));
    }

    @Test
    public void rejectsEntriesOutsideTheExtension() throws IOException {
        var zip = zip("plugin-ghidra/../../escaped.txt", "x");
        var staging = temp.newFolder("staging").toPath();

        assertThrows(IOException.class, () -> UpdateInstaller.extract(zip, staging));
        assertFalse(Files.exists(staging.getParent().resolve("escaped.txt")));
    }

    @Test
    public void rejectsZipWithoutPluginJar() throws IOException {
        var zip = zip("plugin-ghidra/extension.properties", "name=plugin-ghidra");
        assertThrows(IOException.class, () -> UpdateInstaller.extract(zip, temp.newFolder("staging").toPath()));
    }

    @Test
    public void verifiesChecksum() throws Exception {
        var file = temp.newFile("download.zip").toPath();
        Files.writeString(file, "release");
        var sha256 = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest("release".getBytes(StandardCharsets.UTF_8)));

        UpdateInstaller.verifySha256(file, sha256);
        UpdateInstaller.verifySha256(file, sha256.toUpperCase());
        assertThrows(IOException.class, () -> UpdateInstaller.verifySha256(file, "0".repeat(64)));
        assertThrows(IOException.class, () -> UpdateInstaller.verifySha256(file, null));
    }

    @Test
    public void readsStagedVersion() throws IOException {
        var staging = temp.newFolder("staging").toPath();
        assertTrue(UpdateInstaller.stagedVersion(staging).isEmpty());
        Files.writeString(staging.resolve(ExtensionSwapper.READY_FILE), "v1.3.0\n");
        assertEquals("v1.3.0", UpdateInstaller.stagedVersion(staging).orElseThrow());
    }
}

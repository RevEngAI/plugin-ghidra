package ai.reveng.toolkit.ghidra.core.services.update;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** Unit tests for the pure parts of {@link UpdateChecker}. */
public class UpdateCheckerTest {

    private static final String RELEASE = """
            {"tag_name": "v1.2.0",
             "html_url": "https://github.com/RevEngAI/plugin-ghidra/releases/tag/v1.2.0",
             "assets": [
               {"name": "ghidra_12.1.3_plugin-ghidra.zip", "browser_download_url": "https://example/12.1.3.zip"},
               {"name": "ghidra_12.2_plugin-ghidra.zip", "browser_download_url": "https://example/12.2.zip"}
             ]}
            """;

    @Test
    public void comparesSemanticVersions() {
        assertTrue(UpdateChecker.isNewer("v1.2.0", "v1.1.9"));
        assertTrue(UpdateChecker.isNewer("v2.0.0", "v1.10.10"));
        assertTrue(UpdateChecker.isNewer("v1.10.0", "v1.9.0"));
        assertFalse(UpdateChecker.isNewer("v1.1.0", "v1.1.0"));
        assertFalse(UpdateChecker.isNewer("v1.0.9", "v1.1.0"));
    }

    @Test
    public void unparseableVersionsAreNeverNewer() {
        assertFalse(UpdateChecker.isNewer("v1.2.0", UpdateChecker.UNKNOWN_VERSION));
        assertFalse(UpdateChecker.isNewer("latest", "v1.0.0"));
        assertFalse(UpdateChecker.isNewer("v1.2", "v1.0.0"));
    }

    @Test
    public void findsAssetForGhidraVersion() {
        var update = UpdateChecker.findUpdate("v1.1.0", "12.2", RELEASE).orElseThrow();
        assertEquals("v1.2.0", update.version());
        assertEquals("https://github.com/RevEngAI/plugin-ghidra/releases/tag/v1.2.0", update.releaseUrl());
        assertEquals("https://example/12.2.zip", update.downloadUrl());
    }

    @Test
    public void noUpdateWhenCurrent() {
        assertTrue(UpdateChecker.findUpdate("v1.2.0", "12.2", RELEASE).isEmpty());
    }

    @Test
    public void noUpdateWithoutAssetForGhidraVersion() {
        assertTrue(UpdateChecker.findUpdate("v1.1.0", "11.4", RELEASE).isEmpty());
    }

    @Test
    public void noUpdateOnMalformedJson() {
        assertTrue(UpdateChecker.findUpdate("v1.1.0", "12.2", "not json").isEmpty());
        assertTrue(UpdateChecker.findUpdate("v1.1.0", "12.2", "{}").isEmpty());
    }
}

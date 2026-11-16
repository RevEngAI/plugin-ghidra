package ai.reveng.toolkit.ghidra.core.ui;

import ghidra.framework.OperatingSystem;
import org.junit.Test;

import java.net.URI;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * Guards that URLs open with the OS's own launcher, not Ghidra's manual-viewer setting, whose 12.2
 * macOS default ({@code anaconda-navigator}) is usually missing (ENG-4233).
 */
public class WebBrowserTest {

    private static final URI URL = URI.create("https://portal.reveng.ai/analyses/1229816");

    @Test
    public void macUsesOpen() {
        assertEquals(List.of("open", URL.toString()), WebBrowser.command(OperatingSystem.MAC_OS_X, URL));
    }

    @Test
    public void linuxUsesXdgOpen() {
        assertEquals(List.of("xdg-open", URL.toString()), WebBrowser.command(OperatingSystem.LINUX, URL));
    }

    @Test
    public void windowsUsesUrlProtocolHandler() {
        assertEquals(List.of("rundll32", "url.dll,FileProtocolHandler", URL.toString()),
                WebBrowser.command(OperatingSystem.WINDOWS, URL));
    }
}

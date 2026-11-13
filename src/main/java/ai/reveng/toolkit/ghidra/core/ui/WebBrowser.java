package ai.reveng.toolkit.ghidra.core.ui;

import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.Msg;

import java.io.IOException;
import java.net.URI;
import java.util.List;

/// Opens URLs in the user's default browser via the OS launcher. Ghidra's BrowserLoader goes through
/// the manual-viewer option, whose macOS default in 12.2 is `anaconda-navigator`; java.awt.Desktop
/// frequently no-ops or is reported unsupported inside Ghidra's JVM.
public final class WebBrowser {

    private WebBrowser() {
    }

    public static void open(URI uri) {
        try {
            new ProcessBuilder(command(Platform.CURRENT_PLATFORM.getOperatingSystem(), uri)).start();
        } catch (IOException e) {
            Msg.showError(WebBrowser.class, null, "URI Opening Failed",
                    "Browsing to URI %s failed".formatted(uri), e);
        }
    }

    static List<String> command(OperatingSystem os, URI uri) {
        String url = uri.toString();
        return switch (os) {
            case MAC_OS_X -> List.of("open", url);
            case WINDOWS -> List.of("rundll32", "url.dll,FileProtocolHandler", url);
            default -> List.of("xdg-open", url);
        };
    }
}

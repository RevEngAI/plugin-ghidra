package ai.reveng;

import ai.reveng.toolkit.ghidra.plugins.ReaiAPIServicePlugin;
import ghidra.framework.plugintool.PluginTool;

import java.nio.file.Path;

/**
 * Subclass of {@link ReaiAPIServicePlugin} that overrides the config file path
 * and suppresses the setup wizard to allow testing without filesystem or UI dependencies.
 *
 * Uses a static field for the config path because Ghidra may call init() on a
 * different thread (e.g. Swing EDT) than the test thread.
 */
public class TestableReaiAPIServicePlugin extends ReaiAPIServicePlugin {

    private static volatile Path configPathOverride;

    public static void setConfigPathOverride(Path path) {
        configPathOverride = path;
    }

    public static void clearConfigPathOverride() {
        configPathOverride = null;
    }

    public TestableReaiAPIServicePlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected Path getConfigPath() {
        Path override = configPathOverride;
        if (override != null) {
            return override;
        }
        return super.getConfigPath();
    }

    @Override
    protected void runSetupWizard() {
        // No-op in tests
    }
}

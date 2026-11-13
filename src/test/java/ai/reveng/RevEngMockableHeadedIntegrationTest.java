package ai.reveng;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.plugins.LoggingPlugin;
import docking.DialogComponentProvider;
import generic.jar.ResourceFile;
import ghidra.GhidraTestApplicationLayout;
import utility.application.ApplicationLayout;
import ghidra.framework.GModule;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.mgr.ServiceManager;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.database.ProgramBuilder;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import org.junit.After;
import org.junit.Before;

import java.io.File;
import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertNotNull;

/// Base class
abstract class RevEngMockableHeadedIntegrationTest extends AbstractGhidraHeadedIntegrationTest {
    protected TestEnv env;

    /// Registers this project as a module so its data/*.theme.properties load, as for an installed extension.
    @Override
    protected ApplicationLayout createApplicationLayout() throws IOException {
        return new GhidraTestApplicationLayout(new File(getTestDirectoryPath())) {
            @Override
            protected Map<String, GModule> findGhidraModules() throws IOException {
                var modules = new HashMap<>(super.findGhidraModules());
                var root = new ResourceFile(new File("").getAbsoluteFile());
                modules.put(root.getName(), new GModule(applicationRootDirs, root));
                return modules;
            }
        };
    }

    @Before
    public void setup() throws IOException, PluginException {
        // For most tests we want to fail if a user visible error would show up.
        // Ghidra already has a nifty feature for that, we just need to activate it
        setErrorGUIEnabled(false);

        env = new TestEnv();
        env.addPlugin(LoggingPlugin.class);

    }

    @After
    public void tearDown() throws Exception {
        env.dispose();
    }

    /// An empty x86-64 program owned by this test, for tests that don't care what it is called.
    protected ProgramBuilder newX64Program() throws Exception {
        return newX64Program("mock");
    }

    /// An empty x86-64 program owned by this test, for tests whose program name is load bearing.
    protected ProgramBuilder newX64Program(String name) throws Exception {
        return new ProgramBuilder(name, ProgramBuilder._X64, this);
    }

    /// Polls for a dialog against this test's own deadline: the timeout that waitForDialogComponent takes is
    /// ignored in favour of Ghidra's 2s default, which a slow CI runner can exceed while a task is still running
    protected static <T extends DialogComponentProvider> T awaitDialog(Class<T> type) {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        T dialog;
        while ((dialog = getDialogComponent(type)) == null && System.nanoTime() < deadline) {
            sleep(DEFAULT_WAIT_DELAY);
        }
        assertNotNull("timed out waiting for " + type.getSimpleName(), dialog);
        return dialog;
    }


    /// This method adds a provided mocked service to the tool
    /// This allows each test to provide its own mocked API responses
    /// I have not found an official way to add a service without a full plugin, so we get the {@link ServiceManager}
    /// with reflection to add a service
    public static GhidraRevengService addMockedService(PluginTool tool, TypedApiInterface api) {
        ServiceManager serviceManager = (ServiceManager) getInstanceField("serviceMgr", tool);
        var reService = new GhidraRevengService(api);
        serviceManager.addService(GhidraRevengService.class, reService);
        return reService;
    }
}

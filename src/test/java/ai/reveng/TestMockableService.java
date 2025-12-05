package ai.reveng;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import org.junit.Test;


import java.nio.file.Path;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class TestMockableService extends RevEngMockableHeadedIntegrationTest {

    /// Basic test and demo for mocking the API
    @Test
    public void test() {
        var addedService = addMockedService(env.getTool(), new UnimplementedAPI() {
            public BinaryHash upload(Path path) {
                return new BinaryHash("mockhash");
            }
        });

        var returnedService = env.getTool().getService(GhidraRevengService.class);
        assertNotNull(returnedService);
        assertEquals(addedService, returnedService);
        assertEquals("mockhash", returnedService.upload(Path.of("anyfile")).sha256());
    }
}

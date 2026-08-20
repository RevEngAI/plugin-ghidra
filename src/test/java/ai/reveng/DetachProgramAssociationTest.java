package ai.reveng;

import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class DetachProgramAssociationTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void testDetachWithoutMarkedFunctions() throws Exception {
        var service = addMockedService(env.getTool(), new UnimplementedAPI());
        var builder = newX64Program("detach-test");
        var program = builder.getProgram();
        service.registerAnalysisForProgram(program, new TypedApiInterface.AnalysisID(1));
        assertTrue("the program should be associated before detaching",
                service.getKnownProgram(program).isPresent());

        program.withTransaction("Undo binary association", () -> service.removeProgramAssociation(program));

        assertTrue("detaching should clear the association even with no marked functions",
                service.getKnownProgram(program).isEmpty());
    }
}

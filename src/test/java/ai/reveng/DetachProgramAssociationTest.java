package ai.reveng;

import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ghidra.program.database.ProgramBuilder;
import org.junit.Test;

public class DetachProgramAssociationTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void testDetachWithoutMarkedFunctions() throws Exception {
        var service = addMockedService(env.getTool(), new UnimplementedAPI());
        var builder = new ProgramBuilder("detach-test", ProgramBuilder._X64, this);
        var program = builder.getProgram();

        program.withTransaction("Undo binary association", () -> service.removeProgramAssociation(program));
    }
}

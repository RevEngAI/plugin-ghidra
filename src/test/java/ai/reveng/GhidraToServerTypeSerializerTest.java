package ai.reveng;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraToServerTypeSerializer;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Integration test for {@link GhidraToServerTypeSerializer}: verifies a Ghidra function's signature,
 * variables, and referenced custom types are serialised into the server's data-type blob for
 * push-back (PLU-322).
 */
public class GhidraToServerTypeSerializerTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void serialisesSignatureVariablesAndStructDependency() throws Exception {
        var builder = new ProgramBuilder("mock", ProgramBuilder._X64, this);
        builder.createMemory("mem", "0x4000", 0x100);
        var program = builder.getProgram();

        var intType = IntegerDataType.dataType;
        var charType = CharDataType.dataType;

        var struct = new StructureDataType("MyStruct", 0);
        struct.add(intType, "field0", null);
        builder.addDataType(struct);

        Parameter count = new ParameterImpl("count", intType, program);
        Parameter buffer = new ParameterImpl("buffer", new PointerDataType(struct), program);
        Function function = builder.createEmptyFunction("process_input", "0x4000", 0x40, intType, count, buffer);

        int txId = program.startTransaction("add local");
        function.addLocalVariable(new LocalVariableImpl("tmp", charType, -0x8, program), SourceType.USER_DEFINED);
        program.endTransaction(txId, true);

        long imageBase = program.getImageBase().getOffset();
        var info = GhidraToServerTypeSerializer.buildFunctionInfo(function, imageBase);

        var funcTypes = info.getFuncTypes();
        assertEquals("process_input", funcTypes.getName());
        assertEquals("Function", funcTypes.getArtifactType());
        assertEquals("addr is relative to the image base",
                function.getEntryPoint().getOffset() - imageBase, funcTypes.getAddr().longValue());

        var header = funcTypes.getHeader();
        assertEquals("int", header.getType());
        assertEquals(2, header.getArgs().size());
        assertEquals("count", header.getArgs().get("0").getName());
        assertEquals("int", header.getArgs().get("0").getType());
        assertEquals("buffer", header.getArgs().get("1").getName());

        assertTrue("stack variable is serialised",
                funcTypes.getStackVars().values().stream().anyMatch(v -> v.getName().equals("tmp")));

        assertTrue("referenced struct is emitted as a dependency",
                info.getFuncDeps().stream()
                        .anyMatch(dep -> dep.getName().equals("MyStruct") && "Struct".equals(dep.getArtifactType())));
    }
}

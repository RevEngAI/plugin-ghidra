package ai.reveng;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.FunctionDependencies;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.Struct;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.StructMember;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.Typedef;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Regression test for {@link GhidraRevengService#loadDependencyDataTypes}: a struct member reported
 * beyond the struct's declared size must not abort the whole type load (the crash seen when the
 * agent's decompile tool result triggered a function-info pull).
 */
public class DependencyDataTypeLoadingTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void growsStructToFitMemberBeyondDeclaredSize() throws Exception {
        // Declared size 32, but a member sits at offset 32 (== size) — replaceAtOffset would reject it.
        var head = new StructMember(null, "head", 0, "int_type_missing", 4);
        var tail = new StructMember(null, "tail", 32, "ptr_type_missing", 8);
        var struct = new Struct(null, "OversizedStruct", 32, new StructMember[]{head, tail});
        var deps = new FunctionDependencies(new Typedef[0], new Struct[]{struct});

        DataTypeManager dtm = GhidraRevengService.loadDependencyDataTypes(deps);

        Structure loaded = (Structure) dtm.getDataType("/OversizedStruct");
        assertTrue("struct should have grown to fit the trailing member, length was " + loaded.getLength(),
                loaded.getLength() >= 40);
        assertEquals("tail", loaded.getComponentAt(32).getFieldName());
        assertEquals("head", loaded.getComponentAt(0).getFieldName());
    }
}

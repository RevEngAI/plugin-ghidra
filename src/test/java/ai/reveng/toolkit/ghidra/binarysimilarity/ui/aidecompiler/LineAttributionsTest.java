package ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler;

import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class LineAttributionsTest {

    private static final List<String> ASSEMBLY = List.of(
            "0x401000\tPUSH RBP",
            "0x401001\tMOV RBP,RSP",
            "0x401004\tMOV EAX,0x1",
            "0x401009\tPOP RBP",
            "0x40100a\tRET");

    @Test
    public void disassemblyLinesAreOneRowBehindTheAssembly() {
        var attributions = LineAttributions.of(Map.of("0", List.of(2L)), ASSEMBLY);

        assertEquals(List.of(0x401001L), attributions.addressesFor(2));
        assertEquals(List.of(2), attributions.decompilationLinesFor(0x401001L));
        assertEquals(List.of(), attributions.decompilationLinesFor(0x401000L));
    }

    @Test
    public void manyToManyInBothDirections() {
        var attributions = LineAttributions.of(Map.of(
                "1", List.of(3L, 4L),
                "2", List.of(4L)), ASSEMBLY);

        assertEquals(List.of(0x401004L, 0x401009L), attributions.addressesFor(4));
        assertEquals(List.of(0x401004L), attributions.addressesFor(3));
        assertEquals(List.of(3, 4), attributions.decompilationLinesFor(0x401004L));
    }

    @Test
    public void unresolvableEntriesAreSkipped() {
        var raw = new HashMap<String, List<Long>>();
        raw.put("x", List.of(1L));
        raw.put("4", List.of(1L));      // row 5, past the end
        raw.put("-2", List.of(1L));     // row -1
        raw.put("3", null);
        var attributions = LineAttributions.of(raw, ASSEMBLY);

        assertTrue(attributions.isEmpty());
    }

    @Test
    public void assemblyWithoutAnAddressContributesNothing() {
        var attributions = LineAttributions.of(Map.of("0", List.of(1L)), List.of("PUSH RBP", "MOV RBP,RSP"));

        assertTrue(attributions.isEmpty());
    }

    @Test
    public void addressesPastLongMaxParse() {
        assertEquals(Long.valueOf(0xffffffff80001000L), LineAttributions.parseAddress("0xffffffff80001000\tNOP"));
        assertEquals(Long.valueOf(0x140001000L), LineAttributions.parseAddress("0x140001000 PUSH RBP"));
        assertNull(LineAttributions.parseAddress("label:"));
    }
}

package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.JSON;
import ai.reveng.model.DisassemblyOutputBody;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * Covers {@link DisassemblyBlocksReader}, which pulls the assembly out of the untyped
 * {@code basic_blocks} value of {@code GET /v3/functions/{function_id}/blocks}.
 *
 * <p>Each case is driven through the generated {@link DisassemblyOutputBody} rather than a
 * hand-built {@code Object}, so the deserialisation the SDK actually performs — including the
 * required {@code function_id} and {@code returns} fields, and Gson's untyped handling of
 * {@code basic_blocks} — is exercised alongside the reader.
 */
public class DisassemblyBlocksReaderTest {

    private static List<String> read(String json) {
        DisassemblyOutputBody body = JSON.getGson().fromJson(json, DisassemblyOutputBody.class);
        return DisassemblyBlocksReader.readAssembly(body.getBasicBlocks());
    }

    /// A block as v3 sends it: `{min_addr, max_addr, destinations, asm}`. Assembly lines carry the
    /// address and the instruction separated by a tab, and a destination's `vaddr` is a number.
    private static String block(long minAddr, long maxAddr, long destination, String... asm) {
        return """
                {
                  "min_addr": %d,
                  "max_addr": %d,
                  "destinations": [{"vaddr": %d, "flowtype": "UNCONDITIONAL_JUMP"}],
                  "asm": [%s]
                }""".formatted(minAddr, maxAddr, destination,
                String.join(", ", List.of(asm).stream().map(l -> '"' + l + '"').toList()));
    }

    /// The surrounding body, carrying the fields the spec marks required plus the sibling blobs v3
    /// added; passing null omits `basic_blocks` entirely, as v3 does for a function without one.
    private static String body(String basicBlocks) {
        return """
                {
                  "function_id": 1109480836,
                  "returns": true,
                  "return_type": "int",
                  "params": [],
                  "local_variables": [],
                  "global_variables": []%s
                }""".formatted(basicBlocks == null ? ""
                        : ",\n  \"basic_blocks\": [%s]".formatted(basicBlocks));
    }

    @Test
    public void blocksAreConcatenatedInAddressOrder() {
        // Deliberately out of order, and at load addresses past Integer.MAX_VALUE — the generated v2
        // block model narrows these to int, which is why the reader parses them itself.
        String json = body(String.join(",\n",
                block(0x140001010L, 0x140001018L, 0x140001020L,
                        "0x140001010\\tADD RSP,0x20", "0x140001014\\tRET"),
                block(0x140001000L, 0x140001010L, 0x140001010L,
                        "0x140001000\\tPUSH RBP", "0x140001001\\tMOV RBP,RSP")));

        assertEquals(List.of(
                        "0x140001000\tPUSH RBP", "0x140001001\tMOV RBP,RSP",
                        "0x140001010\tADD RSP,0x20", "0x140001014\tRET"),
                read(json));
    }

    @Test
    public void aBodyWithoutBlocksReadsAsNoAssembly() {
        // How v3 reports a function that carries no stored disassembly: 200, block fields absent.
        assertEquals(List.of(), read(body(null)));
    }

    @Test
    public void anEmptyBlockListReadsAsNoAssembly() {
        assertEquals(List.of(), read(body("")));
    }

    @Test
    public void blocksWithoutAssemblyContributeNothing() {
        String json = body(String.join(",\n",
                "{\"min_addr\": 4096, \"max_addr\": 4100, \"destinations\": []}",
                block(0x1010L, 0x1018L, 0x1020L, "0x1010\\tRET")));

        assertEquals(List.of("0x1010\tRET"), read(json));
    }

    @Test
    public void blocksWithoutAStartAddressSortLast() {
        String json = body(String.join(",\n",
                "{\"asm\": [\"NOP\"]}",
                block(0x1000L, 0x1004L, 0x1010L, "0x1000\\tPUSH RBP")));

        assertEquals(List.of("0x1000\tPUSH RBP", "NOP"), read(json));
    }

    /// A block carrying fields the reader does not use must not derail the blocks around it.
    @Test
    public void legacyBlockFieldsAreIgnored() {
        String json = body("""
                {
                  "id": 0,
                  "min_addr": 4096,
                  "max_addr": 4100,
                  "comment": null,
                  "destinations": [{"vaddr": "4128", "flowtype": "FALL_THROUGH", "destination_block_id": 1}],
                  "asm": ["0x1000\\tPUSH RBP"]
                }""");

        assertEquals(List.of("0x1000\tPUSH RBP"), read(json));
    }
}

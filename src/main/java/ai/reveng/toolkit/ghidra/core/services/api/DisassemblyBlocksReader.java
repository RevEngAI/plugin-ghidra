package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.JSON;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/// Reads the assembly out of the `basic_blocks` value of `GET /v3/functions/{function_id}/blocks`.
///
/// The v3 body leaves `basic_blocks` untyped, so the generated
/// {@link ai.reveng.model.DisassemblyOutputBody} hands it over as a bare {@link Object}. It is the
/// stored disassembly blob passed through verbatim, an array of `{min_addr, max_addr, destinations,
/// asm}`. Unknown keys are ignored, so a block carrying more than that is read the same way.
///
/// The generated v2 block model is deliberately not reused to read this. It requires an `id` field
/// that v3 does not send, and it narrows the addresses to `int`, which overflows on the load addresses
/// of 64-bit images. Only `min_addr` and `asm` are read here; the plugin has no use for the control
/// flow edges.
///
/// Nothing here throws on a shape it does not recognise. A block with no assembly contributes no
/// lines, and a body carrying no blocks at all yields an empty list — which is how v3 reports a
/// function that has no stored disassembly, where v2 answered 404.
public final class DisassemblyBlocksReader {

    private DisassemblyBlocksReader() {
    }

    /// Flattens the blocks into the function's assembly, ordered by the address each block starts at.
    public static List<String> readAssembly(Object basicBlocks) {
        if (basicBlocks == null) {
            return List.of();
        }
        JsonElement blocks = JSON.getGson().toJsonTree(basicBlocks);
        if (!blocks.isJsonArray()) {
            return List.of();
        }

        List<JsonObject> ordered = new ArrayList<>();
        for (JsonElement block : blocks.getAsJsonArray()) {
            if (block.isJsonObject()) {
                ordered.add(block.getAsJsonObject());
            }
        }
        ordered.sort(Comparator.comparingLong(DisassemblyBlocksReader::startAddress));

        List<String> assembly = new ArrayList<>();
        for (JsonObject block : ordered) {
            appendAssembly(assembly, block);
        }
        return assembly;
    }

    /// Blocks that declare no start address sort last, so the ones that do keep their address order.
    private static long startAddress(JsonObject block) {
        JsonElement minAddr = block.get("min_addr");
        if (minAddr == null || !minAddr.isJsonPrimitive() || !minAddr.getAsJsonPrimitive().isNumber()) {
            return Long.MAX_VALUE;
        }
        return minAddr.getAsLong();
    }

    private static void appendAssembly(List<String> assembly, JsonObject block) {
        JsonElement asm = block.get("asm");
        if (asm == null || !asm.isJsonArray()) {
            return;
        }
        for (JsonElement line : asm.getAsJsonArray()) {
            if (line.isJsonPrimitive()) {
                assembly.add(line.getAsString());
            }
        }
    }
}

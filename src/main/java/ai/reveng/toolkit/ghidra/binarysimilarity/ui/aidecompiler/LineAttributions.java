package ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/// Which instructions fed which AI decompilation lines, as read from
/// `GET /v3/functions/{function_id}/ai-decompilation/line-attributions`.
///
/// The endpoint numbers both sides by line, 0-based, many-to-many in both directions. Disassembly
/// lines are resolved here to instruction addresses, so the listing can be lit without knowing how
/// the portal laid the assembly out.
///
/// Mirrors the portal: the model numbered the sequencer trace, which runs one line ahead of the
/// blocks' assembly, so disassembly line `n` is assembly line `n + 1`.
public final class LineAttributions {

    static final int DISASSEMBLY_ROW_OFFSET = 1;

    public static final LineAttributions EMPTY = new LineAttributions(Map.of(), Map.of());

    private final Map<Integer, List<Long>> addressesByDecompilationLine;
    private final Map<Long, List<Integer>> decompilationLinesByAddress;

    private LineAttributions(Map<Integer, List<Long>> addressesByDecompilationLine,
                             Map<Long, List<Integer>> decompilationLinesByAddress) {
        this.addressesByDecompilationLine = addressesByDecompilationLine;
        this.decompilationLinesByAddress = decompilationLinesByAddress;
    }

    /// @param disassemblyToDecompilation the endpoint's map, keyed by disassembly line
    /// @param assembly the function's assembly, each line led by its address (`0x401000\tPUSH RBP`)
    public static LineAttributions of(Map<String, List<Long>> disassemblyToDecompilation, List<String> assembly) {
        if (disassemblyToDecompilation == null || assembly == null) {
            return EMPTY;
        }
        var byDecompilationLine = new TreeMap<Integer, TreeSet<Long>>();
        var byAddress = new TreeMap<Long, TreeSet<Integer>>();
        disassemblyToDecompilation.forEach((rawLine, decompilationLines) -> {
            Long address = addressOfRow(assembly, parseLine(rawLine));
            if (address == null || decompilationLines == null) {
                return;
            }
            for (Long decompilationLine : decompilationLines) {
                if (decompilationLine == null) {
                    continue;
                }
                int line = decompilationLine.intValue();
                byDecompilationLine.computeIfAbsent(line, k -> new TreeSet<>()).add(address);
                byAddress.computeIfAbsent(address, k -> new TreeSet<>()).add(line);
            }
        });
        var addresses = new TreeMap<Integer, List<Long>>();
        byDecompilationLine.forEach((line, set) -> addresses.put(line, List.copyOf(set)));
        var lines = new TreeMap<Long, List<Integer>>();
        byAddress.forEach((address, set) -> lines.put(address, List.copyOf(set)));
        return new LineAttributions(addresses, lines);
    }

    /// Addresses of the instructions that fed the 0-based decompilation line, ascending.
    public List<Long> addressesFor(int decompilationLine) {
        return addressesByDecompilationLine.getOrDefault(decompilationLine, List.of());
    }

    /// 0-based decompilation lines the instruction at {@code address} fed, ascending.
    public List<Integer> decompilationLinesFor(long address) {
        return decompilationLinesByAddress.getOrDefault(address, List.of());
    }

    public boolean isEmpty() {
        return addressesByDecompilationLine.isEmpty();
    }

    private static Integer parseLine(String rawLine) {
        try {
            return Integer.parseInt(rawLine);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Long addressOfRow(List<String> assembly, Integer disassemblyLine) {
        if (disassemblyLine == null) {
            return null;
        }
        int row = disassemblyLine + DISASSEMBLY_ROW_OFFSET;
        if (row < 0 || row >= assembly.size()) {
            return null;
        }
        return parseAddress(assembly.get(row));
    }

    static Long parseAddress(String assemblyLine) {
        if (assemblyLine == null) {
            return null;
        }
        String head = assemblyLine.strip().split("\\s+", 2)[0];
        if (!head.startsWith("0x") && !head.startsWith("0X")) {
            return null;
        }
        try {
            return Long.parseUnsignedLong(head.substring(2), 16);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}

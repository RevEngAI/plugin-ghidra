package ai.reveng.toolkit.ghidra.core.services.api;

import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Program;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Optional;

/// The file a program was imported from.
///
/// Ghidra records the importer's path, which is missing on other machines (e.g. in a shared project),
/// but its loaders also store the file's bytes in the program, which travel with it.
public final class OriginalBinary {
    private static final int CHUNK = 1 << 20;

    private OriginalBinary() {
    }

    public static Path importPath(Program program) {
        try {
            return Path.of(program.getExecutablePath());
        } catch (InvalidPathException e) {
            // On Windows the path looks like "/C:/vfcompat.dll"
            return Path.of(program.getExecutablePath().substring(1));
        }
    }

    /// Size of the original file, from the stored bytes if present, else from disk.
    public static long size(Program program) throws IOException {
        FileBytes stored = stored(program);
        return stored != null ? stored.getSize() : Files.size(importPath(program));
    }

    /// Writes the stored bytes to a new temporary directory, under the original file name.
    /// Empty if none are stored or they don't hash to the program's SHA-256.
    public static Optional<Path> extract(Program program) throws IOException {
        FileBytes stored = stored(program);
        if (stored == null) {
            return Optional.empty();
        }
        Path name = importPath(program).getFileName();
        Path file = Files.createTempDirectory("reai-upload").resolve(name != null ? name.toString() : program.getName());
        MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        byte[] buffer = new byte[CHUNK];
        try (OutputStream out = Files.newOutputStream(file)) {
            for (long offset = 0; offset < stored.getSize(); ) {
                int read = stored.getOriginalBytes(offset, buffer, 0, (int) Math.min(CHUNK, stored.getSize() - offset));
                out.write(buffer, 0, read);
                sha256.update(buffer, 0, read);
                offset += read;
            }
        }
        if (!HexFormat.of().formatHex(sha256.digest()).equalsIgnoreCase(program.getExecutableSHA256())) {
            delete(file);
            return Optional.empty();
        }
        return Optional.of(file);
    }

    /// Deletes a file returned by {@link #extract} and its directory.
    public static void delete(Path extracted) throws IOException {
        Files.deleteIfExists(extracted);
        Files.deleteIfExists(extracted.getParent());
    }

    public static String notFoundMessage(Path path) {
        return "Original binary not found at %s and not stored in the program. Copy it to that path or re-import it."
                .formatted(path);
    }

    private static @Nullable FileBytes stored(Program program) {
        var all = program.getMemory().getAllFileBytes();
        return all.isEmpty() ? null : all.getFirst();
    }
}

package ai.reveng.toolkit.ghidra.core.services.api.mocks;

import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.ModelName;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class UnimplementedAPI implements TypedApiInterface {
    protected AnalysisStatus getNextStatus(AnalysisStatus previousStatus) {
        Objects.requireNonNull(previousStatus);
        return switch (previousStatus) {
            case Queued -> AnalysisStatus.Processing;
            case Processing -> AnalysisStatus.Complete;
            case Complete ->  AnalysisStatus.Complete;
            case Error -> AnalysisStatus.Error;
        };
    }

    @Override
    public String getAnalysisLogs(AnalysisID analysisID) {
        return "ANALYSIS LOGS";
    }

    @Override
    public void authenticate() {

    }

    @Override
    public void renameFunction(FunctionID id, String newName) {

    }

    @Override
    public BinaryHash upload(Path binPath) {
        // Calculate the SHA256 hash of the binary at the path
        try {
            byte[] b = Files.readAllBytes(binPath);
            byte[] hash = MessageDigest.getInstance("SHA256").digest(b);
            return new BinaryHash(HexFormat.of().formatHex(hash));

        } catch (IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }
}

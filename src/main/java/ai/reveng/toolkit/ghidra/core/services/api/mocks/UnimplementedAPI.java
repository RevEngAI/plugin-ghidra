package ai.reveng.toolkit.ghidra.core.services.api.mocks;

import ai.reveng.invoker.ApiException;
import ai.reveng.model.CreateAnalysisDataTypesInputBody;
import ai.reveng.model.UpdateAnalysisDataTypesInputBody;
import ai.reveng.model.UpdateFunctionSignatureInputBody;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.FunctionSignatureBatch;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

public class UnimplementedAPI implements TypedApiInterface {
    protected AnalysisStatus getNextStatus(AnalysisStatus previousStatus) {
        Objects.requireNonNull(previousStatus);
        return switch (previousStatus) {
            case Uploaded -> AnalysisStatus.Queued;
            case Queued -> AnalysisStatus.Processing;
            case Processing -> AnalysisStatus.Complete;
            case Complete ->  AnalysisStatus.Complete;
            case Error -> AnalysisStatus.Error;
            case Unknown -> AnalysisStatus.Unknown;
        };
    }

    @Override
    public String getAnalysisLogs(AnalysisID analysisID) {
        return "ANALYSIS LOGS";
    }

    @Override
    public void renameFunction(FunctionID id, String newName, String newNameMangled) {

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

    /// This gets called when registering the initial mock analysis
    /// it just pretends that there is no type info available
    @Override
    public FunctionSignatureBatch listFunctionSignatures(List<FunctionID> functionIDs, boolean includeDataTypes) {
        return FunctionSignatureBatch.empty();
    }

    /// The write path is answered rather than refused, so a test exercising a push does not have to
    /// stub all three endpoints just to get past them. An empty catalogue that accepts everything and
    /// remembers nothing: the analysis has no types, creating some reports none back, and a signature
    /// write succeeds silently. Tests that care about what was written override these.
    @Override
    public List<ServerDataType> listAnalysisDataTypes(AnalysisID analysisID, long offset, long limit) {
        return List.of();
    }

    @Override
    public List<ServerDataType> createAnalysisDataTypes(AnalysisID analysisID,
                                                        CreateAnalysisDataTypesInputBody request) {
        return List.of();
    }

    @Override
    public List<ServerDataType> updateAnalysisDataTypes(AnalysisID analysisID,
                                                        UpdateAnalysisDataTypesInputBody request) {
        return List.of();
    }

    @Override
    public void updateFunctionSignature(AnalysisID analysisID, FunctionID functionID,
                                        UpdateFunctionSignatureInputBody signature) throws ApiException {
    }
}

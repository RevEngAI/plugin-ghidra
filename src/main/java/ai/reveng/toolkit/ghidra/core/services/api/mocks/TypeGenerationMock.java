package ai.reveng.toolkit.ghidra.core.services.api.mocks;

import ai.reveng.toolkit.ghidra.core.services.api.types.*;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class TypeGenerationMock extends UnimplementedAPI {

    Set<FunctionID> generatedFunctions = new HashSet<>();
    @Override
    public DataTypeList generateFunctionDataTypes(AnalysisID analysisID, List<FunctionID> functionIDS) {
        var statuses = functionIDS.stream()
                .map(id -> new FunctionDataTypeStatus(
                        false,
                        Optional.empty(),
                        "UNKNOWN",
                        null,
                        id
                ))
                .toList();
        return new DataTypeList(
                functionIDS.size(), 0, statuses.toArray(new FunctionDataTypeStatus[0])
        );
    }

    @Override
    public DataTypeList getFunctionDataTypes(List<FunctionID> functionIDS) {
        for (FunctionID functionID : functionIDS) {
            if (generatedFunctions.contains(functionID)) continue;
            generatedFunctions.add(functionID);
            break;
        }

        var statuses = functionIDS.stream()
                .map(id -> new FunctionDataTypeStatus(
                        generatedFunctions.contains(id),
                        Optional.empty(),
                        generatedFunctions.contains(id) ? "completed" : "UNKNOWN",
                        null,
                        id
                ))
                .toList();

        return new DataTypeList(
                functionIDS.size(), 0, statuses.toArray(new FunctionDataTypeStatus[0])
        );
    }

    @Override
    public FunctionDetails getFunctionDetails(FunctionID id) {
        return new FunctionDetails(
                id,
                "placeholder_for_%s".formatted(id),
                0L,
                10L,
                new AnalysisID(1337),
                new BinaryID(1337),
                "placeholder_for_%s".formatted(id),
                new BinaryHash("placeholder_for_%s".formatted(id)),
                "demangled_placeholder_for_%s".formatted(id)
        );
    }
}

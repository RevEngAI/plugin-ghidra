import ai.reveng.model.FunctionDataTypes;
import ai.reveng.model.FunctionInfoOutput;
import ai.reveng.toolkit.ghidra.binarysimilarity.cmds.ComputeTypeInfoTask;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.V2Response;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.Structure;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class ConvertBinSyncArtifactTests extends AbstractRevEngIntegrationTest {

    TypedApiInterface.AnalysisID analysisID = new TypedApiInterface.AnalysisID(1337);


    @Test
    public void testSimpleGhidraSignatureGeneration() throws DataTypeDependencyException, IOException {
        V2Response mockResponse = getMockResponseFromFile("main_fdupes_77846709.json");

//        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        var funcInfo = FunctionDataTypes.fromJson(mockResponse.getJsonData().toString());
        var signature = GhidraRevengService.getFunctionSignature(funcInfo.getDataTypes()).orElseThrow();

        assert signature.getName().equals("main");
        assert signature.getReturnType().getName().equals("int");
        assert signature.getArguments().length == 2;

        assert signature.getArguments()[0].getName().equals("argc");
        assert signature.getArguments()[0].getDataType().getName().equals("int");

        assert signature.getArguments()[1].getName().equals("argv");
        assert signature.getArguments()[1].getDataType().getName().equals("char * *");
    }




    @Test
    public void testDependencyToDtm() {
        var mockResponse = getMockResponseFromFile("confirmmatch_fdupes_77846700.json");
        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        var dtm = GhidraRevengService.loadDependencyDataTypes(functionDataTypeStatus.data_types().get().func_deps());


        // Print all datatypes for debugging
        for (Iterator<DataType> it = dtm.getAllDataTypes(); it.hasNext(); ) {
            var ty = it.next();
            Msg.info(this, ty.getCategoryPath());
            Msg.info(this, ty.getName());
        }
        // There should be a typedef FILE in the folder DWARF/stdio.h/ for
        var fileType = dtm.getDataType(new  CategoryPath(CategoryPath.ROOT, "DWARF", "stdio.h"), "FILE");
        List<DataType> results = new ArrayList();
        dtm.findDataTypes("FILE", results);
        assert fileType != null;

    }

    @Test
    public void testComplexGhidraSignatureGeneration() throws DataTypeDependencyException, IOException {
        var mockResponse = getMockResponseFromFile("confirmmatch_fdupes_77846700.json");

        var funcInfo = FunctionInfoOutput.fromJson(mockResponse.getJsonData().toString());
        var signature = GhidraRevengService.getFunctionSignature(funcInfo).orElseThrow();

        assert signature.getName().equals("confirmmatch");
        Msg.info(this, signature);
    }


    @Test
    public void testComplexGhidraSignatureGeneration2() throws DataTypeDependencyException, IOException {
        var mockResponse = getMockResponseFromFile("summarizematches_fdupes.json");

        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        var funcInfo = FunctionInfoOutput.fromJson(mockResponse.getJsonData().toString());
        var signature = GhidraRevengService.getFunctionSignature(funcInfo).orElseThrow();

        assert signature.getName().equals("summarizematches");
        Msg.info(this, signature);
    }

    @Test
    public void testComplexGhidraSignatureGeneration3() throws DataTypeDependencyException, IOException {
        var mockResponse = getMockResponseFromFile("md5_process_fdupes.json");

        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        var funcInfo = FunctionInfoOutput.fromJson(mockResponse.getJsonData().toString());
        var signature = GhidraRevengService.getFunctionSignature(funcInfo).orElseThrow();

        var dtm = signature.getDataTypeManager();
        assert signature.getName().equals("md5_process");

        Structure stateType = (Structure) dtm.getDataType("/DWARF/md5.h/md5_state_s");
        assert stateType.getLength() == 88;
        assert stateType.getNumComponents() == 3;

    }


    /**
     * This test is to ensure that the function signature generation does not loop infinitely
     */
    @Ignore("Ignored until it can properly distinguish an infinite loop and an exception")
    @Test
    public void testNoLoopForBrokenDeps() throws DataTypeDependencyException, IOException {
        var mockResponse = getMockResponseFromFile("errormsg.json");

        var funcInfo = FunctionInfoOutput.fromJson(mockResponse.getJsonData().toString());
        var signature = GhidraRevengService.getFunctionSignature(funcInfo).orElseThrow();

        assert signature.getName().equals("md5_process");
        Msg.info(this, signature);
    }

    /**
     * This function takes a function pointer as an argument
     * BinSync doesn't serialize them by default, and this specific example JSON is missing it
     * The function is `registerpair` from `fdupes`: <a href="https://portal.reveng.ai/function/77846706?tab=Disassembly">registerpair</a>
     */
    @Test
    public void testFunctionPointerArgument() throws DataTypeDependencyException, IOException {
        var mockResponse = getMockResponseFromFile("complex_pointer.json");
        var signature = GhidraRevengService.getFunctionSignature(
                FunctionInfoOutput.fromJson(mockResponse.getJsonData().toString())
        );
    }

    @Test
    public void testPendingStatus() {
        var mockResponse = getMockResponseFromFile("pending.json");
        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        assert !functionDataTypeStatus.completed();
        assert functionDataTypeStatus.data_types().isEmpty();
        assert functionDataTypeStatus.status().equals("pending");
    }

    @Test
    public void testBatchResponse() {
        var mockResponse = getMockResponseFromFile("data_types_batch_response.json");
        DataTypeList batchResponse = DataTypeList.fromJson(mockResponse.getJsonData());

        var r1 = batchResponse.statusForFunction(new TypedApiInterface.FunctionID(266294328));
        assert r1.data_types().orElseThrow().functionName().equals("sort_pairs_by_mtime");
    }

    @Test
    public void testDataTypeGenerationTask() throws CancelledException {
        var mockApi = new TypeGenerationMock();
        var task = new ComputeTypeInfoTask(
                new GhidraRevengService(mockApi),
                IntStream.range(0, 5).boxed().map(TypedApiInterface.FunctionID::new).collect(Collectors.toList()), null
                );
        task.run(TaskMonitor.DUMMY);

    }

    public static class TypeGenerationMock extends UnimplementedAPI {

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
                    "placeholder_for_%s".formatted(id),
                    new BinaryHash("placeholder_for_%s".formatted(id)),
                    "demangled_placeholder_for_%s".formatted(id)
            );
        }
    }
}

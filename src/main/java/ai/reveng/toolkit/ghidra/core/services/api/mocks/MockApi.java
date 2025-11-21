package ai.reveng.toolkit.ghidra.core.services.api.mocks;

import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.APIAuthenticationException;
import org.json.JSONObject;

import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@Deprecated
public class MockApi implements TypedApiInterface {
    @Override
    public BinaryHash upload(Path binPath) throws FileNotFoundException {
        return new BinaryHash("b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6");
    }

    @Override
    @Deprecated
    public List<LegacyAnalysisResult> search(BinaryHash hash) {
        if (hash.equals(new BinaryHash("b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6"))) {
            return List.of(new LegacyAnalysisResult(
                    new AnalysisID(1234),
                    new BinaryID(17920),
                    "true",
                    "no creation date",
                    1,
                    "model name",
                    hash,
                    AnalysisStatus.Complete,
                    123456,
                    "b48f61e85bcbc7866d78a8f0b72acd8c0c177ebd15cea466d1edb67409fca269"
            ));
        }
        return List.of();
    }

    @Override
    public AnalysisStatus status(BinaryID binID) {
        return AnalysisStatus.Complete;
    }

    @Override
    public String getAnalysisLogs(AnalysisID analysisID) {
        return "";
    }

    @Override
    public void authenticate() throws APIAuthenticationException {
    }

    @Override
    public void renameFunction(FunctionID id, String newName) {
        
    }

    @Override
    public List<FunctionInfo> getFunctionInfo(AnalysisID analysisID) {
        var r = """
                {
                  "success": true,
                  "functions": [
                    {
                      "function_id": 3524063,
                      "function_name_mangled": "_DT_INIT",
                      "function_vaddr": 4096,
                      "function_size": 26
                    },
                    {
                      "function_id": 3524064,
                      "function_name_mangled": "FUN_00001030",
                      "function_vaddr": 4144,
                      "function_size": 1403
                    },
                    {
                      "function_id": 3524065,
                      "function_name_mangled": "entry",
                      "function_vaddr": 5552,
                      "function_size": 37
                    },
                    {
                      "function_id": 3524066,
                      "function_name_mangled": "FUN_000015e0",
                      "function_vaddr": 5600,
                      "function_size": 32
                    },
                    {
                      "function_id": 3524067,
                      "function_name_mangled": "FUN_00001610",
                      "function_vaddr": 5648,
                      "function_size": 49
                    },
                    {
                      "function_id": 3524068,
                      "function_name_mangled": "_FINI_0",
                      "function_vaddr": 5712,
                      "function_size": 53
                    },
                    {
                      "function_id": 3524069,
                      "function_name_mangled": "FUN_000016b0",
                      "function_vaddr": 5808,
                      "function_size": 222
                    },
                    {
                      "function_id": 3524070,
                      "function_name_mangled": "FUN_000017b0",
                      "function_vaddr": 6064,
                      "function_size": 231
                    },
                    {
                      "function_id": 3524071,
                      "function_name_mangled": "FUN_000018a0",
                      "function_vaddr": 6304,
                      "function_size": 54
                    },
                    {
                      "function_id": 3524072,
                      "function_name_mangled": "FUN_000018e0",
                      "function_vaddr": 6368,
                      "function_size": 248
                    },
                    {
                      "function_id": 3524073,
                      "function_name_mangled": "FUN_00001a00",
                      "function_vaddr": 6656,
                      "function_size": 86
                    },
                    {
                      "function_id": 3524074,
                      "function_name_mangled": "FUN_00001a60",
                      "function_vaddr": 6752,
                      "function_size": 241
                    },
                    {
                      "function_id": 3524075,
                      "function_name_mangled": "FUN_00001b70",
                      "function_vaddr": 7024,
                      "function_size": 5613
                    },
                    {
                      "function_id": 3524076,
                      "function_name_mangled": "FUN_000031f0",
                      "function_vaddr": 12784,
                      "function_size": 118
                    },
                    {
                      "function_id": 3524077,
                      "function_name_mangled": "FUN_00003280",
                      "function_vaddr": 12928,
                      "function_size": 1497
                    },
                    {
                      "function_id": 3524078,
                      "function_name_mangled": "FUN_00003860",
                      "function_vaddr": 14432,
                      "function_size": 18
                    }
                  ]
                }
                """;
        var jsonObject = new JSONObject(r);
        var result = new ArrayList<FunctionInfo>();
        jsonObject.getJSONArray("functions").forEach((Object o) -> {
            result.add(FunctionInfo.fromJSONObject((JSONObject) o));
        });
        return result;
    }
}

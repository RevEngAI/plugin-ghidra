package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.model.FunctionDataTypes;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.FunctionDataTypeMessage;
import org.json.JSONObject;

import javax.annotation.Nullable;
import java.util.Optional;

/**
 * {
 *   "completed": true,
 *   "data_types": {
 *     "func_types": {
 *       "stack_vars": null,
 *       "size": 107,
 *       "last_change": null,
 *       "name": "FUN_0010203b",
 *       "header": {
 *         "args": {
 *           "0x0": {
 *             "offset": 0,
 *             "size": 8,
 *             "last_change": null,
 *             "name": "param_1",
 *             "type": "long *"
 *           },
 *           "0x1": {
 *             "offset": 1,
 *             "size": 8,
 *             "last_change": null,
 *             "name": "param_2",
 *             "type": "char * *"
 *           }
 *         },
 *         "last_change": null,
 *         "name": "FUN_0010203b",
 *         "addr": 8251,
 *         "type": "int"
 *       },
 *       "addr": 8251,
 *       "type": "int"
 *     },
 *     "func_deps": []
 *   },
 *   "status": "completed"
 * }
 * @deprecated Use {@link FunctionDataTypes} instead
 */
@Deprecated
public record FunctionDataTypeStatus(
        boolean completed,
        Optional<FunctionDataTypeMessage> data_types,
//        JSONObject data_types,
        String status,
        @Nullable Integer dataTypesVersion,
        @Nullable TypedApiInterface.FunctionID functionID
        ) {

    public static FunctionDataTypeStatus fromJson(JSONObject json) {
        Integer dataTypesVersion;
        if (json.has("data_types_version") && !json.isNull("data_types_version")) {
            dataTypesVersion = json.getInt("data_types_version");
        } else {
            dataTypesVersion = null;
        }
        return new FunctionDataTypeStatus(
                json.getBoolean("completed"),
                // Can be null if the function is not completed yet
                !json.isNull("data_types") ? Optional.of(FunctionDataTypeMessage.fromJsonObject(json.getJSONObject("data_types"))) : Optional.empty(),
                json.getString("status"),
                dataTypesVersion,
                json.has("function_id") ? new TypedApiInterface.FunctionID(json.getInt("function_id")) : null
        );
    }
}

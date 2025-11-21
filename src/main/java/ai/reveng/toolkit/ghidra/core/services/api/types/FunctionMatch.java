package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import org.json.JSONObject;

/**
 * @param origin_function_id
 * @param nearest_neighbor_id
 * @param nearest_neighbor_function_name
 * @param nearest_neighbor_binary_name
 * @param nearest_neighbor_sha_256_hash
 * @param nearest_neighbor_debug
 * @param similarity
 */
public record FunctionMatch(
        FunctionID origin_function_id,
        FunctionID nearest_neighbor_id,
        String nearest_neighbor_function_name,
        String nearest_neighbor_binary_name,
        BinaryHash nearest_neighbor_sha_256_hash,
        Boolean nearest_neighbor_debug,
        double similarity
) {
    public static FunctionMatch fromJSONObject(JSONObject json) {
        return new FunctionMatch(
                new FunctionID(json.getInt("origin_function_id")),
                new FunctionID(json.getInt("nearest_neighbor_id")),
                json.getString("nearest_neighbor_function_name"),
                json.getString("nearest_neighbor_binary_name"),
                new BinaryHash(json.getString("nearest_neighbor_sha_256_hash")),
                json.has("nearest_neighbor_debug") ? json.getBoolean("nearest_neighbor_debug") : null,
                // This is called confidence for legacy reasons, but it is actually the similarity
                json.getDouble("confidence")
        );
    }

    public String name(){
        return nearest_neighbor_function_name;
    }
}

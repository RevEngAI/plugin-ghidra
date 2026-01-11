package ai.reveng.toolkit.ghidra.core.services.api.types.binsync;

import ai.reveng.model.Structure;
import org.json.JSONObject;

/**
 *     Describes a struct.
 *     All members are stored by their byte offset from the start of the struct.
 *
 *     based on the Struct artifact from BinSync.
 */
public record Struct(
        String last_change,
        String name,
        int size,
        StructMember[] members
) {
    public static Struct fromJsonObject(JSONObject jsonObject) {
        JSONObject jsonMembers = jsonObject.getJSONObject("members");
        // Handle members
        StructMember[] members = jsonMembers.keySet().stream()
                .map(jsonMembers::getJSONObject)
                .map(StructMember::fromJsonObject)
                .toList().toArray(new StructMember[0]);

        return new Struct(
                !jsonObject.isNull("last_change") ? jsonObject.getString("last_change") : null,
                jsonObject.getString("name"),
                jsonObject.getInt("size"),
                members
        );
    }

    public static boolean matches(JSONObject jsonObject) {
        return jsonObject.has("name") && jsonObject.has("size") && jsonObject.has("members");
    }


    public static Struct fromOpenAPI(Structure struct) {
        StructMember[] members = struct.getMembers().values().stream()
                .map(StructMember::fromOpenAPI)
                .toList().toArray(new StructMember[0]);

        return new Struct(
                struct.getLastChange(),
                struct.getName(),
                struct.getSize(),
                members
        );
    }
}

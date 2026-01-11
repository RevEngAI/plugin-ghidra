package ai.reveng.toolkit.ghidra.core.services.api.types.binsync;

import ai.reveng.model.TypeDefinition;
import org.json.JSONObject;

import java.util.Set;

/**
 * Based on the Typedef artifact from BinSync.
 */
public record Typedef(
        String last_change,
        String name,
        String type
) {

        public static Typedef fromJsonObject(JSONObject obj) {
            return new Typedef(
                    !obj.isNull("last_change") ? obj.getString("last_change") : null,
                    obj.getString("name"),
                    obj.getString("type")
            );
        }


        public static boolean matches(JSONObject obj) {
            return obj.keySet().equals(Set.of("last_change", "name", "type"));
//            return obj.has("type") && obj.has("name");
        }

    public static Typedef fromOpenAPI(TypeDefinition typedef) {
        return new Typedef(
                typedef.getLastChange(),
                typedef.getName(),
                typedef.getType()
        );
    }
}

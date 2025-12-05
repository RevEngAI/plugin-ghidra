package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import org.json.JSONObject;

import java.util.List;

/**
 * Collection Object for the old V1 API
 * and still returned by https://api.reveng.ai/v2/docs#tag/Collections/operation/list_collections_v2_collections_get
 *
 * @param collectionID
 * @param collectionScope
 * @param collectionName
 * @param owner
 * @param creationDate
 * @param modelName
 * @param description
 * @param tags
 */
public record LegacyCollection(
        TypedApiInterface.CollectionID collectionID,
        String collectionScope,
        String collectionName,
        String owner,
        String creationDate,
        String modelName,
        String description,
        List<String> tags
) {
    public static LegacyCollection fromJSONObject(JSONObject json){
        return new LegacyCollection(
                new TypedApiInterface.CollectionID(json.getInt("collection_id")),
                json.getString("collection_scope"),
                json.getString("collection_name"),
                json.getString("collection_owner"),
                json.getString("creation"),
                json.getString("model_name"),
                json.getString("description"),
                json.getJSONArray("collection_tags").toList().stream().map(Object::toString).toList()
        );
    }
}

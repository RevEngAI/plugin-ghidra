package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import org.json.JSONObject;

import java.util.List;

/**
 * Collection Object for the V2 API
 *
 * Prototypical object returned by <a href="https://api.reveng.ai/v2/docs#tag/Collections/operation/get_collection_v2_collections__collection_id__get">v2/collections/{collection_id}</a>
 * @param collectionID
 * @param collectionScope
 * @param collectionName
 * @param owner
 * @param creationDate
 * @param modelName
 * @param description
 * @param tags
 */
public record Collection(
        TypedApiInterface.CollectionID collectionID,
        String collectionName,
        String description,
        Integer modelID,
        Integer userId,
        String collectionScope,
        String creationDate,
        List<String> tags,
        List<TypedApiInterface.AnalysisID> binaries
) {
    public static Collection fromJSONObject(JSONObject json){
        return new Collection(
                new TypedApiInterface.CollectionID(json.getInt("collection_id")),
                json.getString("collection_name"),
                json.getString("description"),
                json.getInt("model_id"),
                json.getInt("user_id"),
                json.getString("collection_scope"),
                json.getString("created_at"),
                json.has("tags") ? json.getJSONArray("tags").toList().stream().map(Object::toString).toList() : null,
                json.has("binaries") ? json.getJSONArray("binaries").toList().stream().map( rawID -> new TypedApiInterface.AnalysisID((Integer) rawID)).toList() : null
        );
    }
}

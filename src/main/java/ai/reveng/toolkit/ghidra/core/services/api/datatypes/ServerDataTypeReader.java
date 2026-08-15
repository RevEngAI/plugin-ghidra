package ai.reveng.toolkit.ghidra.core.services.api.datatypes;

import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType.*;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads the spec's {@code DataTypeEntry} JSON straight into the flattened {@link ServerDataType},
 * switching on the {@code kind} discriminator.
 *
 * <p><b>Why this exists.</b> The generated {@code ai.reveng.model.DataTypeEntry} cannot deserialise:
 * its gson adapter match-counts the payload against all ten variants instead of using the
 * discriminator, and since every variant shares the same required fields several always match. That
 * is not fixable from the plugin side by registering an adapter for {@code DataTypeEntry}, because
 * the container models call the <i>static</i> {@code DataTypeEntry.validateJsonElement} before
 * delegating to any adapter — so a factory registered for {@code DataTypeEntry} is never reached.
 *
 * <p><b>How the read path uses it.</b> Call the generated {@code DataTypesApi} {@code ...Call(...)}
 * form, which still builds every request (path, query, auth) exactly as the SDK would, then hand the
 * response body here instead of to the generated deserialiser. {@code ConversationsApiChatService}
 * uses the same {@code okhttp3.Call} escape hatch for SSE. Nothing needs registering on the shared
 * {@code ApiClient}: no generated model the plugin deserialises embeds a {@code DataTypeEntry}.
 *
 * <p>{@link #readEntries} covers every container in one call — each of them holds its entries in a
 * single named array ({@code items} for {@code ListAnalysisDataTypesOutputBody} and
 * {@code AnalysisDataTypesOutputBody}, {@code data_types} for {@code FunctionSignatureBody}) — so no
 * container needs its own model or adapter.
 */
public final class ServerDataTypeReader implements JsonDeserializer<ServerDataType> {

    private static final Type MEMBERS = new TypeToken<List<Member>>() {}.getType();
    private static final Type VALUES = new TypeToken<List<EnumValue>>() {}.getType();
    private static final Type PARAMETERS = new TypeToken<List<Parameter>>() {}.getType();

    /// Snake-case naming binds the nested entries' fields ({@code data_type_id}, {@code is_bitfield},
    /// {@code bit_offset}, ...) reflectively; the entry itself is read by hand below.
    private static final Gson GSON = new GsonBuilder()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .registerTypeAdapter(ServerDataType.class, new ServerDataTypeReader())
            .create();

    /// Read one {@code DataTypeEntry}.
    public static ServerDataType readEntry(JsonElement entry) {
        return GSON.fromJson(entry, ServerDataType.class);
    }

    /// Read the {@code DataTypeEntry} array held in {@code field} of a container body. Returns empty
    /// when the field is absent or JSON null, which the spec allows for every such array.
    public static List<ServerDataType> readEntries(JsonElement body, String field) {
        if (body == null || !body.isJsonObject()) {
            return List.of();
        }
        JsonElement array = body.getAsJsonObject().get(field);
        if (array == null || !array.isJsonArray()) {
            return List.of();
        }
        List<ServerDataType> entries = new ArrayList<>();
        for (JsonElement entry : array.getAsJsonArray()) {
            entries.add(readEntry(entry));
        }
        return entries;
    }

    @Override
    public ServerDataType deserialize(JsonElement json, Type type, JsonDeserializationContext context) {
        JsonObject entry = json.getAsJsonObject();
        Kind kind = Kind.fromJson(string(entry, "kind"));
        Long id = number(entry, "data_type_id");
        return new ServerDataType(
                id == null ? 0L : id,
                string(entry, "namespace"),
                string(entry, "name"),
                kind,
                number(entry, "size"),
                string(entry, "source_type"),
                Boolean.TRUE.equals(bool(entry, "has_definition")),
                number(entry, "source_function_id"),
                string(entry, "created_at"),
                definition(kind, entry.get("definition"), context));
    }

    private static Definition definition(Kind kind, JsonElement raw, JsonDeserializationContext context) {
        if (raw == null || !raw.isJsonObject()) {
            return null;
        }
        JsonObject def = raw.getAsJsonObject();
        return switch (kind) {
            case STRUCT -> new StructDefinition(list(def, "members", MEMBERS, context));
            case UNION -> new UnionDefinition(list(def, "members", MEMBERS, context));
            case ENUM -> new EnumDefinition(list(def, "values", VALUES, context));
            case TYPEDEF -> new TypedefDefinition(number(def, "target_data_type_id"));
            case POINTER -> new PointerDefinition(number(def, "pointee_data_type_id"));
            case ARRAY -> new ArrayDefinition(number(def, "count"), number(def, "element_data_type_id"));
            case FUNCTION_DEFINITION -> new FunctionTypeDefinition(
                    number(def, "return_data_type_id"), list(def, "parameters", PARAMETERS, context));
            // These kinds never carry a definition; ignore one if the server ever sends it.
            case BASE, BITFIELD, UNKNOWN -> null;
        };
    }

    private static <T> List<T> list(JsonObject owner, String field, Type type, JsonDeserializationContext context) {
        JsonElement array = owner.get(field);
        if (array == null || !array.isJsonArray()) {
            return List.of();
        }
        List<T> items = context.deserialize(array, type);
        return items == null ? List.of() : items;
    }

    private static String string(JsonObject owner, String field) {
        JsonElement value = owner.get(field);
        return value == null || value.isJsonNull() ? null : value.getAsString();
    }

    private static Long number(JsonObject owner, String field) {
        JsonElement value = owner.get(field);
        return value == null || value.isJsonNull() ? null : value.getAsLong();
    }

    private static Boolean bool(JsonObject owner, String field) {
        JsonElement value = owner.get(field);
        return value == null || value.isJsonNull() ? null : value.getAsBoolean();
    }
}

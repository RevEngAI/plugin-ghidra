package ai.reveng.toolkit.ghidra.core.services.api.datatypes;

import javax.annotation.Nullable;
import java.util.List;

/**
 * A v3 data type as the portal reports it, flattened.
 *
 * <p>The spec models this as {@code DataTypeEntry}, a ten-way {@code oneOf} discriminated by
 * {@code kind}. All ten variants carry an identical set of fields and differ only in the optional
 * {@code definition} object, so the union is really one record with a variant payload — which is
 * what this is. The plugin never handles the generated union; see {@link ServerDataTypeReader}.
 *
 * @param id               {@code data_type_id}; identifies the type within its analysis. 0 is valid.
 * @param hasDefinition    whether the server says this type carries a definition. Distinguishes a
 *                         kind that never has one from a type referenced but never defined.
 * @param sourceFunctionId set when the type was transferred from another function rather than
 *                         extracted.
 * @param createdAt        raw ISO-8601 timestamp, left unparsed.
 * @param definition       null for {@code BASE}, {@code BITFIELD} and {@code UNKNOWN}, which never
 *                         carry one, and for a type that was referenced but never defined.
 */
public record ServerDataType(
        long id,
        String namespace,
        String name,
        Kind kind,
        @Nullable Long size,
        String sourceType,
        boolean hasDefinition,
        @Nullable Long sourceFunctionId,
        @Nullable String createdAt,
        @Nullable Definition definition) {

    /// The {@code kind} discriminator. Order matches the spec's discriminator mapping.
    public enum Kind {
        STRUCT, UNION, ENUM, TYPEDEF, POINTER, ARRAY, FUNCTION_DEFINITION, BITFIELD, BASE, UNKNOWN;

        /// Kinds the server may add later map to {@link #UNKNOWN} rather than failing the read.
        public static Kind fromJson(@Nullable String value) {
            for (Kind kind : values()) {
                if (kind.name().equals(value)) {
                    return kind;
                }
            }
            return UNKNOWN;
        }
    }

    /// The kind-specific payload. Sealed; every implementation lives in this file.
    public sealed interface Definition {}

    /// A struct or union field. Every id/offset/size in the v3 family is a 64-bit integer.
    public record Member(@Nullable String name, long offset, long size, @Nullable Long dataTypeId,
                         boolean isBitfield, @Nullable Long bitOffset, @Nullable Long bitSize) {}

    /// An enum constant. {@code value} stays a decimal string: it may be negative or exceed 64
    /// unsigned bits, which no Java integer type nor a JSON number can carry safely.
    public record EnumValue(String name, String value) {}

    /// A parameter of a function-definition type.
    public record Parameter(@Nullable String name, long ordinal, long size, @Nullable Long dataTypeId) {}

    public record StructDefinition(List<Member> members) implements Definition {}

    public record UnionDefinition(List<Member> members) implements Definition {}

    public record EnumDefinition(List<EnumValue> values) implements Definition {}

    public record TypedefDefinition(@Nullable Long targetDataTypeId) implements Definition {}

    public record PointerDefinition(@Nullable Long pointeeDataTypeId) implements Definition {}

    public record ArrayDefinition(@Nullable Long count, @Nullable Long elementDataTypeId) implements Definition {}

    public record FunctionTypeDefinition(@Nullable Long returnDataTypeId, List<Parameter> parameters)
            implements Definition {}
}

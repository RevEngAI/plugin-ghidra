package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType.*;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataTypeReader;
import com.google.gson.JsonParser;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

/**
 * Covers {@link ServerDataTypeReader}, which reads the spec's {@code DataTypeEntry} straight into
 * the flattened {@link ServerDataType} by switching on {@code kind}.
 *
 * <p>The generated {@code ai.reveng.model.DataTypeEntry} is deliberately not exercised: it cannot
 * deserialise. Its adapter match-counts against all ten variants rather than using the
 * discriminator, and every variant shares the same required fields so several always match. Nor can
 * that be patched around from the plugin: the container models call the static
 * {@code DataTypeEntry.validateJsonElement} before delegating, so an adapter registered for
 * {@code DataTypeEntry} is never reached. The plugin reads the response body itself instead.
 */
public class DataTypeEntryDeserialisationTest {

    /// Every field the spec marks required on all ten variants, so payloads below stay realistic.
    private static String entry(long id, String kind, String definition) {
        return """
                {
                  "data_type_id": %d,
                  "kind": "%s",
                  "name": "T%d",
                  "namespace": "",
                  "source_type": "SYSTEM",
                  "has_definition": %b,
                  "created_at": "2026-08-13T10:00:00Z"%s
                }""".formatted(id, kind, id, definition != null, definition == null ? "" : ",\n  \"definition\": " + definition);
    }

    private static ServerDataType read(String json) {
        return ServerDataTypeReader.readEntry(JsonParser.parseString(json));
    }

    private static final String STRUCT_DEF = """
            {"members": [
              {"name": "sin_family", "offset": 0, "size": 2, "data_type_id": 18, "is_bitfield": false},
              {"name": "flag", "offset": 2, "size": 1, "data_type_id": 19, "is_bitfield": true,
               "bit_offset": 3, "bit_size": 1}
            ]}""";

    private static final String ENUM_DEF = """
            {"values": [
              {"name": "AF_UNSPEC", "value": "0"},
              {"name": "NEG_ONE", "value": "-1"},
              {"name": "MAX_U64", "value": "18446744073709551615"}
            ]}""";

    private static final String FUNCTION_DEF = """
            {"return_data_type_id": 7, "parameters": [
              {"name": "argc", "ordinal": 0, "size": 4, "data_type_id": 18},
              {"name": "argv", "ordinal": 1, "size": 8, "data_type_id": 21}
            ]}""";

    @Test
    public void allTenKindsFlattenToTheRightDefinition() {
        assertEquals(Kind.STRUCT, read(entry(1, "STRUCT", STRUCT_DEF)).kind());
        assertTrue(read(entry(1, "STRUCT", STRUCT_DEF)).definition() instanceof StructDefinition);
        assertTrue(read(entry(2, "UNION", """
                {"members": [{"name": "a", "offset": 0, "size": 4, "is_bitfield": false}]}"""))
                .definition() instanceof UnionDefinition);
        assertTrue(read(entry(3, "ENUM", ENUM_DEF)).definition() instanceof EnumDefinition);
        assertTrue(read(entry(4, "TYPEDEF", """
                {"target_data_type_id": 18}""")).definition() instanceof TypedefDefinition);
        assertTrue(read(entry(5, "POINTER", """
                {"pointee_data_type_id": 18}""")).definition() instanceof PointerDefinition);
        assertTrue(read(entry(6, "ARRAY", """
                {"count": 8, "element_data_type_id": 18}""")).definition() instanceof ArrayDefinition);
        assertTrue(read(entry(7, "FUNCTION_DEFINITION", FUNCTION_DEF))
                .definition() instanceof FunctionTypeDefinition);

        // The three kinds that never carry a definition.
        for (String kind : List.of("BITFIELD", "BASE", "UNKNOWN")) {
            ServerDataType type = read(entry(8, kind, null));
            assertEquals(Kind.valueOf(kind), type.kind());
            assertNull("kind " + kind + " must not carry a definition", type.definition());
            assertFalse(type.hasDefinition());
        }
    }

    @Test
    public void structMembersIncludingBitfieldsSurvive() {
        var definition = (StructDefinition) read(entry(1, "STRUCT", STRUCT_DEF)).definition();
        assertEquals(2, definition.members().size());

        Member first = definition.members().get(0);
        assertEquals("sin_family", first.name());
        assertEquals(0L, first.offset());
        assertEquals(2L, first.size());
        assertEquals(Long.valueOf(18), first.dataTypeId());
        assertFalse(first.isBitfield());
        assertNull(first.bitOffset());

        Member bitfield = definition.members().get(1);
        assertTrue(bitfield.isBitfield());
        assertEquals(Long.valueOf(3), bitfield.bitOffset());
        assertEquals(Long.valueOf(1), bitfield.bitSize());
    }

    @Test
    public void enumValuesStayDecimalStringsIncludingNegativeAndAboveSixtyFourBits() {
        var definition = (EnumDefinition) read(entry(3, "ENUM", ENUM_DEF)).definition();
        assertEquals(3, definition.values().size());
        assertEquals("0", definition.values().get(0).value());
        assertEquals("NEG_ONE", definition.values().get(1).name());
        assertEquals("-1", definition.values().get(1).value());
        // Would not survive a long; the spec keeps it a string for exactly this reason.
        assertEquals("18446744073709551615", definition.values().get(2).value());
    }

    @Test
    public void functionParametersAndTargetIdsSurvive() {
        var function = (FunctionTypeDefinition) read(entry(7, "FUNCTION_DEFINITION", FUNCTION_DEF)).definition();
        assertEquals(Long.valueOf(7), function.returnDataTypeId());
        assertEquals(2, function.parameters().size());
        assertEquals("argv", function.parameters().get(1).name());
        assertEquals(1L, function.parameters().get(1).ordinal());
        assertEquals(Long.valueOf(21), function.parameters().get(1).dataTypeId());

        assertEquals(Long.valueOf(18),
                ((TypedefDefinition) read(entry(4, "TYPEDEF", "{\"target_data_type_id\": 18}")).definition())
                        .targetDataTypeId());
        assertEquals(Long.valueOf(18),
                ((PointerDefinition) read(entry(5, "POINTER", "{\"pointee_data_type_id\": 18}")).definition())
                        .pointeeDataTypeId());
        var array = (ArrayDefinition) read(entry(6, "ARRAY", "{\"count\": 8, \"element_data_type_id\": 18}")).definition();
        assertEquals(Long.valueOf(8), array.count());
        assertEquals(Long.valueOf(18), array.elementDataTypeId());
    }

    @Test
    public void flatFieldsSurviveIncludingALargeSizeAndAZeroId() {
        ServerDataType type = read("""
                {
                  "data_type_id": 0,
                  "kind": "BASE",
                  "name": "unsigned long long",
                  "namespace": "/DWARF/limits.h",
                  "source_type": "AI_DECOMP",
                  "has_definition": false,
                  "source_function_id": 987654321,
                  "size": 9223372036854775807,
                  "created_at": "2026-08-13T10:00:00Z"
                }""");
        assertEquals(0L, type.id());
        assertEquals("unsigned long long", type.name());
        assertEquals("/DWARF/limits.h", type.namespace());
        assertEquals("AI_DECOMP", type.sourceType());
        assertEquals(Long.valueOf(Long.MAX_VALUE), type.size());
        assertEquals(Long.valueOf(987654321), type.sourceFunctionId());
        assertEquals("2026-08-13T10:00:00Z", type.createdAt());
    }

    @Test
    public void absentOptionalsAndAKindDeclaredButNeverDefined() {
        ServerDataType type = read(entry(9, "STRUCT", null));
        assertNull("size is absent when the server could not determine it", type.size());
        assertNull(type.sourceFunctionId());
        assertNull("a type referenced but never defined carries no definition", type.definition());
        assertFalse(type.hasDefinition());

        // A definition present but with a null array still yields an empty list, never null.
        var empty = (StructDefinition) read(entry(10, "STRUCT", "{\"members\": null}")).definition();
        assertNotNull(empty);
        assertTrue(empty.members().isEmpty());
    }

    @Test
    public void unrecognisedKindDegradesToUnknownRatherThanFailing() {
        ServerDataType type = read(entry(11, "SOME_FUTURE_KIND", null));
        assertEquals(Kind.UNKNOWN, type.kind());
    }

    /// The real list read path: GET /v3/analyses/{analysis_id}/data-types.
    @Test
    public void listAnalysisDataTypesOutputBodyWithMixedKindsParses() {
        String body = """
                {
                  "total_count": 4,
                  "items": [%s, %s, %s, %s]
                }""".formatted(
                entry(1, "STRUCT", STRUCT_DEF),
                entry(3, "ENUM", ENUM_DEF),
                entry(5, "POINTER", "{\"pointee_data_type_id\": 1}"),
                entry(8, "BASE", null));

        List<ServerDataType> types = ServerDataTypeReader.readEntries(JsonParser.parseString(body), "items");
        assertEquals(4, types.size());
        assertEquals(List.of(Kind.STRUCT, Kind.ENUM, Kind.POINTER, Kind.BASE),
                types.stream().map(ServerDataType::kind).toList());
        assertEquals(2, ((StructDefinition) types.get(0).definition()).members().size());
        assertEquals("-1", ((EnumDefinition) types.get(1).definition()).values().get(1).value());
        assertEquals(Long.valueOf(1), ((PointerDefinition) types.get(2).definition()).pointeeDataTypeId());
        assertNull(types.get(3).definition());
    }

    /// The real signature read path: GET /v3/analyses/{analysis_id}/functions/{function_id}/signature.
    @Test
    public void functionSignatureBodyWithMixedKindsParses() {
        String body = """
                {
                  "function_id": 4242,
                  "function_name": "main",
                  "has_signature": true,
                  "calling_convention": "__stdcall",
                  "created_at": "2026-08-13T10:00:00Z",
                  "return_data_type_id": 7,
                  "source_type": "USER",
                  "parameters": [
                    {"ordinal": 0, "name": "argc", "data_type_id": 7},
                    {"ordinal": 1, "name": "argv", "data_type_id": 5}
                  ],
                  "data_types": [%s, %s, %s]
                }""".formatted(
                entry(7, "BASE", null),
                entry(5, "POINTER", "{\"pointee_data_type_id\": 7}"),
                entry(2, "UNION", "{\"members\": [{\"name\": \"raw\", \"offset\": 0, \"size\": 8, \"is_bitfield\": false}]}"));

        List<ServerDataType> types = ServerDataTypeReader.readEntries(JsonParser.parseString(body), "data_types");
        assertEquals(3, types.size());
        assertEquals(List.of(Kind.BASE, Kind.POINTER, Kind.UNION),
                types.stream().map(ServerDataType::kind).toList());
        assertEquals(Long.valueOf(7), ((PointerDefinition) types.get(1).definition()).pointeeDataTypeId());
        Member member = ((UnionDefinition) types.get(2).definition()).members().get(0);
        assertEquals("raw", member.name());
        assertEquals(8L, member.size());
    }

    @Test
    public void containerWithNoTypesParses() {
        assertTrue(ServerDataTypeReader.readEntries(
                JsonParser.parseString("{\"total_count\": 0, \"items\": null}"), "items").isEmpty());
        assertTrue(ServerDataTypeReader.readEntries(
                JsonParser.parseString("{\"total_count\": 0}"), "items").isEmpty());
    }
}

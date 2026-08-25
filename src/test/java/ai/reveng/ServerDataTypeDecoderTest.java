package ai.reveng;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraDataTypeEncoder;
import ai.reveng.toolkit.ghidra.core.services.api.ServerDataTypeDecoder;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataTypeReader;
import com.google.gson.JsonParser;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/// Tests for {@link ServerDataTypeDecoder}, which resolves the server's data types by
/// `data_type_id` rather than by name.
public class ServerDataTypeDecoderTest extends RevEngMockableHeadedIntegrationTest {

    private static List<ServerDataType> types(String json) {
        return ServerDataTypeReader.readEntries(JsonParser.parseString(json), "items");
    }

    /// A struct member reported beyond the struct's declared size must not abort the whole type
    /// load: the struct grows to fit instead.
    @Test
    public void growsStructToFitMemberBeyondDeclaredSize() {
        var decoder = ServerDataTypeDecoder.decode(types("""
                {"items": [
                  {"data_type_id": 1, "namespace": "", "name": "OversizedStruct", "kind": "STRUCT",
                   "size": 32, "source_type": "AUTO", "has_definition": true,
                   "definition": {"members": [
                     {"name": "head", "offset": 0, "size": 4, "data_type_id": null, "is_bitfield": false},
                     {"name": "tail", "offset": 32, "size": 8, "data_type_id": null, "is_bitfield": false}
                   ]}}
                ]}
                """));

        Structure loaded = (Structure) decoder.typeFor(1L, 0);
        assertTrue("struct should have grown to fit the trailing member, length was " + loaded.getLength(),
                loaded.getLength() >= 40);
        assertEquals("head", loaded.getComponentAt(0).getFieldName());
        assertEquals("tail", loaded.getComponentAt(32).getFieldName());
    }

    /// A struct holding a pointer to itself used to need the dependency list to arrive in a usable
    /// order. Resolving by id closes the cycle without any retrying.
    @Test
    public void resolvesSelfReferentialStruct() {
        var decoder = ServerDataTypeDecoder.decode(types("""
                {"items": [
                  {"data_type_id": 1, "namespace": "", "name": "Node", "kind": "STRUCT",
                   "size": 8, "source_type": "AUTO", "has_definition": true,
                   "definition": {"members": [
                     {"name": "next", "offset": 0, "size": 8, "data_type_id": 2, "is_bitfield": false}
                   ]}},
                  {"data_type_id": 2, "namespace": "", "name": "Node *", "kind": "POINTER",
                   "size": 8, "source_type": "AUTO", "has_definition": true,
                   "definition": {"pointee_data_type_id": 1}}
                ]}
                """));

        Structure node = (Structure) decoder.typeFor(1L, 0);
        DataType next = node.getComponentAt(0).getDataType();
        assertTrue("member should be a pointer, was " + next.getClass(), next instanceof Pointer);
        assertEquals(node, ((Pointer) next).getDataType());
    }

    /// The types arrive in whatever order the server lists them, so a typedef may be read before its
    /// target. Both passes work off the id map, so the order does not matter.
    @Test
    public void resolvesTypedefDeclaredBeforeItsTarget() {
        var decoder = ServerDataTypeDecoder.decode(types("""
                {"items": [
                  {"data_type_id": 5, "namespace": "sys", "name": "handle_t", "kind": "TYPEDEF",
                   "size": 8, "source_type": "AUTO", "has_definition": true,
                   "definition": {"target_data_type_id": 6}},
                  {"data_type_id": 6, "namespace": "sys", "name": "handle_s", "kind": "STRUCT",
                   "size": 4, "source_type": "AUTO", "has_definition": true,
                   "definition": {"members": [
                     {"name": "fd", "offset": 0, "size": 4, "data_type_id": null, "is_bitfield": false}
                   ]}}
                ]}
                """));

        DataType typedef = decoder.typeFor(5L, 0);
        assertTrue("expected a typedef, got " + typedef.getClass(), typedef instanceof TypeDef);
        assertEquals("handle_t", typedef.getName());
        assertEquals("/sys", typedef.getCategoryPath().getPath());
        assertEquals(decoder.typeFor(6L, 0), ((TypeDef) typedef).getDataType());
    }

    /// Enum constants stay strings on the wire because they can be negative or exceed what a signed
    /// 64-bit value holds.
    @Test
    public void decodesEnumValuesIncludingNegativeAndUnsigned64() {
        var decoder = ServerDataTypeDecoder.decode(types("""
                {"items": [
                  {"data_type_id": 3, "namespace": "", "name": "Flags", "kind": "ENUM",
                   "size": 8, "source_type": "AUTO", "has_definition": true,
                   "definition": {"values": [
                     {"name": "NEG", "value": "-1"},
                     {"name": "ZERO", "value": "0"},
                     {"name": "MAX_U64", "value": "18446744073709551615"}
                   ]}}
                ]}
                """));

        Enum flags = (Enum) decoder.typeFor(3L, 0);
        assertEquals(-1L, flags.getValue("NEG"));
        assertEquals(0L, flags.getValue("ZERO"));
        assertEquals(-1L, flags.getValue("MAX_U64"));
    }

    @Test
    public void decodesUnionMembers() {
        var decoder = ServerDataTypeDecoder.decode(types("""
                {"items": [
                  {"data_type_id": 7, "namespace": "", "name": "Value", "kind": "UNION",
                   "size": 8, "source_type": "AUTO", "has_definition": true,
                   "definition": {"members": [
                     {"name": "as_int", "offset": 0, "size": 4, "data_type_id": null, "is_bitfield": false},
                     {"name": "as_ptr", "offset": 0, "size": 8, "data_type_id": null, "is_bitfield": false}
                   ]}}
                ]}
                """));

        Union value = (Union) decoder.typeFor(7L, 0);
        assertEquals(2, value.getNumComponents());
        assertEquals("as_int", value.getComponent(0).getFieldName());
        assertEquals("as_ptr", value.getComponent(1).getFieldName());
    }

    /// The server only ships the type closure it knows about, so a reference can dangle. That has to
    /// degrade to a filler rather than fail the decode.
    @Test
    public void referencedButUndefinedTypeBecomesUndefinedFiller() {
        var decoder = ServerDataTypeDecoder.decode(types("""
                {"items": [
                  {"data_type_id": 1, "namespace": "", "name": "Holder", "kind": "STRUCT",
                   "size": 4, "source_type": "AUTO", "has_definition": true,
                   "definition": {"members": [
                     {"name": "missing", "offset": 0, "size": 4, "data_type_id": 999, "is_bitfield": false}
                   ]}}
                ]}
                """));

        Structure holder = (Structure) decoder.typeFor(1L, 0);
        assertNotNull(holder.getComponentAt(0));
        assertEquals("missing", holder.getComponentAt(0).getFieldName());
        // An id nobody defined is still answered, with a same-sized placeholder.
        assertEquals(4, decoder.typeFor(999L, 4).getLength());
    }

    /// What lets the write path keep a namespace it found on a Ghidra category path is that a type
    /// pulled from server namespace `X` lands in a category the encoder maps back to exactly `X`.
    ///
    /// That holds for the kinds the decoder builds with an explicit category — struct, union, enum,
    /// typedef and function definition. It does not for pointers and arrays, which Ghidra derives
    /// from their pointee and element and which therefore carry that type's category rather than
    /// their own, nor for base types, which are looked up as Ghidra built-ins by name. Those kinds
    /// never round-trip a namespace at all, which is why the write path treats a namespace the
    /// analysis does not already use as a local one.
    @Test
    public void namedKindsRoundTripTheirNamespaceThroughTheCategoryPath() {
        var entries = types("""
                {"items": [
                  {"data_type_id": 1, "namespace": "DWARF::stdio.h", "name": "FILE", "kind": "STRUCT",
                   "size": 8, "source_type": "AUTO", "has_definition": true,
                   "definition": {"members": [
                     {"name": "fd", "offset": 0, "size": 4, "data_type_id": null, "is_bitfield": false}]}},
                  {"data_type_id": 2, "namespace": "sys", "name": "handle_t", "kind": "TYPEDEF",
                   "size": 8, "source_type": "AUTO", "has_definition": true,
                   "definition": {"target_data_type_id": 1}},
                  {"data_type_id": 3, "namespace": "flags", "name": "Level", "kind": "ENUM",
                   "size": 4, "source_type": "AUTO", "has_definition": true,
                   "definition": {"values": [{"name": "LOW", "value": "1"}]}},
                  {"data_type_id": 4, "namespace": "u", "name": "Value", "kind": "UNION",
                   "size": 8, "source_type": "AUTO", "has_definition": true,
                   "definition": {"members": [
                     {"name": "as_int", "offset": 0, "size": 4, "data_type_id": null, "is_bitfield": false}]}},
                  {"data_type_id": 5, "namespace": "api", "name": "callback", "kind": "FUNCTION_DEFINITION",
                   "size": 0, "source_type": "AUTO", "has_definition": true,
                   "definition": {"return_data_type_id": null, "parameters": []}},
                  {"data_type_id": 6, "namespace": "", "name": "Local", "kind": "STRUCT",
                   "size": 4, "source_type": "USER", "has_definition": true,
                   "definition": {"members": [
                     {"name": "x", "offset": 0, "size": 4, "data_type_id": null, "is_bitfield": false}]}}
                ]}
                """);
        var decoder = ServerDataTypeDecoder.decode(entries);

        for (ServerDataType entry : entries) {
            DataType decoded = decoder.typeFor(entry.id(), 0);
            assertEquals("namespace of " + entry.name() + " must survive the round trip",
                    entry.namespace(),
                    GhidraDataTypeEncoder.keyOf(decoded).namespace());
            assertEquals("and so must its name",
                    entry.name(), GhidraDataTypeEncoder.keyOf(decoded).name());
        }
    }

    /// BASE types carry no definition — only a name, which has to resolve to a Ghidra built-in.
    @Test
    public void resolvesBaseTypesByName() {
        var decoder = ServerDataTypeDecoder.decode(types("""
                {"items": [
                  {"data_type_id": 1, "namespace": "", "name": "int", "kind": "BASE",
                   "size": 4, "source_type": "AUTO", "has_definition": false}
                ]}
                """));

        assertEquals("int", decoder.typeFor(1L, 0).getName());
    }
}

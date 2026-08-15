package ai.reveng;

import ai.reveng.toolkit.ghidra.core.services.api.AnalysisDataTypesService.TypeKey;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraDataTypeEncoder;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType.Kind;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/// Tests for {@link GhidraDataTypeEncoder}, which turns Ghidra types into the v3 create/update
/// bodies. The mirror of {@link ai.reveng.toolkit.ghidra.core.services.api.ServerDataTypeDecoder}.
public class GhidraDataTypeEncoderTest extends ghidra.test.AbstractGhidraHeadlessIntegrationTest {

    /// Resolves every key to a distinct id, in the order the keys are first asked for, which is
    /// what the create/update pass would have produced.
    private static GhidraDataTypeEncoder.Ids idsFor(List<ghidra.program.model.data.DataType> closure) {
        Map<TypeKey, Long> ids = new java.util.LinkedHashMap<>();
        long next = 1;
        for (var type : closure) {
            ids.putIfAbsent(GhidraDataTypeEncoder.keyOf(type), next++);
        }
        return ids::get;
    }

    private static Object instanceOfCreate(ghidra.program.model.data.DataType type) {
        return GhidraDataTypeEncoder.createEntry(type).getActualInstance();
    }

    private static Object instanceOfUpdate(ghidra.program.model.data.DataType type,
                                           GhidraDataTypeEncoder.Ids ids) {
        return GhidraDataTypeEncoder.updateEntry(type, 1L, ids).orElseThrow().getActualInstance();
    }

    @Test
    public void mapsEveryGhidraKindToItsVariant() {
        var struct = new StructureDataType("S", 0);
        struct.add(new IntegerDataType(), "a", null);
        var union = new UnionDataType("U");
        union.add(new IntegerDataType(), "a", null);
        var enumeration = new EnumDataType("E", 4);
        enumeration.add("A", 1);
        var typedef = new TypedefDataType("T", new IntegerDataType());
        var pointer = new PointerDataType(struct);
        var array = new ArrayDataType(new CharDataType(), 16, 1);
        var functionType = new FunctionDefinitionDataType("F");
        functionType.setReturnType(new IntegerDataType());

        assertEquals(Kind.STRUCT, GhidraDataTypeEncoder.kindOf(struct));
        assertEquals(Kind.UNION, GhidraDataTypeEncoder.kindOf(union));
        assertEquals(Kind.ENUM, GhidraDataTypeEncoder.kindOf(enumeration));
        assertEquals(Kind.TYPEDEF, GhidraDataTypeEncoder.kindOf(typedef));
        assertEquals(Kind.POINTER, GhidraDataTypeEncoder.kindOf(pointer));
        assertEquals(Kind.ARRAY, GhidraDataTypeEncoder.kindOf(array));
        assertEquals(Kind.FUNCTION_DEFINITION, GhidraDataTypeEncoder.kindOf(functionType));
        assertEquals(Kind.BASE, GhidraDataTypeEncoder.kindOf(new IntegerDataType()));
        assertEquals(Kind.UNKNOWN,
                GhidraDataTypeEncoder.kindOf(ghidra.program.model.data.Undefined1DataType.dataType));

        assertTrue(instanceOfCreate(struct) instanceof ai.reveng.model.CreateStructDataType);
        assertTrue(instanceOfCreate(union) instanceof ai.reveng.model.CreateUnionDataType);
        assertTrue(instanceOfCreate(enumeration) instanceof ai.reveng.model.CreateEnumDataType);
        assertTrue(instanceOfCreate(typedef) instanceof ai.reveng.model.CreateTypedefDataType);
        assertTrue(instanceOfCreate(pointer) instanceof ai.reveng.model.CreatePointerDataType);
        assertTrue(instanceOfCreate(array) instanceof ai.reveng.model.CreateArrayDataType);
        assertTrue(instanceOfCreate(functionType) instanceof ai.reveng.model.CreateFunctionDataType);
        assertTrue(instanceOfCreate(new IntegerDataType()) instanceof ai.reveng.model.CreateBaseDataType);
        assertTrue(instanceOfCreate(ghidra.program.model.data.Undefined1DataType.dataType)
                instanceof ai.reveng.model.CreateUnknownDataType);
    }

    /// A `Create*` body carries no `data_type_id` and cannot point at anything created alongside it,
    /// so the definitions it does carry have to be empty.
    @Test
    public void createBodiesCarryEmptyDefinitions() {
        var struct = new StructureDataType("S", 0);
        struct.add(new IntegerDataType(), "a", null);

        var created = (ai.reveng.model.CreateStructDataType) instanceOfCreate(struct);
        assertEquals("S", created.getName());
        assertEquals("", created.getNamespace());
        assertEquals(Long.valueOf(struct.getLength()), created.getSize());
        assertTrue("the definition is filled in by the update pass", created.getDefinition().getMembers().isEmpty());

        var pointer = (ai.reveng.model.CreatePointerDataType) instanceOfCreate(new PointerDataType(struct));
        assertNull(pointer.getDefinition().getPointeeDataTypeId());

        var functionType = new FunctionDefinitionDataType("F");
        functionType.setArguments(new ParameterDefinitionImpl("a", new IntegerDataType(), null));
        var created3 = (ai.reveng.model.CreateFunctionDataType) instanceOfCreate(functionType);
        assertTrue(created3.getDefinition().getParameters().isEmpty());
    }

    @Test
    public void structMembersEncodeWithOffsetSizeAndTypeId() {
        var inner = new StructureDataType("Inner", 0);
        inner.add(new IntegerDataType(), "x", null);
        var outer = new StructureDataType("Outer", 0);
        outer.add(new IntegerDataType(), "count", null);
        outer.add(inner, "body", null);
        // Unnamed padding is legal and must survive as a null name.
        outer.add(new CharDataType(), null, null);

        var closure = GhidraDataTypeEncoder.closure(List.of(outer));
        var ids = idsFor(closure);
        var updated = (ai.reveng.model.UpdateStructDataType) instanceOfUpdate(outer, ids);

        var members = updated.getDefinition().getMembers();
        assertEquals(3, members.size());
        assertEquals("count", members.get(0).getName());
        assertEquals(Long.valueOf(0), members.get(0).getOffset());
        assertEquals(Long.valueOf(4), members.get(0).getSize());
        assertEquals(Boolean.FALSE, members.get(0).getIsBitfield());
        assertEquals("body", members.get(1).getName());
        assertEquals(Long.valueOf(4), members.get(1).getOffset());
        assertEquals("the member points at the inner struct's id",
                ids.idOf(GhidraDataTypeEncoder.keyOf(inner)), members.get(1).getDataTypeId());
        assertNull("unnamed padding keeps a null name", members.get(2).getName());
    }

    /// A bitfield is a property of the member that holds it, not a type of its own: the member
    /// points at the bitfield's base type and carries the bit geometry itself.
    @Test
    public void bitfieldsEncodeOnTheMemberNotAsAType() throws Exception {
        var flags = new StructureDataType("Flags", 0);
        flags.setPackingEnabled(true);
        flags.addBitField(new IntegerDataType(), 1, "enabled", null);
        flags.addBitField(new IntegerDataType(), 3, "level", null);

        var closure = GhidraDataTypeEncoder.closure(List.of(flags));
        assertFalse("no standalone BITFIELD type is invented",
                closure.stream().anyMatch(type -> GhidraDataTypeEncoder.kindOf(type) == Kind.BITFIELD));
        assertTrue("the member's base type is what gets an id",
                closure.stream().anyMatch(type -> "int".equals(type.getName())));

        var updated = (ai.reveng.model.UpdateStructDataType) instanceOfUpdate(flags, idsFor(closure));
        var members = updated.getDefinition().getMembers();
        assertEquals(2, members.size());
        assertEquals(Boolean.TRUE, members.get(0).getIsBitfield());
        assertEquals(Long.valueOf(1), members.get(0).getBitSize());
        assertEquals(Boolean.TRUE, members.get(1).getIsBitfield());
        assertEquals(Long.valueOf(3), members.get(1).getBitSize());
    }

    /// The API wants a bitfield's offset from the start of the containing type. Ghidra reports the
    /// offset of the least-significant bit within the component's storage unit, and on a big-endian
    /// target that is counted from the far end of the unit: the same four fields report 7, 4, 0 and
    /// 0 rather than 0, 1, 4 and 0. Taking that at face value would put the first field of a
    /// big-endian struct at bit 7 and then walk backwards.
    @Test
    public void bitfieldOffsetsAreCountedFromTheStartOfTheTypeOnEitherEndianness() throws Exception {
        assertEquals("little-endian offsets run 0, 1, 4, 8",
                List.of(0L, 1L, 4L, 8L), bitOffsetsOfPackedFlags(false));
        assertEquals("and big-endian offsets have to run the same way",
                List.of(0L, 1L, 4L, 8L), bitOffsetsOfPackedFlags(true));
    }

    /// `int a:1; int b:3; int c:4; int d:8;` packed into a manager of the given endianness.
    private static List<Long> bitOffsetsOfPackedFlags(boolean bigEndian) throws Exception {
        var organization = ghidra.program.model.data.DataOrganizationImpl.getDefaultOrganization(null);
        organization.setBigEndian(bigEndian);
        var dtm = new ghidra.program.model.data.StandAloneDataTypeManager("endianness", organization);
        int transaction = dtm.startTransaction("build");
        try {
            var flags = new StructureDataType("Flags", 0, dtm);
            flags.setPackingEnabled(true);
            flags.addBitField(new IntegerDataType(dtm), 1, "a", null);
            flags.addBitField(new IntegerDataType(dtm), 3, "b", null);
            flags.addBitField(new IntegerDataType(dtm), 4, "c", null);
            flags.addBitField(new IntegerDataType(dtm), 8, "d", null);

            var updated = (ai.reveng.model.UpdateStructDataType) instanceOfUpdate(flags, key -> 1L);
            return updated.getDefinition().getMembers().stream()
                    .map(ai.reveng.model.DataTypeMemberEntry::getBitOffset)
                    .toList();
        } finally {
            dtm.endTransaction(transaction, true);
            dtm.close();
        }
    }

    @Test
    public void unionMembersAllSitAtOffsetZero() {
        var union = new UnionDataType("U");
        union.add(new IntegerDataType(), "asInt", null);
        union.add(new ArrayDataType(new CharDataType(), 4, 1), "asBytes", null);

        var closure = GhidraDataTypeEncoder.closure(List.of(union));
        var updated = (ai.reveng.model.UpdateUnionDataType) instanceOfUpdate(union, idsFor(closure));

        assertEquals(2, updated.getDefinition().getMembers().size());
        updated.getDefinition().getMembers()
                .forEach(member -> assertEquals(Long.valueOf(0), member.getOffset()));
    }

    /// Enum values stay decimal strings on the wire because they may be negative or exceed 64
    /// unsigned bits, which no JSON number and no Java integer type can carry safely. Ghidra can
    /// only hold a signed long, so what the encoder has to get right is that it never turns the
    /// value back into a number — negatives keep their sign, and the field stays wide enough to
    /// carry a value Ghidra itself could not have produced.
    @Test
    public void enumValuesSurviveAsStringsIncludingNegativeAndAbove64Bits() {
        var enumeration = new EnumDataType("E", 8);
        enumeration.add("NEGATIVE", -1);
        enumeration.add("ZERO", 0);
        enumeration.add("MAX_SIGNED", Long.MAX_VALUE);

        var updated = (ai.reveng.model.UpdateEnumDataType) instanceOfUpdate(enumeration, key -> null);
        var byName = updated.getDefinition().getValues().stream()
                .collect(java.util.stream.Collectors.toMap(
                        ai.reveng.model.DataTypeEnumValueEntry::getName,
                        ai.reveng.model.DataTypeEnumValueEntry::getValue));

        assertEquals(3, byName.size());
        assertEquals("-1", byName.get("NEGATIVE"));
        assertEquals("0", byName.get("ZERO"));
        assertEquals("9223372036854775807", byName.get("MAX_SIGNED"));

        // The wire field is a string end to end, so a value past what any Java integer type holds
        // round-trips unchanged rather than overflowing on the way through.
        String aboveUnsigned64 = "18446744073709551616";
        var carried = new ai.reveng.model.DataTypeEnumValueEntry().name("HUGE").value(aboveUnsigned64);
        assertEquals(aboveUnsigned64, carried.getValue());
    }

    @Test
    public void pointersAndArraysGetTheirOwnDerivedNames() {
        var struct = new StructureDataType("Foo", 0);
        struct.add(new IntegerDataType(), "a", null);
        var pointer = new PointerDataType(struct);
        var array = new ArrayDataType(new CharDataType(), 16, 1);

        assertEquals("Foo *", GhidraDataTypeEncoder.keyOf(pointer).name());
        assertEquals(Kind.POINTER, GhidraDataTypeEncoder.keyOf(pointer).kind());
        assertEquals("char[16]", GhidraDataTypeEncoder.keyOf(array).name());
        assertEquals(Kind.ARRAY, GhidraDataTypeEncoder.keyOf(array).kind());

        var closure = GhidraDataTypeEncoder.closure(List.of(pointer, array));
        var ids = idsFor(closure);
        var encodedPointer = (ai.reveng.model.UpdatePointerDataType) instanceOfUpdate(pointer, ids);
        assertEquals("the pointee gets an id of its own",
                ids.idOf(GhidraDataTypeEncoder.keyOf(struct)),
                encodedPointer.getDefinition().getPointeeDataTypeId());

        var encodedArray = (ai.reveng.model.UpdateArrayDataType) instanceOfUpdate(array, ids);
        assertEquals(Long.valueOf(16), encodedArray.getDefinition().getCount());
        assertEquals(ids.idOf(GhidraDataTypeEncoder.keyOf(new CharDataType())),
                encodedArray.getDefinition().getElementDataTypeId());
    }

    @Test
    public void typedefsAndFunctionTypesResolveTheirTargets() {
        var typedef = new TypedefDataType("size_t", new UnsignedLongLongDataType());
        var functionType = new FunctionDefinitionDataType("callback");
        functionType.setReturnType(new IntegerDataType());
        functionType.setArguments(
                new ParameterDefinitionImpl("ctx", new PointerDataType(VoidDataType.dataType), null),
                new ParameterDefinitionImpl("n", typedef, null));

        var closure = GhidraDataTypeEncoder.closure(List.of(typedef, functionType));
        var ids = idsFor(closure);

        var encodedTypedef = (ai.reveng.model.UpdateTypedefDataType) instanceOfUpdate(typedef, ids);
        assertEquals(ids.idOf(GhidraDataTypeEncoder.keyOf(new UnsignedLongLongDataType())),
                encodedTypedef.getDefinition().getTargetDataTypeId());

        var encoded = (ai.reveng.model.UpdateFunctionDataType) instanceOfUpdate(functionType, ids);
        var parameters = encoded.getDefinition().getParameters();
        assertEquals(2, parameters.size());
        assertEquals(Long.valueOf(0), parameters.get(0).getOrdinal());
        assertEquals("ctx", parameters.get(0).getName());
        assertEquals(Long.valueOf(1), parameters.get(1).getOrdinal());
        assertEquals(ids.idOf(GhidraDataTypeEncoder.keyOf(typedef)), parameters.get(1).getDataTypeId());
        assertEquals(ids.idOf(GhidraDataTypeEncoder.keyOf(new IntegerDataType())),
                encoded.getDefinition().getReturnDataTypeId());
    }

    /// `PUT` replaces a stored type in full, so a Ghidra type with nothing to say must not be
    /// allowed to write an empty definition over whatever the server extracted.
    @Test
    public void typesWithNothingToSayProduceNoUpdate() {
        assertTrue("a base type has no definition to write",
                GhidraDataTypeEncoder.updateEntry(new IntegerDataType(), 1L, key -> null).isEmpty());
        assertTrue("an empty local struct must not clear a populated server one",
                GhidraDataTypeEncoder.updateEntry(new StructureDataType("Empty", 0), 1L, key -> null).isEmpty());
        assertTrue("a pointee that resolved to nothing leaves the stored pointer alone",
                GhidraDataTypeEncoder.updateEntry(
                        new PointerDataType(new StructureDataType("Unknown", 4)), 1L, key -> null).isEmpty());
    }

    /// The namespace round-trips through the category path, which is how a type the plugin pulled
    /// from the server resolves back to the same entry instead of being created again.
    @Test
    public void namespaceIsTheInverseOfTheDecodersCategoryPath() {
        var local = new StructureDataType("Local", 0);
        assertEquals("", GhidraDataTypeEncoder.keyOf(local).namespace());

        var scoped = new StructureDataType(new CategoryPath("/DWARF/stdio.h"), "FILE", 0);
        assertEquals("DWARF::stdio.h", GhidraDataTypeEncoder.keyOf(scoped).namespace());
        assertEquals("FILE", GhidraDataTypeEncoder.keyOf(scoped).name());
    }

    /// Two Ghidra instances of the same type are one server type, so the closure de-duplicates on
    /// the key rather than on object identity.
    @Test
    public void closureDedupesByServerIdentityAndTerminatesOnCycles() {
        var node = new StructureDataType("Node", 0);
        node.add(new PointerDataType(node), "next", null);
        node.add(new PointerDataType(node), "prev", null);
        node.add(new IntegerDataType(), "value", null);

        var closure = GhidraDataTypeEncoder.closure(List.of(node, node));
        var keys = closure.stream().map(GhidraDataTypeEncoder::keyOf).toList();

        assertEquals("no key appears twice", keys.size(), keys.stream().distinct().count());
        assertTrue(keys.contains(new TypeKey("", "Node", Kind.STRUCT)));
        assertTrue(keys.contains(new TypeKey("", "Node *", Kind.POINTER)));
        assertTrue(keys.contains(new TypeKey("", "int", Kind.BASE)));
    }

    @Test
    public void structsKeepGrowingMembersInOffsetOrder() {
        Structure struct = new StructureDataType("Ordered", 0);
        struct.add(new CharDataType(), "a", null);
        struct.add(new IntegerDataType(), "b", null);

        var closure = GhidraDataTypeEncoder.closure(List.of(struct));
        var updated = (ai.reveng.model.UpdateStructDataType) instanceOfUpdate(struct, idsFor(closure));
        var members = updated.getDefinition().getMembers();

        assertEquals(Long.valueOf(0), members.get(0).getOffset());
        assertEquals(Long.valueOf(1), members.get(1).getOffset());
    }
}

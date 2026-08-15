package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.AnalysisDataTypesService.TypeKey;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType.Kind;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;

import javax.annotation.Nullable;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/// Turns Ghidra data types into the v3 create/update bodies, the mirror of
/// {@link ServerDataTypeDecoder}.
///
/// Decoding resolves references by `data_type_id`, so encoding has to produce them. A Ghidra type
/// carries no server id, so the identity used on the way out is the one the server files types
/// under — `(namespace, name, kind)`, a {@link TypeKey} — and every reference between types is
/// emitted by looking the referenced type's key up in a map of already-known ids. Minting those ids
/// is {@link AnalysisDataTypesService}'s job; this class only ever reads them.
///
/// `namespace` is the inverse of the decoder's category path: a type at the root category encodes
/// as the empty namespace, which is what a locally authored Ghidra type gets, and a type the plugin
/// pulled from the server round-trips back to the namespace it arrived with.
///
/// The derived namespace is what a type is *looked up* by. What it is *written* under is a separate
/// decision, because a Ghidra category is not only ever a server namespace — a type out of one of
/// Ghidra's own archives sits in a category named after that archive and never came from the server
/// at all. {@link AnalysisDataTypesService} makes that call and passes the namespace in; the
/// overloads without one keep the derived value.
public final class GhidraDataTypeEncoder {

    /// Upper bound on transitive dependency resolution, so a pathological type graph cannot make a
    /// reactive push walk forever. Also keeps a single push well inside the endpoints' batch limits.
    private static final int MAX_TYPES = 500;

    /// Ghidra's placeholders for "no calling convention recorded", which the API would rather not
    /// have at all than have as a literal.
    private static final Set<String> UNSET_CALLING_CONVENTIONS = Set.of(
            Function.UNKNOWN_CALLING_CONVENTION_STRING, Function.DEFAULT_CALLING_CONVENTION_STRING);

    private GhidraDataTypeEncoder() {}

    /// Resolves a referenced type to the analysis' id for it. Absent ids encode as an omitted
    /// reference, which the API reads as "unresolved" rather than as an error.
    @FunctionalInterface
    public interface Ids {
        @Nullable
        Long idOf(TypeKey key);

        static Ids of(Map<TypeKey, Long> ids) {
            return ids::get;
        }
    }

    /// Every type reachable from a function's signature and variables: its return type, its
    /// parameters, its stack variables, and everything those reach transitively.
    ///
    /// This is the root set of a type push — the closure has to be resolved to ids before the
    /// signature that names them can be written.
    public static List<DataType> reachableTypes(Function function) {
        return closure(roots(function));
    }

    /// The names of every type {@link #reachableTypes} finds, for deciding which functions a local
    /// edit to a named type affects.
    public static Set<String> referencedTypeNames(Function function) {
        Set<String> names = new LinkedHashSet<>();
        for (DataType type : reachableTypes(function)) {
            names.add(type.getName());
        }
        return names;
    }

    /// Close `roots` over their dependencies, de-duplicated by {@link TypeKey} because that is the
    /// identity the server stores: two Ghidra instances of the same key are one server type.
    ///
    /// Dependencies come after the type that needs them where the graph allows it, but the order is
    /// not load-bearing — references are written as ids, which are all known before any definition
    /// is built.
    public static List<DataType> closure(Collection<DataType> roots) {
        Map<TypeKey, DataType> seen = new LinkedHashMap<>();
        Deque<DataType> queue = new ArrayDeque<>();
        for (DataType root : roots) {
            if (root != null) {
                queue.add(root);
            }
        }
        while (!queue.isEmpty() && seen.size() < MAX_TYPES) {
            DataType type = queue.poll();
            if (type == null || seen.putIfAbsent(keyOf(type), type) != null) {
                continue;
            }
            queue.addAll(dependenciesOf(type));
        }
        return List.copyOf(seen.values());
    }

    /// The server's identity for a Ghidra type.
    public static TypeKey keyOf(DataType type) {
        return new TypeKey(namespaceOf(type), nameOf(type), kindOf(type));
    }

    /// The `kind` discriminator for a Ghidra type.
    ///
    /// The structural interfaces are tested before the "no length" fallback because a
    /// {@link FunctionDefinition} reports a length of -1 while still being a fully modelled type.
    public static Kind kindOf(@Nullable DataType type) {
        if (type == null || Undefined.isUndefined(type)) {
            return Kind.UNKNOWN;
        }
        if (type instanceof TypeDef) {
            return Kind.TYPEDEF;
        }
        if (type instanceof Pointer) {
            return Kind.POINTER;
        }
        if (type instanceof Array) {
            return Kind.ARRAY;
        }
        if (type instanceof Enum) {
            return Kind.ENUM;
        }
        if (type instanceof Structure) {
            return Kind.STRUCT;
        }
        if (type instanceof Union) {
            return Kind.UNION;
        }
        if (type instanceof FunctionDefinition) {
            return Kind.FUNCTION_DEFINITION;
        }
        if (type.getLength() < 0) {
            return Kind.UNKNOWN;
        }
        return Kind.BASE;
    }

    /// A create body for one type, carrying no definition worth the name.
    ///
    /// A `Create*` variant has no `data_type_id`, so nothing in the same batch can be pointed at:
    /// the definitions are deliberately left empty here and filled in by
    /// {@link #updateEntry(DataType, long, Ids)} once the server has assigned ids.
    public static ai.reveng.model.CreateDataTypeEntry createEntry(DataType type) {
        return createEntry(type, namespaceOf(type));
    }

    /// As {@link #createEntry(DataType)}, but filed under `namespace` rather than under the one the
    /// type's category path implies.
    public static ai.reveng.model.CreateDataTypeEntry createEntry(DataType type, String namespace) {
        Long size = sizeOf(type);
        String name = nameOf(type);
        return new ai.reveng.model.CreateDataTypeEntry(switch (kindOf(type)) {
            case STRUCT -> new ai.reveng.model.CreateStructDataType()
                    .kind(ai.reveng.model.CreateStructDataType.KindEnum.STRUCT)
                    .name(name).namespace(namespace).size(size)
                    .definition(new ai.reveng.model.StructDefinition().members(List.of()));
            case UNION -> new ai.reveng.model.CreateUnionDataType()
                    .kind(ai.reveng.model.CreateUnionDataType.KindEnum.UNION)
                    .name(name).namespace(namespace).size(size)
                    .definition(new ai.reveng.model.UnionDefinition().members(List.of()));
            case ENUM -> new ai.reveng.model.CreateEnumDataType()
                    .kind(ai.reveng.model.CreateEnumDataType.KindEnum.ENUM)
                    .name(name).namespace(namespace).size(size)
                    .definition(new ai.reveng.model.EnumDefinition().values(List.of()));
            case TYPEDEF -> new ai.reveng.model.CreateTypedefDataType()
                    .kind(ai.reveng.model.CreateTypedefDataType.KindEnum.TYPEDEF)
                    .name(name).namespace(namespace).size(size)
                    .definition(new ai.reveng.model.TypedefDefinition());
            case POINTER -> new ai.reveng.model.CreatePointerDataType()
                    .kind(ai.reveng.model.CreatePointerDataType.KindEnum.POINTER)
                    .name(name).namespace(namespace).size(size)
                    .definition(new ai.reveng.model.PointerDefinition());
            case ARRAY -> new ai.reveng.model.CreateArrayDataType()
                    .kind(ai.reveng.model.CreateArrayDataType.KindEnum.ARRAY)
                    .name(name).namespace(namespace).size(size)
                    .definition(new ai.reveng.model.ArrayDefinition());
            case FUNCTION_DEFINITION -> new ai.reveng.model.CreateFunctionDataType()
                    .kind(ai.reveng.model.CreateFunctionDataType.KindEnum.FUNCTION_DEFINITION)
                    .name(name).namespace(namespace).size(size)
                    .definition(new ai.reveng.model.FunctionTypeDefinition().parameters(List.of()));
            // These kinds carry no definition at all, so creating them completes in one request.
            case BITFIELD -> new ai.reveng.model.CreateBitfieldDataType()
                    .kind(ai.reveng.model.CreateBitfieldDataType.KindEnum.BITFIELD)
                    .name(name).namespace(namespace).size(size);
            case BASE -> new ai.reveng.model.CreateBaseDataType()
                    .kind(ai.reveng.model.CreateBaseDataType.KindEnum.BASE)
                    .name(name).namespace(namespace).size(size);
            case UNKNOWN -> new ai.reveng.model.CreateUnknownDataType()
                    .kind(ai.reveng.model.CreateUnknownDataType.KindEnum.UNKNOWN)
                    .name(name).namespace(namespace).size(size);
        });
    }

    /// An update body for one type, with every reference resolved through `ids`.
    ///
    /// Empty for a type whose Ghidra form says nothing the server does not already have: the kinds
    /// that never carry a definition, and a composite or reference type that is locally a bare
    /// placeholder. `PUT` replaces a stored type in full, so writing an empty definition would
    /// erase whatever the server extracted; a push that has nothing to say says nothing.
    public static Optional<ai.reveng.model.UpdateDataTypeEntry> updateEntry(DataType type, long id, Ids ids) {
        return updateEntry(type, namespaceOf(type), id, ids);
    }

    /// As {@link #updateEntry(DataType, long, Ids)}, but filed under `namespace` rather than under
    /// the one the type's category path implies. `PUT` replaces a stored type in full, so this has
    /// to be the namespace the entry `id` already lives at — otherwise the update would move it.
    public static Optional<ai.reveng.model.UpdateDataTypeEntry> updateEntry(DataType type,
                                                                            String namespace,
                                                                            long id,
                                                                            Ids ids) {
        Long size = sizeOf(type);
        String name = nameOf(type);
        return switch (kindOf(type)) {
            case STRUCT -> {
                List<ai.reveng.model.DataTypeMemberEntry> members = membersOf((Composite) type, false, ids);
                yield members.isEmpty() ? Optional.empty() : Optional.of(new ai.reveng.model.UpdateDataTypeEntry(
                        new ai.reveng.model.UpdateStructDataType()
                                .kind(ai.reveng.model.UpdateStructDataType.KindEnum.STRUCT)
                                .dataTypeId(id).name(name).namespace(namespace).size(size)
                                .definition(new ai.reveng.model.StructDefinition().members(members))));
            }
            case UNION -> {
                List<ai.reveng.model.DataTypeMemberEntry> members = membersOf((Composite) type, true, ids);
                yield members.isEmpty() ? Optional.empty() : Optional.of(new ai.reveng.model.UpdateDataTypeEntry(
                        new ai.reveng.model.UpdateUnionDataType()
                                .kind(ai.reveng.model.UpdateUnionDataType.KindEnum.UNION)
                                .dataTypeId(id).name(name).namespace(namespace).size(size)
                                .definition(new ai.reveng.model.UnionDefinition().members(members))));
            }
            case ENUM -> {
                List<ai.reveng.model.DataTypeEnumValueEntry> values = valuesOf((Enum) type);
                yield values.isEmpty() ? Optional.empty() : Optional.of(new ai.reveng.model.UpdateDataTypeEntry(
                        new ai.reveng.model.UpdateEnumDataType()
                                .kind(ai.reveng.model.UpdateEnumDataType.KindEnum.ENUM)
                                .dataTypeId(id).name(name).namespace(namespace).size(size)
                                .definition(new ai.reveng.model.EnumDefinition().values(values))));
            }
            case TYPEDEF -> {
                Long target = ids.idOf(keyOf(((TypeDef) type).getDataType()));
                yield target == null ? Optional.empty() : Optional.of(new ai.reveng.model.UpdateDataTypeEntry(
                        new ai.reveng.model.UpdateTypedefDataType()
                                .kind(ai.reveng.model.UpdateTypedefDataType.KindEnum.TYPEDEF)
                                .dataTypeId(id).name(name).namespace(namespace).size(size)
                                .definition(new ai.reveng.model.TypedefDefinition().targetDataTypeId(target))));
            }
            case POINTER -> {
                // A null pointee is `void *`, which has nothing to resolve and nothing to write.
                DataType pointee = ((Pointer) type).getDataType();
                Long target = pointee == null ? null : ids.idOf(keyOf(pointee));
                yield target == null ? Optional.empty() : Optional.of(new ai.reveng.model.UpdateDataTypeEntry(
                        new ai.reveng.model.UpdatePointerDataType()
                                .kind(ai.reveng.model.UpdatePointerDataType.KindEnum.POINTER)
                                .dataTypeId(id).name(name).namespace(namespace).size(size)
                                .definition(new ai.reveng.model.PointerDefinition().pointeeDataTypeId(target))));
            }
            case ARRAY -> {
                Array array = (Array) type;
                Long element = ids.idOf(keyOf(array.getDataType()));
                yield element == null ? Optional.empty() : Optional.of(new ai.reveng.model.UpdateDataTypeEntry(
                        new ai.reveng.model.UpdateArrayDataType()
                                .kind(ai.reveng.model.UpdateArrayDataType.KindEnum.ARRAY)
                                .dataTypeId(id).name(name).namespace(namespace).size(size)
                                .definition(new ai.reveng.model.ArrayDefinition()
                                        .count((long) array.getNumElements())
                                        .elementDataTypeId(element))));
            }
            case FUNCTION_DEFINITION -> {
                FunctionDefinition definition = (FunctionDefinition) type;
                List<ai.reveng.model.DataTypeFunctionParameterEntry> parameters = parametersOf(definition, ids);
                Long returnType = ids.idOf(keyOf(definition.getReturnType()));
                yield parameters.isEmpty() && returnType == null
                        ? Optional.empty()
                        : Optional.of(new ai.reveng.model.UpdateDataTypeEntry(
                                new ai.reveng.model.UpdateFunctionDataType()
                                        .kind(ai.reveng.model.UpdateFunctionDataType.KindEnum.FUNCTION_DEFINITION)
                                        .dataTypeId(id).name(name).namespace(namespace).size(size)
                                        .definition(new ai.reveng.model.FunctionTypeDefinition()
                                                .parameters(parameters)
                                                .returnDataTypeId(returnType))));
            }
            // Nothing beyond name, namespace and size, all of which the create already carried.
            case BASE, BITFIELD, UNKNOWN -> Optional.empty();
        };
    }

    /// The function's local signature as a signature update, with every type named by id.
    ///
    /// `PUT .../signature` replaces the stored signature in full, so parameter storage is carried
    /// over as well: leaving it out would clear the storage the server extracted.
    public static ai.reveng.model.UpdateFunctionSignatureInputBody signatureOf(Function function, Ids ids) {
        var body = new ai.reveng.model.UpdateFunctionSignatureInputBody();

        String callingConvention = function.getCallingConventionName();
        if (callingConvention != null && !callingConvention.isBlank()
                && !UNSET_CALLING_CONVENTIONS.contains(callingConvention)) {
            body.setCallingConvention(callingConvention);
        }

        List<ai.reveng.model.SignatureParameterInput> parameters = new ArrayList<>();
        Parameter[] declared = function.getParameters();
        for (int ordinal = 0; ordinal < declared.length; ordinal++) {
            Parameter parameter = declared[ordinal];
            var input = new ai.reveng.model.SignatureParameterInput()
                    .ordinal((long) ordinal)
                    .name(parameter.getName())
                    .dataTypeId(ids.idOf(keyOf(parameter.getDataType())))
                    .bitLength(Math.max(0, parameter.getLength()) * 8L);
            storageOf(parameter).ifPresent(input::storage);
            parameters.add(input);
        }
        body.setParameters(parameters);
        body.setReturnDataTypeId(ids.idOf(keyOf(function.getReturnType())));
        return body;
    }

    /// Convenience overload for callers holding the id map {@link AnalysisDataTypesService#ensure}
    /// returned.
    public static ai.reveng.model.UpdateFunctionSignatureInputBody signatureOf(Function function,
                                                                              Map<TypeKey, Long> ids) {
        return signatureOf(function, Ids.of(ids));
    }

    private static List<DataType> roots(Function function) {
        List<DataType> roots = new ArrayList<>();
        roots.add(function.getReturnType());
        for (Parameter parameter : function.getParameters()) {
            roots.add(parameter.getDataType());
        }
        for (Variable variable : function.getLocalVariables()) {
            if (variable.isStackVariable()) {
                roots.add(variable.getDataType());
            }
        }
        return roots;
    }

    /// The types one type refers to. A pointer's pointee and an array's element count as
    /// dependencies because they are types in their own right on the server, each with its own id.
    private static List<DataType> dependenciesOf(DataType type) {
        List<DataType> dependencies = new ArrayList<>();
        switch (kindOf(type)) {
            case STRUCT, UNION -> {
                for (DataTypeComponent component : ((Composite) type).getDefinedComponents()) {
                    dependencies.add(memberTypeOf(component));
                }
            }
            case TYPEDEF -> dependencies.add(((TypeDef) type).getDataType());
            case POINTER -> dependencies.add(((Pointer) type).getDataType());
            case ARRAY -> dependencies.add(((Array) type).getDataType());
            case FUNCTION_DEFINITION -> {
                FunctionDefinition definition = (FunctionDefinition) type;
                dependencies.add(definition.getReturnType());
                for (ParameterDefinition parameter : definition.getArguments()) {
                    dependencies.add(parameter.getDataType());
                }
            }
            default -> {
            }
        }
        dependencies.removeIf(java.util.Objects::isNull);
        return dependencies;
    }

    /// A bitfield is expressed on the member rather than as a type of its own, so what the member
    /// points at is the bitfield's base type.
    @Nullable
    private static DataType memberTypeOf(DataTypeComponent component) {
        if (component.getDataType() instanceof BitFieldDataType bitField) {
            return bitField.getBaseDataType();
        }
        return component.getDataType();
    }

    private static List<ai.reveng.model.DataTypeMemberEntry> membersOf(Composite composite,
                                                                      boolean union,
                                                                      Ids ids) {
        boolean bigEndian = isBigEndian(composite);
        List<ai.reveng.model.DataTypeMemberEntry> members = new ArrayList<>();
        for (DataTypeComponent component : composite.getDefinedComponents()) {
            DataType memberType = memberTypeOf(component);
            var member = new ai.reveng.model.DataTypeMemberEntry()
                    // A null field name is legal: it is how unnamed padding is reported.
                    .name(component.getFieldName())
                    .offset(union ? 0L : component.getOffset())
                    .size((long) component.getLength())
                    .dataTypeId(memberType == null ? null : ids.idOf(keyOf(memberType)));
            if (component.getDataType() instanceof BitFieldDataType bitField) {
                member.isBitfield(true)
                        .bitOffset(bitOffsetOf(component, bitField, bigEndian))
                        .bitSize((long) bitField.getBitSize());
            } else {
                member.isBitfield(false);
            }
            members.add(member);
        }
        return members;
    }

    /// The bit offset of a bitfield member from the start of the containing type, which is what the
    /// API asks for.
    ///
    /// Ghidra reports the offset of the least-significant bit within the component's storage unit,
    /// so the two agree only on a little-endian target, where the least-significant bit *is* the
    /// first one. Big-endian fills a storage unit from the most-significant end, so the same field
    /// has to be counted from the other side of the unit: a big-endian `int a:1` at the start of a
    /// struct reports a bit offset of 7, not 0, and successive fields count down rather than up.
    private static long bitOffsetOf(DataTypeComponent component, BitFieldDataType bitField, boolean bigEndian) {
        long withinUnit = bigEndian
                ? component.getLength() * 8L - bitField.getBitOffset() - bitField.getBitSize()
                : bitField.getBitOffset();
        return component.getOffset() * 8L + withinUnit;
    }

    /// A composite with no manager cannot say what it is laid out for; little-endian is both the
    /// commoner case and what Ghidra's own default data organisation assumes.
    private static boolean isBigEndian(Composite composite) {
        var manager = composite.getDataTypeManager();
        return manager != null && manager.getDataOrganization() != null
                && manager.getDataOrganization().isBigEndian();
    }

    /// Enum constants keep their decimal-string form all the way out: a value may be negative or
    /// exceed 64 unsigned bits, so it is never parsed into a number on the wire.
    private static List<ai.reveng.model.DataTypeEnumValueEntry> valuesOf(Enum enumeration) {
        List<ai.reveng.model.DataTypeEnumValueEntry> values = new ArrayList<>();
        for (String name : enumeration.getNames()) {
            values.add(new ai.reveng.model.DataTypeEnumValueEntry()
                    .name(name)
                    .value(Long.toString(enumeration.getValue(name))));
        }
        return values;
    }

    private static List<ai.reveng.model.DataTypeFunctionParameterEntry> parametersOf(FunctionDefinition definition,
                                                                                     Ids ids) {
        List<ai.reveng.model.DataTypeFunctionParameterEntry> parameters = new ArrayList<>();
        ParameterDefinition[] arguments = definition.getArguments();
        for (int ordinal = 0; ordinal < arguments.length; ordinal++) {
            ParameterDefinition argument = arguments[ordinal];
            parameters.add(new ai.reveng.model.DataTypeFunctionParameterEntry()
                    .ordinal((long) ordinal)
                    .size((long) Math.max(0, argument.getLength()))
                    .name(argument.getName())
                    .dataTypeId(ids.idOf(keyOf(argument.getDataType()))));
        }
        return parameters;
    }

    private static Optional<ai.reveng.model.SignatureStorageInput> storageOf(Parameter parameter) {
        VariableStorage storage = parameter.getVariableStorage();
        if (storage == null || !storage.isValid()) {
            return Optional.empty();
        }
        if (storage.isRegisterStorage() && storage.getRegister() != null) {
            return Optional.of(new ai.reveng.model.SignatureStorageInput()
                    .kind("reg").location(storage.getRegister().getName()));
        }
        if (storage.isStackStorage()) {
            return Optional.of(new ai.reveng.model.SignatureStorageInput()
                    .kind("stack").location(Integer.toString(storage.getStackOffset())));
        }
        if (storage.isMemoryStorage()) {
            return Optional.of(new ai.reveng.model.SignatureStorageInput().kind("mem"));
        }
        return Optional.empty();
    }

    /// The scope the server files the type under, as the inverse of
    /// {@link ServerDataTypeDecoder}'s category path. A locally authored type lives at the root
    /// category and so pushes with the empty namespace.
    private static String namespaceOf(@Nullable DataType type) {
        if (type == null) {
            return "";
        }
        CategoryPath path = type.getCategoryPath();
        if (path == null || path.isRoot()) {
            return "";
        }
        return String.join("::", path.getPathElements());
    }

    private static String nameOf(@Nullable DataType type) {
        if (type == null) {
            return "undefined";
        }
        String name = type.getName();
        return name == null || name.isBlank() ? "undefined" : name;
    }

    /// Ghidra reports -1 for a type with no meaningful size (a function definition); the API wants
    /// the field omitted rather than negative.
    @Nullable
    private static Long sizeOf(@Nullable DataType type) {
        if (type == null) {
            return null;
        }
        int length = type.getLength();
        return length < 0 ? null : (long) length;
    }
}

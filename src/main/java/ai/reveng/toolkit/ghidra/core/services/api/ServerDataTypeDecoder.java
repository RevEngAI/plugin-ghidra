package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;
import ai.reveng.toolkit.ghidra.core.services.api.types.TypePathAndName;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.CancelledException;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/// Turns the data types of one analysis into a self-contained Ghidra {@link DataTypeManager}.
///
/// Every type the server reports carries a `data_type_id` that is unique within its analysis, and
/// every reference between types — a struct member's type, a pointer's pointee, a typedef's target,
/// a parameter's type — is expressed as one of those ids. Decoding therefore never has to resolve a
/// type by name, which is what makes this two straightforward passes:
///
///  1. create an empty shell for every composite id (struct, union, enum) and register it;
///  2. resolve every remaining id by lookup, then fill the shells in.
///
/// Cycles resolve on their own: any cycle in a well-formed type graph runs through a composite, and
/// composites already exist by the time pass 2 starts. A degenerate cycle that never reaches one is
/// broken by a recursion guard rather than by retrying until the graph settles.
///
/// The manager and everything in it are transient — they exist to give a decoded signature somewhere
/// to keep its dependencies, exactly as a program's own manager would.
public final class ServerDataTypeDecoder {

    private final StandAloneDataTypeManager dtm;
    private final Map<Long, ServerDataType> source;
    private final Map<Long, DataType> decoded = new HashMap<>();
    private final Set<Long> resolving = new HashSet<>();
    private final DataTypeParser parser;

    private ServerDataTypeDecoder(Collection<ServerDataType> types) {
        this.dtm = new StandAloneDataTypeManager("transient");
        this.parser = new DataTypeParser(dtm, null, null, DataTypeParser.AllowedDataTypes.ALL);
        this.source = new LinkedHashMap<>();
        for (ServerDataType type : types) {
            // A duplicate id can only come from stitching several responses together; the entries
            // are then identical, so keeping the first is enough.
            source.putIfAbsent(type.id(), type);
        }
    }

    /// Decode a whole analysis' worth of types. Order of the input does not matter.
    public static ServerDataTypeDecoder decode(Collection<ServerDataType> types) {
        ServerDataTypeDecoder decoder = new ServerDataTypeDecoder(types);
        decoder.run();
        return decoder;
    }

    public DataTypeManager dataTypeManager() {
        return dtm;
    }

    /// The Ghidra type for a `data_type_id`, or an undefined filler of `fallbackSize` bytes when the
    /// id is absent or names a type the server never defined.
    public DataType typeFor(@Nullable Long dataTypeId, long fallbackSize) {
        if (dataTypeId == null) {
            return undefined(fallbackSize);
        }
        DataType type = decoded.get(dataTypeId);
        return type != null ? type : undefined(fallbackSize);
    }

    private void run() {
        int transaction = dtm.startTransaction("Decode data types");
        try {
            // Pass 1: an empty shell per composite id, so pass 2 always has something to point at.
            for (ServerDataType type : source.values()) {
                switch (type.kind()) {
                    case STRUCT -> put(type.id(), add(new StructureDataType(
                            categoryPath(type), leafName(type), (int) clampSize(type.size()), dtm)));
                    case UNION -> put(type.id(), add(new UnionDataType(
                            categoryPath(type), leafName(type), dtm)));
                    case ENUM -> put(type.id(), add(new EnumDataType(
                            categoryPath(type), leafName(type), enumLength(type.size()), dtm)));
                    default -> {
                    }
                }
            }

            // Pass 2: resolve everything else by id, then populate the shells.
            for (Long id : source.keySet()) {
                resolve(id);
            }
            for (ServerDataType type : source.values()) {
                fill(type);
            }
        } finally {
            dtm.endTransaction(transaction, true);
        }
    }

    private DataType resolve(long id) {
        DataType existing = decoded.get(id);
        if (existing != null) {
            return existing;
        }
        ServerDataType type = source.get(id);
        if (type == null) {
            // Referenced but not shipped: the server only sends the closure it knows about.
            return Undefined1DataType.dataType;
        }
        if (!resolving.add(id)) {
            // Only reachable for a cycle that never passes through a composite, which cannot
            // describe a real type. Break it instead of looping.
            return Undefined1DataType.dataType;
        }
        try {
            DataType built = build(type);
            put(id, built);
            return built;
        } finally {
            resolving.remove(id);
        }
    }

    private DataType build(ServerDataType type) {
        return switch (type.kind()) {
            case TYPEDEF -> {
                Long target = type.definition() instanceof ServerDataType.TypedefDefinition def
                        ? def.targetDataTypeId() : null;
                DataType targetType = target == null ? undefined(type.size()) : resolve(target);
                yield add(new TypedefDataType(categoryPath(type), leafName(type), targetType, dtm));
            }
            case POINTER -> {
                Long pointee = type.definition() instanceof ServerDataType.PointerDefinition def
                        ? def.pointeeDataTypeId() : null;
                // A null pointee is `void *`; a null length lets Ghidra use the manager's default.
                DataType pointeeType = pointee == null ? VoidDataType.dataType : resolve(pointee);
                yield add(new PointerDataType(pointeeType, pointerLength(type.size()), dtm));
            }
            case ARRAY -> {
                ServerDataType.ArrayDefinition def =
                        type.definition() instanceof ServerDataType.ArrayDefinition array ? array : null;
                DataType element = def == null || def.elementDataTypeId() == null
                        ? Undefined1DataType.dataType : resolve(def.elementDataTypeId());
                int count = def == null || def.count() == null ? 0 : (int) clampSize(def.count());
                int elementLength = Math.max(1, element.getLength());
                yield add(new ArrayDataType(element, Math.max(count, 1), elementLength, dtm));
            }
            case FUNCTION_DEFINITION -> {
                FunctionDefinitionDataType definition =
                        new FunctionDefinitionDataType(categoryPath(type), leafName(type), dtm);
                // Registered before its parameters are resolved so a self-referential signature
                // (a function taking a pointer to its own type) terminates.
                put(type.id(), definition);
                if (type.definition() instanceof ServerDataType.FunctionTypeDefinition def) {
                    definition.setArguments(def.parameters().stream()
                            .map(parameter -> new ParameterDefinitionImpl(
                                    parameter.name(),
                                    typeOrResolve(parameter.dataTypeId(), parameter.size()),
                                    null))
                            .toArray(ParameterDefinitionImpl[]::new));
                    definition.setReturnType(def.returnDataTypeId() == null
                            ? VoidDataType.dataType
                            : resolve(def.returnDataTypeId()));
                }
                yield definition;
            }
            // BASE and BITFIELD name a built-in; UNKNOWN is a kind this plugin does not model yet.
            case BASE, BITFIELD, UNKNOWN -> builtIn(type);
            // Composites were created in pass 1, so this is unreachable in practice.
            case STRUCT, UNION, ENUM -> undefined(type.size());
        };
    }

    private void fill(ServerDataType type) {
        DataType target = decoded.get(type.id());
        switch (type.kind()) {
            case STRUCT -> {
                if (target instanceof Structure structure
                        && type.definition() instanceof ServerDataType.StructDefinition def) {
                    def.members().forEach(member -> place(structure, type, member));
                }
            }
            case UNION -> {
                if (target instanceof Union union
                        && type.definition() instanceof ServerDataType.UnionDefinition def) {
                    def.members().forEach(member -> {
                        try {
                            union.add(typeOrResolve(member.dataTypeId(), member.size()),
                                    member.name(), null);
                        } catch (IllegalArgumentException e) {
                            Msg.error(ServerDataTypeDecoder.class, "Skipping union member '%s' of %s: %s"
                                    .formatted(member.name(), type.name(), e.getMessage()));
                        }
                    });
                }
            }
            case ENUM -> {
                if (target instanceof Enum enumeration
                        && type.definition() instanceof ServerDataType.EnumDefinition def) {
                    def.values().forEach(value -> {
                        try {
                            enumeration.add(value.name(), toLong(value.value()));
                        } catch (IllegalArgumentException e) {
                            Msg.error(ServerDataTypeDecoder.class, "Skipping enum value '%s' of %s: %s"
                                    .formatted(value.name(), type.name(), e.getMessage()));
                        }
                    });
                }
            }
            default -> {
            }
        }
    }

    private void place(Structure structure, ServerDataType owner, ServerDataType.Member member) {
        DataType fieldType = typeOrResolve(member.dataTypeId(), member.size());
        // The server occasionally reports a member that extends past the struct's declared size;
        // grow the struct to fit rather than letting replaceAtOffset reject it and abort the whole
        // type load. A member that still can't be placed is skipped so one bad field doesn't sink
        // the entire signature.
        int offset = (int) clampSize(member.offset());
        int length = (int) Math.max(1, clampSize(member.size()));
        int end = offset + length;
        if (structure.getLength() < end) {
            structure.growStructure(end - structure.getLength());
        }
        try {
            structure.replaceAtOffset(offset, fieldType, length, member.name(), null);
        } catch (IllegalArgumentException e) {
            Msg.error(ServerDataTypeDecoder.class, "Skipping struct member '%s' at offset %d of %s: %s"
                    .formatted(member.name(), offset, owner.name(), e.getMessage()));
        }
    }

    /// Look a built-in up by name, e.g. `int`, `char *`, `unsigned long`. These types have no
    /// definition of their own, so the name is all the server sends.
    private DataType builtIn(ServerDataType type) {
        String name = type.name();
        if (name == null || name.isBlank()) {
            return undefined(type.size());
        }
        try {
            DataType parsed = parser.parse(name);
            if (parsed != null) {
                return parsed;
            }
        } catch (InvalidDataTypeException e) {
            // Not a name Ghidra knows; fall through to a same-sized filler.
        } catch (CancelledException e) {
            throw new RuntimeException(e);
        }
        return undefined(type.size());
    }

    private DataType typeOrResolve(@Nullable Long dataTypeId, long fallbackSize) {
        return dataTypeId == null ? undefined(fallbackSize) : resolve(dataTypeId);
    }

    private DataType add(DataType type) {
        return dtm.addDataType(type, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
    }

    private void put(long id, DataType type) {
        decoded.put(id, type);
    }

    private static CategoryPath categoryPath(ServerDataType type) {
        String namespace = type.namespace();
        if (namespace == null || namespace.isBlank()) {
            return CategoryPath.ROOT;
        }
        return TypePathAndName.fromString(namespace + "::" + leafName(type)).toCategoryPath();
    }

    private static String leafName(ServerDataType type) {
        String name = type.name();
        if (name == null || name.isBlank()) {
            return "anon_%d".formatted(type.id());
        }
        return TypePathAndName.fromString(name).name();
    }

    /// Ghidra sizes are `int`; the API's are `long`. Anything that does not fit is not a real type.
    private static long clampSize(@Nullable Long size) {
        if (size == null || size <= 0) {
            return 0;
        }
        return Math.min(size, Integer.MAX_VALUE);
    }

    /// Ghidra enums must be 1, 2, 4 or 8 bytes wide.
    private static int enumLength(@Nullable Long size) {
        long clamped = clampSize(size);
        if (clamped >= 8) {
            return 8;
        }
        if (clamped >= 4) {
            return 4;
        }
        if (clamped >= 2) {
            return 2;
        }
        return 1;
    }

    /// -1 lets Ghidra use the manager's default pointer size, which is what an unsized pointer means.
    private static int pointerLength(@Nullable Long size) {
        long clamped = clampSize(size);
        return clamped <= 0 || clamped > 8 ? -1 : (int) clamped;
    }

    /// Enum values stay strings on the wire because they may be negative or exceed 64 unsigned bits.
    /// Ghidra can only hold a `long`, so widen through {@link BigInteger} and take the low 64 bits.
    private static long toLong(String value) {
        return new BigInteger(value.trim()).longValue();
    }

    /// An exact-width filler for a type we could not build. Ghidra only has undefined1/2/4/8, so
    /// anything else becomes an array of undefined1 to keep the surrounding layout intact.
    private static DataType undefined(long size) {
        long clamped = clampSize(size);
        if (clamped == 1 || clamped == 2 || clamped == 4 || clamped == 8) {
            return Undefined.getUndefinedDataType((int) clamped);
        }
        if (clamped <= 0) {
            return Undefined1DataType.dataType;
        }
        return new ArrayDataType(Undefined1DataType.dataType, (int) clamped, 1);
    }

    /// Build the signature of a function from its server entry, with every referenced type taken
    /// from this decoder's manager so the result is self-contained.
    public FunctionDefinitionDataType signature(String functionName,
                                                @Nullable Long returnDataTypeId,
                                                List<ai.reveng.model.SignatureParameterEntry> parameters) {
        FunctionDefinitionDataType definition = new FunctionDefinitionDataType(functionName, dtm);
        try {
            definition.setName(functionName);
        } catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }
        if (parameters != null) {
            definition.setArguments(parameters.stream()
                    .map(parameter -> new ParameterDefinitionImpl(
                            parameter.getName(),
                            typeFor(parameter.getDataTypeId(), bytesOf(parameter.getBitLength())),
                            null))
                    .toArray(ParameterDefinitionImpl[]::new));
        }
        definition.setReturnType(returnDataTypeId == null
                ? VoidDataType.dataType
                : typeFor(returnDataTypeId, 0));
        return definition;
    }

    private static long bytesOf(@Nullable Long bitLength) {
        return bitLength == null ? 0 : Math.max(0, bitLength / 8);
    }
}

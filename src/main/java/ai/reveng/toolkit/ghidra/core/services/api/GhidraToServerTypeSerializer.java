package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.model.FunctionArgument;
import ai.reveng.model.FunctionDependency;
import ai.reveng.model.FunctionHeader;
import ai.reveng.model.FunctionInfo;
import ai.reveng.model.FunctionStackVariable;
import ai.reveng.model.FunctionType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Serialises a Ghidra {@link Function}'s signature and variables into the server's data-type blob
 * ({@link FunctionInfo}) so local edits can be pushed back to the portal. This is the inverse of
 * {@link GhidraRevengService#getFunctionSignature}.
 *
 * <p>Mirrors the IDA plugin's {@code variable_sync_service._build_function_info} /
 * {@code _collect_func_deps}: the header carries the return type and arguments (keyed by ordinal),
 * stack variables are keyed by stack offset, and custom types referenced by any of these are
 * emitted as {@link FunctionDependency} entries (structs, unions, enums, typedefs), resolved
 * transitively.
 */
public final class GhidraToServerTypeSerializer {

    /// Upper bound on transitive dependency resolution, matching the IDA plugin's guard.
    private static final int MAX_DEPENDENCIES = 500;

    private GhidraToServerTypeSerializer() {}

    public static FunctionInfo buildFunctionInfo(Function function, long imageBase) {
        long addr = function.getEntryPoint().getOffset() - imageBase;
        String returnType = typeName(function.getReturnType());

        Map<String, FunctionArgument> args = new LinkedHashMap<>();
        Parameter[] parameters = function.getParameters();
        for (int i = 0; i < parameters.length; i++) {
            var parameter = parameters[i];
            long offset = i;
            args.put(Long.toHexString(offset), new FunctionArgument()
                    .offset(offset)
                    .name(parameter.getName())
                    .type(typeName(parameter.getDataType()))
                    .size((long) parameter.getLength()));
        }

        var header = new FunctionHeader()
                .name(function.getName())
                .addr(addr)
                .type(returnType)
                .args(args);

        Map<String, FunctionStackVariable> stackVars = new LinkedHashMap<>();
        for (Variable variable : function.getLocalVariables()) {
            if (!variable.isStackVariable()) {
                continue;
            }
            long offset = variable.getStackOffset();
            stackVars.put(Long.toHexString(offset), new FunctionStackVariable()
                    .offset(offset)
                    .name(variable.getName())
                    .type(typeName(variable.getDataType()))
                    .size((long) variable.getLength())
                    .addr(addr));
        }

        var funcType = new FunctionType()
                .addr(addr)
                .size(function.getBody().getNumAddresses())
                .header(header)
                .stackVars(stackVars)
                .name(function.getName())
                .type(returnType)
                .artifactType("Function");

        return new FunctionInfo()
                .funcTypes(funcType)
                .funcDeps(collectDependencies(function));
    }

    private static List<FunctionDependency> collectDependencies(Function function) {
        Deque<DataType> queue = new ArrayDeque<>();
        queue.add(function.getReturnType());
        for (Parameter parameter : function.getParameters()) {
            queue.add(parameter.getDataType());
        }
        for (Variable variable : function.getLocalVariables()) {
            if (variable.isStackVariable()) {
                queue.add(variable.getDataType());
            }
        }

        Map<String, FunctionDependency> deps = new LinkedHashMap<>();
        int guard = 0;
        while (!queue.isEmpty() && guard++ < MAX_DEPENDENCIES) {
            DataType base = baseType(queue.poll());
            if (base == null) {
                continue;
            }
            String name = base.getName();
            if (deps.containsKey(name)) {
                continue;
            }
            var dependency = toDependency(base, queue);
            if (dependency != null) {
                deps.put(name, dependency);
            }
        }
        return new ArrayList<>(deps.values());
    }

    /// Emits a dependency for custom types and enqueues nested types to resolve; returns null for
    /// primitives and built-ins, which the server already knows.
    private static FunctionDependency toDependency(DataType type, Deque<DataType> queue) {
        if (type instanceof Structure || type instanceof Union) {
            var composite = (ghidra.program.model.data.Composite) type;
            Map<String, Object> members = new LinkedHashMap<>();
            for (DataTypeComponent component : composite.getDefinedComponents()) {
                queue.add(component.getDataType());
                Map<String, Object> member = new LinkedHashMap<>();
                member.put("name", component.getFieldName());
                member.put("offset", (long) component.getOffset());
                member.put("type", typeName(component.getDataType()));
                member.put("size", (long) component.getLength());
                members.put(Long.toHexString(component.getOffset()), member);
            }
            return new FunctionDependency()
                    .name(type.getName())
                    .size((long) type.getLength())
                    .members(members)
                    .artifactType("Struct");
        }
        if (type instanceof Enum enumType) {
            Map<String, Object> members = new LinkedHashMap<>();
            for (String memberName : enumType.getNames()) {
                members.put(memberName, enumType.getValue(memberName));
            }
            return new FunctionDependency()
                    .name(type.getName())
                    .size((long) type.getLength())
                    .members(members)
                    .artifactType("Enum");
        }
        if (type instanceof TypeDef typeDef) {
            queue.add(typeDef.getDataType());
            return new FunctionDependency()
                    .name(type.getName())
                    .type(typeName(typeDef.getDataType()))
                    .artifactType("Typedef");
        }
        return null;
    }

    /// Unwraps pointer and array decoration to reach the underlying named type.
    static DataType baseType(DataType type) {
        DataType current = type;
        while (true) {
            if (current instanceof Pointer pointer) {
                current = pointer.getDataType();
            } else if (current instanceof Array array) {
                current = array.getDataType();
            } else {
                return current;
            }
        }
    }

    /// Server type string, including pointer/array decoration (e.g. {@code "MyStruct *"}).
    static String typeName(DataType type) {
        return type == null ? "undefined" : type.getName();
    }
}

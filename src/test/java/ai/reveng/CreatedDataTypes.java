package ai.reveng;

import ai.reveng.model.CreateAnalysisDataTypesInputBody;
import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataType;

import java.util.List;
import java.util.function.LongSupplier;

/// What a mock server answers a data-type create with: each type as it was sent, under a new id.
///
/// The answer has to name the types it was asked for. A push resolves every type a signature names
/// through the created types' `(namespace, name, kind)`, and a signature with a type it cannot
/// resolve is not sent.
final class CreatedDataTypes {

    private CreatedDataTypes() {}

    static List<ServerDataType> echo(CreateAnalysisDataTypesInputBody request, LongSupplier nextId) {
        return request.getDataTypes().stream()
                .map(entry -> {
                    Object instance = entry.getActualInstance();
                    return new ServerDataType(nextId.getAsLong(), string(instance, "getNamespace"),
                            string(instance, "getName"),
                            ServerDataType.Kind.fromJson(string(instance, "getKind")),
                            null, "USER", false, null, null, null);
                })
                .toList();
    }

    private static String string(Object target, String method) {
        try {
            Object value = target.getClass().getMethod(method).invoke(target);
            return value == null ? null : value.toString();
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }
}

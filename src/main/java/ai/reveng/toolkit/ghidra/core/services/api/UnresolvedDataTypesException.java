package ai.reveng.toolkit.ghidra.core.services.api;

import java.util.Set;

/// A function's types could not all be given a portal id, so its signature was not written.
///
/// Sending the signature anyway would name the missing types as null, and the portal replaces a
/// stored signature in full, so it would lose the types it had. The edit is held back instead and
/// stays unpushed. {@link PushFailure} classifies this as {@link PushFailure#REJECTED}: sending the
/// same edit again gets the same answer.
public final class UnresolvedDataTypesException extends Exception {

    private final Set<String> typeNames;

    public UnresolvedDataTypesException(Set<String> typeNames) {
        super(describe(typeNames));
        this.typeNames = Set.copyOf(typeNames);
    }

    public Set<String> typeNames() {
        return typeNames;
    }

    private static String describe(Set<String> typeNames) {
        final int shown = 5;
        String names = typeNames.stream().limit(shown).map("\"%s\""::formatted)
                .collect(java.util.stream.Collectors.joining(", "));
        if (typeNames.size() > shown) {
            names += " and %d more".formatted(typeNames.size() - shown);
        }
        return "no portal id for the data type(s) %s, so the signature was not sent".formatted(names);
    }
}

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
    private final boolean pastClosureLimit;

    /// @param typeNames        the types the function reaches that could not be written in full
    /// @param pastClosureLimit whether the function reaches more types than
    ///                         {@link GhidraDataTypeEncoder#MAX_TYPES}, which is then the cause
    ///                         rather than the portal
    public UnresolvedDataTypesException(Set<String> typeNames, boolean pastClosureLimit) {
        super(pastClosureLimit ? describeLimit() : describe(typeNames));
        this.typeNames = Set.copyOf(typeNames);
        this.pastClosureLimit = pastClosureLimit;
    }

    public Set<String> typeNames() {
        return typeNames;
    }

    public boolean pastClosureLimit() {
        return pastClosureLimit;
    }

    private static String describeLimit() {
        return ("it reaches more than %d data types, the most the plugin pushes for one function, so "
                + "the signature was not sent").formatted(GhidraDataTypeEncoder.MAX_TYPES);
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

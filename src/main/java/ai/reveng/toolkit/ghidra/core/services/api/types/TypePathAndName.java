package ai.reveng.toolkit.ghidra.core.services.api.types;

import ghidra.program.model.data.CategoryPath;

/// A scoped type name split into its Ghidra {@link CategoryPath} and its leaf name.
///
/// The server reports a type's scope in a `namespace` field, using `::` as the separator, e.g.
/// `stdint`, `DWARF::stdio.h` or the empty string for the root scope. Ghidra models the same idea
/// as a {@link CategoryPath}, so this splits one into the other.
public record TypePathAndName(
        String name,
        String[] path
) {

    /// Takes strings like:
    ///
    /// - "uint32_t"
    /// - "stdint::uint32_t"
    /// - "DWARF::stdio.h::off_t"
    public static TypePathAndName fromString(String str){
        // split into path and name on "::"
        if (str.contains("::")) {
            String[] pathPlusType = str.split("::");
            var baseType = pathPlusType[pathPlusType.length - 1];

            String[] parts = new String[pathPlusType.length - 1];
            System.arraycopy(pathPlusType, 0, parts, 0, pathPlusType.length - 1);
            return new TypePathAndName(baseType, parts);
        } else {
            return new TypePathAndName(str, new String[0]);
        }
    }

    public CategoryPath toCategoryPath(){
        return (path.length != 0) ? new CategoryPath(CategoryPath.ROOT, path) : CategoryPath.ROOT;
    }

}

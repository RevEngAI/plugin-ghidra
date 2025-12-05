package ai.reveng.toolkit.ghidra.core.services.api.types.binsync;

import ghidra.program.model.data.CategoryPath;

public record TypePathAndName(
        String name,
        String[] path
) {



    /// based on `ArtifactLifter.parse_scoped_type` from binsync
    /// Takes strings like:
    ///
    /// - "uint32_t"
    /// - "stdint::uint32_t"
    /// - "DWARF::stdio.h::off_t"
    /// @param str
    /// @return
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

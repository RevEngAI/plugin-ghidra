package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class TypePathAndNameTest {

    @Test
    public void fromString_splitsTheNamespacePathFromTheName() {
        var path = TypePathAndName.fromString("a::b::c");

        assertEquals("the name is the last segment", "c", path.name());
        assertArrayEquals("the leading segments are the path", new String[]{"a", "b"}, path.path());
    }

    @Test
    public void fromString_leavesAnUnqualifiedNameWithAnEmptyPath() {
        var path = TypePathAndName.fromString("PlainName");

        assertEquals("PlainName", path.name());
        assertArrayEquals("an unqualified name has no path segments", new String[]{}, path.path());
    }
}

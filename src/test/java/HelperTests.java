import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.TypePathAndName;
import org.junit.Test;

public class HelperTests {


    @Test
    public void testPathSplitting(){
        var path = TypePathAndName.fromString("a::b::c");
        assert path.name().equals("c");
        assert path.path().length == 2;
        assert path.path()[0].equals("a");
        assert path.path()[1].equals("b");
    }

    @Test
    public void testPathSplittingNoPath(){
        var path = TypePathAndName.fromString("PlainName");
        assert path.name().equals("PlainName");
        assert path.path().length == 0;
    }
}

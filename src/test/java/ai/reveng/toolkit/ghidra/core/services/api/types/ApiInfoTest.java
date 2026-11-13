package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.junit.Test;

import java.net.URI;

import static org.junit.Assert.assertEquals;

public class ApiInfoTest {

    @Test
    public void normaliseHost_addsHttpsWhenSchemeIsMissing() {
        assertEquals("https://api.reveng.ai:8443", ApiInfo.normaliseHost("api.reveng.ai:8443"));
    }

    @Test
    public void normaliseHost_trimsWhitespace() {
        assertEquals("https://api.reveng.ai", ApiInfo.normaliseHost("  https://api.reveng.ai \t"));
    }

    @Test
    public void normaliseHost_stripsTrailingSlashes() {
        assertEquals("https://api.reveng.ai", ApiInfo.normaliseHost("https://api.reveng.ai//"));
    }

    @Test
    public void normaliseHost_keepsAnExplicitScheme() {
        assertEquals("http://localhost:8080", ApiInfo.normaliseHost("http://localhost:8080"));
    }

    @Test
    public void normaliseHost_leavesBlankInputEmpty() {
        assertEquals("", ApiInfo.normaliseHost("  "));
    }

    @Test
    public void stringConstructor_normalisesBothHosts() {
        var info = new ApiInfo(" api.reveng.ai/ ", "portal.reveng.ai/", "key");

        assertEquals(URI.create("https://api.reveng.ai"), info.hostURI());
        assertEquals(URI.create("https://portal.reveng.ai"), info.portalURI());
    }
}

package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.invoker.JSON;
import ai.reveng.model.FunctionDetailsOutputBody;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionDetails;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Covers {@link FunctionDetails#fromServerResponse}, which maps the body of
 * {@code GET /v3/functions/{function_id}} onto the plugin's own record. Each case is driven
 * through the generated {@link FunctionDetailsOutputBody} so the SDK's own deserialisation,
 * including its required-field validation, is exercised alongside the mapping.
 */
public class FunctionDetailsMappingTest {

    private static FunctionDetails map(String json) {
        return FunctionDetails.fromServerResponse(
                JSON.getGson().fromJson(json, FunctionDetailsOutputBody.class));
    }

    private static final String FULL_BODY = """
            {
              "analysis_id": 4321,
              "binary_id": 99,
              "creation": "2026-01-02T03:04:05Z",
              "debug": true,
              "function_id": 1234,
              "function_name": "demangled_name",
              "function_size": 256,
              "function_vaddr": 16384,
              "mangled_name": "_Z15mangled_namev",
              "source_function_id": 7
            }""";

    @Test
    public void mapsEveryFieldThePluginReads() {
        FunctionDetails details = map(FULL_BODY);

        assertEquals(1234L, details.functionId().value());
        assertEquals("_Z15mangled_namev", details.mangledFunctionName());
        assertEquals("demangled_name", details.demangledName());
        assertEquals(Long.valueOf(16384L), details.functionVaddr());
        assertEquals(Long.valueOf(256L), details.functionSize());
        assertEquals(4321, details.analysisId().id());
    }

    @Test
    public void mangledNameIsOptional() {
        FunctionDetails details = map("""
                {
                  "analysis_id": 4321,
                  "binary_id": 99,
                  "creation": "2026-01-02T03:04:05Z",
                  "debug": false,
                  "function_id": 1234,
                  "function_name": "demangled_name",
                  "function_size": 256,
                  "function_vaddr": 16384
                }""");

        assertNull(details.mangledFunctionName());
        assertEquals("demangled_name", details.demangledName());
    }

    @Test
    public void functionIdSurvivesValuesAboveTheIntRange() {
        FunctionDetails details = map(FULL_BODY.replace("\"function_id\": 1234", "\"function_id\": 4294967296"));

        assertEquals(4294967296L, details.functionId().value());
    }
}

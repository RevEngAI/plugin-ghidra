package ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler;

import ai.reveng.model.AIDecompFunctionMapping;
import ai.reveng.model.ReplacementValue;
import ai.reveng.model.TokenisedData;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Unit tests for the identifier → token resolution that backs the "rename variable/type" edit,
 * mirroring the IDA plugin's {@code resolve_token} / {@code index_of_identifier}.
 */
public class AIDecompTokenResolutionTest {

    @Test
    public void indexOfIdentifier_returnsPositionAmongIdentifiers() {
        String line = "int result = compute(value);";
        assertEquals(0, AIDecompilationdWindow.indexOfIdentifier(line, "int"));
        assertEquals(1, AIDecompilationdWindow.indexOfIdentifier(line, "result"));
        assertEquals(2, AIDecompilationdWindow.indexOfIdentifier(line, "compute"));
        assertEquals(3, AIDecompilationdWindow.indexOfIdentifier(line, "value"));
    }

    @Test
    public void indexOfIdentifier_returnsFirstOccurrence() {
        assertEquals(0, AIDecompilationdWindow.indexOfIdentifier("a = a + b", "a"));
    }

    @Test
    public void indexOfIdentifier_missingWordReturnsMinusOne() {
        assertEquals(-1, AIDecompilationdWindow.indexOfIdentifier("int result = 1;", "missing"));
    }

    @Test
    public void resolveToken_matchesTokenAtSameIdentifierPosition() {
        var mapping = new AIDecompFunctionMapping();
        mapping.setUnmatchedVars(vars(Map.of(
                "TOKEN_A", "result",
                "TOKEN_B", "value")));
        var tokenised = tokenised("int TOKEN_A = compute(TOKEN_B);", mapping);

        // "result" is the identifier at index 1 in the source line.
        assertEquals("TOKEN_A", AIDecompilationdWindow.resolveToken(tokenised, 0, 1, "result"));
        // "value" is the identifier at index 3.
        assertEquals("TOKEN_B", AIDecompilationdWindow.resolveToken(tokenised, 0, 3, "value"));
    }

    @Test
    public void resolveToken_userOverrideTakesPrecedenceOverPredictedValue() {
        var mapping = new AIDecompFunctionMapping();
        mapping.setUnmatchedVars(vars(Map.of("TOKEN_A", "result")));
        mapping.setUserOverrideMappings(Map.of("TOKEN_A", "myResult"));
        var tokenised = tokenised("int TOKEN_A = 1;", mapping);

        // The displayed name is the override, so that is what the user double-clicks.
        assertEquals("TOKEN_A", AIDecompilationdWindow.resolveToken(tokenised, 0, 1, "myResult"));
        // The stale predicted value no longer resolves.
        assertNull(AIDecompilationdWindow.resolveToken(tokenised, 0, 1, "result"));
    }

    @Test
    public void resolveToken_resolvesTypeCategory() {
        var mapping = new AIDecompFunctionMapping();
        mapping.setUnmatchedCustomTypes(vars(Map.of("TOKEN_T", "MyStruct")));
        var tokenised = tokenised("TOKEN_T *p = 0;", mapping);

        assertEquals("TOKEN_T", AIDecompilationdWindow.resolveToken(tokenised, 0, 0, "MyStruct"));
    }

    @Test
    public void resolveToken_fallsBackToUniqueValueMatchWhenPositionMisses() {
        var mapping = new AIDecompFunctionMapping();
        mapping.setUnmatchedVars(vars(Map.of("TOKEN_X", "foo")));
        // Position lookup misses (identIndex out of range for the tokenised line), but there is
        // exactly one token whose effective value is "foo", so it still resolves.
        var tokenised = tokenised("return 0;", mapping);

        assertEquals("TOKEN_X", AIDecompilationdWindow.resolveToken(tokenised, 0, 99, "foo"));
    }

    @Test
    public void resolveToken_ambiguousValueMatchReturnsNull() {
        var mapping = new AIDecompFunctionMapping();
        mapping.setUnmatchedVars(vars(Map.of(
                "TOKEN_X", "foo",
                "TOKEN_Y", "foo")));
        var tokenised = tokenised("return 0;", mapping);

        assertNull(AIDecompilationdWindow.resolveToken(tokenised, 0, 99, "foo"));
    }

    @Test
    public void resolveToken_unknownIdentifierReturnsNull() {
        var mapping = new AIDecompFunctionMapping();
        mapping.setUnmatchedVars(vars(Map.of("TOKEN_A", "result")));
        var tokenised = tokenised("int TOKEN_A = 1;", mapping);

        assertNull(AIDecompilationdWindow.resolveToken(tokenised, 0, 0, "int"));
    }

    @Test
    public void resolveToken_nullMappingReturnsNull() {
        var tokenised = new TokenisedData();
        tokenised.setTokenisedDecompilation("int TOKEN_A = 1;");
        assertNull(AIDecompilationdWindow.resolveToken(tokenised, 0, 1, "result"));
    }

    private static Map<String, ReplacementValue> vars(Map<String, String> tokenToValue) {
        var result = new LinkedHashMap<String, ReplacementValue>();
        tokenToValue.forEach((token, value) -> result.put(token, new ReplacementValue().value(value)));
        return result;
    }

    private static TokenisedData tokenised(String tokenisedDecompilation, AIDecompFunctionMapping mapping) {
        var data = new TokenisedData();
        data.setTokenisedDecompilation(tokenisedDecompilation);
        data.setFunctionMapping(mapping);
        return data;
    }
}

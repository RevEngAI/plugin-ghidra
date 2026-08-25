package ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler;

import ai.reveng.model.GetTokensResponse;
import ai.reveng.model.RenderedToken;
import ai.reveng.model.Token;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

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
    public void effectiveValues_overrideWinsOverPredictedValue() {
        var tokenValues = tokenValues("int TOKEN_A = TOKEN_B;",
                Map.of("TOKEN_A", "result", "TOKEN_B", "value"),
                Map.of("TOKEN_A", "myResult"));

        assertEquals(Map.of("TOKEN_A", "myResult", "TOKEN_B", "value"),
                AIDecompilationdWindow.effectiveValues(tokenValues));
    }

    @Test
    public void effectiveValues_unwrapsARenderedTokenToItsValue() {
        var data = new GetTokensResponse();
        data.setAiDecomp("int TOKEN_A = 1;");
        data.setPlaceholderToRenderedToken(Map.of("TOKEN_A", new RenderedToken()
                .value("result")
                .kind(RenderedToken.KindEnum.LOCAL)
                .dataTypeId(42L)
                .vaddr(0x1000L)));

        // Only the rendered value is taken; the kind and ids the token also carries are not used.
        assertEquals(Map.of("TOKEN_A", "result"), AIDecompilationdWindow.effectiveValues(data));
    }

    @Test
    public void effectiveValues_toleratesTheNullMapsReturnedBeforeARunSucceeds() {
        var tokenValues = new GetTokensResponse();
        tokenValues.setAiDecomp("");
        assertTrue(AIDecompilationdWindow.effectiveValues(tokenValues).isEmpty());
    }

    @Test
    public void effectiveValues_keepsAnOverrideForATokenMissingFromTheRenderedMap() {
        var tokenValues = tokenValues("int TOKEN_A = 1;", Map.of(), Map.of("TOKEN_A", "myResult"));

        assertEquals(Map.of("TOKEN_A", "myResult"), AIDecompilationdWindow.effectiveValues(tokenValues));
    }

    @Test
    public void resolveToken_matchesTokenAtSameIdentifierPosition() {
        var tokenValues = tokenValues("int TOKEN_A = compute(TOKEN_B);",
                Map.of("TOKEN_A", "result", "TOKEN_B", "value"),
                Map.of());

        // "result" is the identifier at index 1 in the source line.
        assertEquals("TOKEN_A", AIDecompilationdWindow.resolveToken(tokenValues, 0, 1, "result"));
        // "value" is the identifier at index 3.
        assertEquals("TOKEN_B", AIDecompilationdWindow.resolveToken(tokenValues, 0, 3, "value"));
    }

    @Test
    public void resolveToken_userOverrideTakesPrecedenceOverPredictedValue() {
        var tokenValues = tokenValues("int TOKEN_A = 1;",
                Map.of("TOKEN_A", "result"),
                Map.of("TOKEN_A", "myResult"));

        // The displayed name is the override, so that is what the user double-clicks.
        assertEquals("TOKEN_A", AIDecompilationdWindow.resolveToken(tokenValues, 0, 1, "myResult"));
        // The stale predicted value no longer resolves.
        assertNull(AIDecompilationdWindow.resolveToken(tokenValues, 0, 1, "result"));
    }

    @Test
    public void resolveToken_resolvesTypeToken() {
        var tokenValues = tokenValues("TOKEN_T *p = 0;", Map.of("TOKEN_T", "MyStruct"), Map.of());

        assertEquals("TOKEN_T", AIDecompilationdWindow.resolveToken(tokenValues, 0, 0, "MyStruct"));
    }

    @Test
    public void resolveToken_fallsBackToUniqueValueMatchWhenPositionMisses() {
        // Position lookup misses (identIndex out of range for the tokenised line), but there is
        // exactly one token whose effective value is "foo", so it still resolves.
        var tokenValues = tokenValues("return 0;", Map.of("TOKEN_X", "foo"), Map.of());

        assertEquals("TOKEN_X", AIDecompilationdWindow.resolveToken(tokenValues, 0, 99, "foo"));
    }

    @Test
    public void resolveToken_fallbackUsesOverriddenValueNotPredictedValue() {
        var tokenValues = tokenValues("return 0;",
                Map.of("TOKEN_X", "foo"),
                Map.of("TOKEN_X", "bar"));

        assertEquals("TOKEN_X", AIDecompilationdWindow.resolveToken(tokenValues, 0, 99, "bar"));
        assertNull(AIDecompilationdWindow.resolveToken(tokenValues, 0, 99, "foo"));
    }

    @Test
    public void resolveToken_ambiguousValueMatchReturnsNull() {
        var tokenValues = tokenValues("return 0;",
                Map.of("TOKEN_X", "foo", "TOKEN_Y", "foo"),
                Map.of());

        assertNull(AIDecompilationdWindow.resolveToken(tokenValues, 0, 99, "foo"));
    }

    @Test
    public void resolveToken_unknownIdentifierReturnsNull() {
        var tokenValues = tokenValues("int TOKEN_A = 1;", Map.of("TOKEN_A", "result"), Map.of());

        assertNull(AIDecompilationdWindow.resolveToken(tokenValues, 0, 0, "int"));
    }

    @Test
    public void resolveToken_noTokenValuesReturnsNull() {
        var tokenValues = new GetTokensResponse();
        tokenValues.setAiDecomp("int TOKEN_A = 1;");
        assertNull(AIDecompilationdWindow.resolveToken(tokenValues, 0, 1, "result"));
    }

    /// The overrides endpoint renames the name of a variable, a type or a member, and nothing else.
    @Test
    public void isRenameable_allowsTheKindsTheOverridesEndpointAccepts() {
        for (var kind : new RenderedToken.KindEnum[]{
                RenderedToken.KindEnum.PARAM, RenderedToken.KindEnum.LOCAL,
                RenderedToken.KindEnum.GLOBAL, RenderedToken.KindEnum.TYPE,
                RenderedToken.KindEnum.FIELD, RenderedToken.KindEnum.ENUM,
                RenderedToken.KindEnum.LABEL}) {
            assertTrue(kind.toString(),
                    AIDecompilationdWindow.isRenameable(tokenOfKind(kind), "TOKEN_A"));
        }
    }

    /// A function is renamed on the function itself; the endpoint answers an override for one with a
    /// 400, so the rename must not send it.
    @Test
    public void isRenameable_refusesAFunctionToken() {
        for (var kind : new RenderedToken.KindEnum[]{
                RenderedToken.KindEnum.OWN_FUNCTION, RenderedToken.KindEnum.FUNCTION,
                RenderedToken.KindEnum.FUNCPTR}) {
            assertFalse(kind.toString(),
                    AIDecompilationdWindow.isRenameable(tokenOfKind(kind), "TOKEN_A"));
        }
    }

    /// A literal is not a name, so there is nothing to rename.
    @Test
    public void isRenameable_refusesALiteral() {
        assertFalse(AIDecompilationdWindow.isRenameable(
                tokenOfKind(RenderedToken.KindEnum.STRING), "TOKEN_A"));
        assertFalse(AIDecompilationdWindow.isRenameable(
                tokenOfKind(RenderedToken.KindEnum.FLOAT), "TOKEN_A"));
    }

    /// An unrecognised or absent kind is treated as not renameable rather than sent hopefully.
    @Test
    public void isRenameable_refusesAnUnknownKindOrToken() {
        assertFalse("a kind this build does not know",
                AIDecompilationdWindow.isRenameable(
                        tokenOfKind(RenderedToken.KindEnum.UNKNOWN_DEFAULT_OPEN_API), "TOKEN_A"));
        assertFalse("no kind at all",
                AIDecompilationdWindow.isRenameable(tokenOfKind(null), "TOKEN_A"));
        assertFalse("a token the response never mentioned",
                AIDecompilationdWindow.isRenameable(
                        tokenOfKind(RenderedToken.KindEnum.PARAM), "TOKEN_MISSING"));
        assertFalse("no rendered tokens at all",
                AIDecompilationdWindow.isRenameable(new GetTokensResponse(), "TOKEN_A"));
    }

    /// One rendered token, TOKEN_A, carrying the given kind.
    private static GetTokensResponse tokenOfKind(RenderedToken.KindEnum kind) {
        var data = new GetTokensResponse();
        data.setAiDecomp("TOKEN_A = 1;");
        var rendered = new LinkedHashMap<String, RenderedToken>();
        rendered.put("TOKEN_A", new RenderedToken().value("name").kind(kind));
        data.setPlaceholderToRenderedToken(rendered);
        return data;
    }

    private static GetTokensResponse tokenValues(String aiDecomp,
                                                 Map<String, String> renderedValues,
                                                 Map<String, String> userOverrides) {
        var data = new GetTokensResponse();
        data.setAiDecomp(aiDecomp);
        var rendered = new LinkedHashMap<String, RenderedToken>();
        renderedValues.forEach((placeholder, value) ->
                rendered.put(placeholder, new RenderedToken().value(value)));
        data.setPlaceholderToRenderedToken(rendered);
        var overrides = new LinkedHashMap<String, Token>();
        userOverrides.forEach((placeholder, value) ->
                overrides.put(placeholder, new Token().value(value)));
        data.setPlaceholderToUserOverride(overrides);
        return data;
    }
}

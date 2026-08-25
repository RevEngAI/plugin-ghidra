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

    /// A real document from the tokens endpoint: a Rust `main`, with two parameters, an invented type
    /// name, the function itself, and two called functions. Every identifier the analyst can
    /// double-click in it is accounted for here.
    private static GetTokensResponse rustMainTokens() {
        var data = new GetTokensResponse();
        data.setAiDecomp("int\n_FUNC0_(\n    int _PARAM0_,\n    _TYPE0_ *_PARAM1_\n)\n{\n"
                + "    return _FCN0_(_FCN1_, __rustc_debug_gdb_scripts_section__, _PARAM0_, _PARAM1_, 0);\n}");
        var rendered = new LinkedHashMap<String, RenderedToken>();
        rendered.put("_FCN0_", new RenderedToken().value("lang_start<()>").functionId(1380166L));
        rendered.put("_FCN1_", new RenderedToken().value("main").functionId(1380659L));
        rendered.put("_FUNC0_", new RenderedToken().value("main").functionId(1380664L));
        rendered.put("_PARAM0_", new RenderedToken().value("param_1"));
        rendered.put("_PARAM1_", new RenderedToken().value("param_2"));
        rendered.put("_TYPE0_", new RenderedToken().value("Type_1"));
        data.setPlaceholderToRenderedToken(rendered);
        return data;
    }

    /// The parameter is the case that has to work: "    int param_1," is the third line of the
    /// decompilation, and "param_1" is the second identifier on it.
    @Test
    public void realDocument_resolvesAndAllowsAParameter() {
        var tokens = rustMainTokens();

        assertEquals("_PARAM0_", AIDecompilationdWindow.resolveToken(tokens, 2, 1, "param_1"));
        assertTrue("a parameter carries no id, so the override owns its name",
                AIDecompilationdWindow.isRenameable(tokens, "_PARAM0_"));

        // And from the body: "return" is an identifier too, so on
        // "return lang_start<()>(main, __rustc..., param_1, param_2, 0)" param_1 is the fifth.
        assertEquals("_PARAM0_", AIDecompilationdWindow.resolveToken(tokens, 6, 4, "param_1"));
    }

    /// The type name the decompilation invented has no data_type_id, so it is renameable too.
    @Test
    public void realDocument_resolvesAndAllowsAnInventedTypeName() {
        var tokens = rustMainTokens();

        assertEquals("_TYPE0_", AIDecompilationdWindow.resolveToken(tokens, 3, 0, "Type_1"));
        assertTrue(AIDecompilationdWindow.isRenameable(tokens, "_TYPE0_"));
    }

    /// A called function resolves, and is then refused: this is the token that produced the 400.
    @Test
    public void realDocument_refusesACalledFunction() {
        var tokens = rustMainTokens();

        assertEquals("_FCN0_", AIDecompilationdWindow.resolveToken(tokens, 6, 1, "lang_start"));
        assertFalse("it carries a function_id, so it is renamed on the function",
                AIDecompilationdWindow.isRenameable(tokens, "_FCN0_"));
    }

    /// Two tokens render as "main" — the function itself and a call to it — so the position on the
    /// line is what tells them apart, and it is consulted before the ambiguity check. Either way the
    /// gate then refuses both, because a function is renamed on the function.
    @Test
    public void realDocument_distinguishesTheFunctionFromTheCallToItByPosition() {
        var tokens = rustMainTokens();

        assertEquals("the signature line names the function itself",
                "_FUNC0_", AIDecompilationdWindow.resolveToken(tokens, 1, 0, "main"));
        assertEquals("the call in the body names the callee",
                "_FCN1_", AIDecompilationdWindow.resolveToken(tokens, 6, 2, "main"));
        assertFalse(AIDecompilationdWindow.isRenameable(tokens, "_FUNC0_"));
        assertFalse(AIDecompilationdWindow.isRenameable(tokens, "_FCN1_"));
    }

    /// A keyword is no token at all, and nothing is invented for it.
    @Test
    public void realDocument_declinesAKeyword() {
        assertNull(AIDecompilationdWindow.resolveToken(rustMainTokens(), 2, 0, "int"));
    }

    /// A token with no id is a name the decompilation invented — a parameter, a local — and the
    /// override endpoint is the only place it exists.
    @Test
    public void isRenameable_allowsATokenThatCarriesNoId() {
        assertTrue(AIDecompilationdWindow.isRenameable(
                tokenWithIds(null, null, null), "TOKEN_A"));
    }

    /// A token that carries an id refers to something named outside this decompilation, and renaming
    /// it is a different call. The overrides endpoint answers one for a function with a 400.
    @Test
    public void isRenameable_refusesATokenThatCarriesAnId() {
        assertFalse("a data type is renamed on the type",
                AIDecompilationdWindow.isRenameable(tokenWithIds(42L, null, null), "TOKEN_A"));
        assertFalse("a function is renamed on the function",
                AIDecompilationdWindow.isRenameable(tokenWithIds(null, 7L, null), "TOKEN_A"));
        assertFalse("and so is an imported one",
                AIDecompilationdWindow.isRenameable(tokenWithIds(null, null, 9L), "TOKEN_A"));
    }

    @Test
    public void isRenameable_refusesATokenTheResponseNeverMentioned() {
        assertFalse(AIDecompilationdWindow.isRenameable(
                tokenWithIds(null, null, null), "TOKEN_MISSING"));
        assertFalse("no rendered tokens at all",
                AIDecompilationdWindow.isRenameable(new GetTokensResponse(), "TOKEN_A"));
    }

    /// One rendered token, TOKEN_A, carrying the given ids.
    private static GetTokensResponse tokenWithIds(Long dataTypeId, Long functionId, Long importedFunctionId) {
        var data = new GetTokensResponse();
        data.setAiDecomp("TOKEN_A = 1;");
        var rendered = new LinkedHashMap<String, RenderedToken>();
        rendered.put("TOKEN_A", new RenderedToken()
                .value("name")
                .dataTypeId(dataTypeId)
                .functionId(functionId)
                .importedFunctionId(importedFunctionId));
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

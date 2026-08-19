package ai.reveng.toolkit.ghidra.core.services.api;

import org.junit.Test;

import java.lang.reflect.Method;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class SdkSchemaTest {

    private static final int[] PINNED = {3, 123, 0};

    @Test
    public void installedSdkIsAtLeastPinned() {
        int[] installed = installedSdkVersion();
        assertTrue(
                "ai.reveng:sdk " + render(installed) + " is older than the pinned " + render(PINNED),
                compare(installed, PINNED) >= 0
        );
    }

    @Test
    public void apiClientsExposeMethodsThePluginCalls() {
        Map<String, String[]> apis = new LinkedHashMap<>();
        apis.put("ai.reveng.api.ConfigApi", new String[]{"getConfig"});
        apis.put("ai.reveng.api.SearchApi", new String[]{"searchBinaries"});
        apis.put("ai.reveng.api.CollectionsApi", new String[]{"v3ListCollections"});
        apis.put("ai.reveng.api.AnalysesCoreApi", new String[]{
                "uploadFile", "createAnalysis", "getAnalysisStatus", "getAnalysisBasicInfo",
                "startAnalysisFunctionMatching", "getAnalysisFunctionMatchingStatus", "getAnalysisFunctionMatches"});
        apis.put("ai.reveng.api.AnalysesResultsMetadataApi", new String[]{"getFunctionsList"});
        apis.put("ai.reveng.api.FunctionsCoreApi", new String[]{
                "startFunctionsMatching", "getFunctionsMatchingStatus", "getFunctionsMatches",
                "getFunctionBlocks", "getFunctionDetails"});
        apis.put("ai.reveng.api.FunctionsRenamingHistoryApi", new String[]{
                "renameFunctionId", "batchRenameFunctions"});
        apis.put("ai.reveng.api.DataTypesApi", new String[]{
                "v3ListFunctionSignaturesCall", "v3ListAnalysisDataTypesCall",
                "v3GetFunctionSignatureHistory",
                // The write path: the two batch data-type endpoints go through the call form
                // because their responses embed DataTypeEntry, while the singular signature write
                // uses the typed form so its status code survives on the ApiException.
                "v3CreateAnalysisDataTypesCall", "v3UpdateAnalysisDataTypesCall",
                "v3UpdateFunctionSignature"});
        apis.put("ai.reveng.api.FunctionsAiDecompilationApi", new String[]{
                "createAiDecompilation", "getAiDecompilation", "v3GetAiDecompilationTokens",
                "v3UpsertAiDecompilationOverrides",
                "getAiDecompilationSummary", "getAiDecompilationSummaryStatus",
                "getAiDecompilationInlineComments", "getAiDecompilationInlineCommentsStatus",
                "regenerateAiDecompilationSummary", "regenerateAiDecompilationInlineComments",
                "upsertAiDecompilationRating"});

        List<String> missing = new ArrayList<>();
        for (Map.Entry<String, String[]> entry : apis.entrySet()) {
            requireMethods(missing, entry.getKey(), entry.getValue());
        }
        assertTrue("SDK API surface drifted: " + missing, missing.isEmpty());
    }

    @Test
    public void modelTypesExposeAccessorsThePluginReliesOn() {
        List<String> missing = new ArrayList<>();

        // The data-type read path deserialises DataTypeEntry itself (see ServerDataTypeReader), so
        // what has to stay stable is the signature surface around it: the entries the plugin reads
        // out of the /v3/functions/signatures body, and the history models it reads whole.
        requireMethods(missing, "ai.reveng.model.BatchFunctionSignatureEntry",
                "getAnalysisId", "getFunctionId", "getFunctionName", "getHasSignature",
                "getParameters", "getReturnDataTypeId");
        requireMethods(missing, "ai.reveng.model.SignatureParameterEntry",
                "getName", "getOrdinal", "getDataTypeId", "getBitLength");
        requireMethods(missing, "ai.reveng.model.GetFunctionSignatureHistoryBody", "getVersions");

        // The write path builds request bodies out of generated models — serialisation of the
        // oneOf unions works even though deserialisation does not — so their setters are the
        // surface that has to stay put.
        requireMethods(missing, "ai.reveng.model.CreateAnalysisDataTypesInputBody", "setDataTypes");
        requireMethods(missing, "ai.reveng.model.UpdateAnalysisDataTypesInputBody", "setDataTypes");
        requireMethods(missing, "ai.reveng.model.CreateDataTypeEntry", "getActualInstance");
        requireMethods(missing, "ai.reveng.model.UpdateDataTypeEntry", "getActualInstance");
        requireMethods(missing, "ai.reveng.model.CreateStructDataType",
                "kind", "name", "namespace", "size", "definition");
        requireMethods(missing, "ai.reveng.model.UpdateStructDataType",
                "kind", "dataTypeId", "name", "namespace", "size", "definition");
        requireMethods(missing, "ai.reveng.model.DataTypeMemberEntry",
                "name", "offset", "size", "dataTypeId", "isBitfield", "bitOffset", "bitSize");
        requireMethods(missing, "ai.reveng.model.DataTypeEnumValueEntry", "name", "value");
        requireMethods(missing, "ai.reveng.model.DataTypeFunctionParameterEntry",
                "ordinal", "size", "name", "dataTypeId");
        requireMethods(missing, "ai.reveng.model.StructDefinition", "members");
        requireMethods(missing, "ai.reveng.model.UnionDefinition", "members");
        requireMethods(missing, "ai.reveng.model.EnumDefinition", "values");
        requireMethods(missing, "ai.reveng.model.TypedefDefinition", "targetDataTypeId");
        requireMethods(missing, "ai.reveng.model.PointerDefinition", "pointeeDataTypeId");
        requireMethods(missing, "ai.reveng.model.ArrayDefinition", "count", "elementDataTypeId");
        requireMethods(missing, "ai.reveng.model.FunctionTypeDefinition",
                "parameters", "returnDataTypeId");
        requireMethods(missing, "ai.reveng.model.UpdateFunctionSignatureInputBody",
                "setCallingConvention", "setParameters", "setReturnDataTypeId");
        requireMethods(missing, "ai.reveng.model.SignatureParameterInput",
                "ordinal", "name", "dataTypeId", "bitLength", "storage");
        requireMethods(missing, "ai.reveng.model.SignatureStorageInput", "kind", "location");
        requireMethods(missing, "ai.reveng.model.FunctionSignatureVersion",
                "getValue", "getUpdatedAt", "getUpdatedBy");

        requireMethods(missing, "ai.reveng.model.AnalysisCreateRequest",
                "getFilename", "getSha256Hash", "getTags", "getAnalysisScope");
        requireMethods(missing, "ai.reveng.model.Tag", "getName");
        requireMethods(missing, "ai.reveng.model.StartMatchingForAnalysisInputBody",
                "getMinSimilarity", "getResultsPerFunction", "getFilters");
        requireMethods(missing, "ai.reveng.model.StartMatchingForFunctionsInputBody",
                "getFunctionIds", "getResultsPerFunction", "getFilters", "getMinSimilarity");
        requireMethods(missing, "ai.reveng.model.MatchFilters",
                "getCollectionIds", "getBinaryIds", "getDebugTypes");
        requireMethods(missing, "ai.reveng.model.GetMatchesOutputBody", "getMatches", "getStatus");
        requireMethods(missing, "ai.reveng.model.MatchedFunction",
                "getFunctionId", "getFunctionName", "getSimilarity", "getConfidence");
        requireMethods(missing, "ai.reveng.model.BatchRenameInputBody", "setFunctions");
        requireMethods(missing, "ai.reveng.model.BatchRenameItem",
                "setFunctionId", "setNewName", "setNewMangledName");
        requireMethods(missing, "ai.reveng.model.FunctionRename", "getNewName", "getNewMangledName");

        // Resolving a double-clicked identifier back to the token to override reads the tokenised
        // source and both name maps, which arrive unmerged.
        requireMethods(missing, "ai.reveng.model.GetTokensResponse",
                "getAiDecomp", "getPlaceholderToRenderedToken", "getPlaceholderToUserOverride");
        // Both maps hold different types, and only the rendered value is read out of either.
        requireMethods(missing, "ai.reveng.model.RenderedToken", "getValue");
        requireMethods(missing, "ai.reveng.model.Token", "getValue");
        requireMethods(missing, "ai.reveng.model.UpsertOverridesInputBody", "getOverrides");

        assertTrue("SDK model surface drifted: " + missing, missing.isEmpty());
    }

    @Test
    public void analysisScopeEnumHasPluginMembers() {
        Class<?> scope = classOrNull("ai.reveng.model.AnalysisScope");
        assertNotNull("ai.reveng.model.AnalysisScope is missing from the SDK", scope);
        List<String> members = new ArrayList<>();
        for (Object constant : scope.getEnumConstants()) {
            members.add(((Enum<?>) constant).name());
        }
        assertTrue("AnalysisScope is missing PRIVATE/PUBLIC, has " + members,
                members.contains("PRIVATE") && members.contains("PUBLIC"));
    }

    private static int[] installedSdkVersion() {
        // Anchored on the invoker rather than a model class: models come and go between SDK
        // releases, and when the anchor disappears this assertion misreports the SDK as absent
        // from the classpath entirely.
        Class<?> anchor = classOrNull("ai.reveng.invoker.ApiClient");
        assertNotNull("ai.reveng:sdk is not on the test classpath", anchor);
        CodeSource codeSource = anchor.getProtectionDomain().getCodeSource();
        assertNotNull("Could not locate the ai.reveng:sdk code source", codeSource);
        String location = codeSource.getLocation().toString();
        Matcher matcher = Pattern.compile("sdk-(\\d+)\\.(\\d+)\\.(\\d+)").matcher(location);
        assertTrue("Could not parse the SDK version from " + location, matcher.find());
        return new int[]{
                Integer.parseInt(matcher.group(1)),
                Integer.parseInt(matcher.group(2)),
                Integer.parseInt(matcher.group(3))
        };
    }

    private static void requireMethods(List<String> missing, String className, String... methods) {
        Class<?> cls = classOrNull(className);
        if (cls == null) {
            missing.add(className + " (class)");
            return;
        }
        for (String method : methods) {
            if (!hasMethod(cls, method)) {
                missing.add(className + "#" + method);
            }
        }
    }

    private static boolean hasMethod(Class<?> cls, String name) {
        for (Method method : cls.getMethods()) {
            if (method.getName().equals(name)) {
                return true;
            }
        }
        return false;
    }

    private static Class<?> classOrNull(String name) {
        try {
            return Class.forName(name);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    private static int compare(int[] a, int[] b) {
        for (int i = 0; i < Math.min(a.length, b.length); i++) {
            if (a[i] != b[i]) {
                return Integer.compare(a[i], b[i]);
            }
        }
        return Integer.compare(a.length, b.length);
    }

    private static String render(int[] version) {
        return Arrays.stream(version).mapToObj(Integer::toString).reduce((a, b) -> a + "." + b).orElse("");
    }
}

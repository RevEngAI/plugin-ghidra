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

    private static final int[] PINNED = {3, 100, 0};

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
        apis.put("ai.reveng.api.SearchApi", new String[]{"searchBinaries", "searchCollections"});
        apis.put("ai.reveng.api.AnalysesCoreApi", new String[]{
                "uploadFile", "createAnalysis", "getAnalysisStatus", "getAnalysisBasicInfo",
                "startAnalysisFunctionMatching", "getAnalysisFunctionMatchingStatus", "getAnalysisFunctionMatches"});
        apis.put("ai.reveng.api.AnalysesResultsMetadataApi", new String[]{"getFunctionsList"});
        apis.put("ai.reveng.api.FunctionsCoreApi", new String[]{
                "startFunctionsMatching", "getFunctionsMatchingStatus", "getFunctionsMatches",
                "autoUnstrip", "aiUnstrip", "getFunctionBlocks", "getFunctionDetails"});
        apis.put("ai.reveng.api.FunctionsRenamingHistoryApi", new String[]{
                "renameFunctionId", "batchRenameFunctions"});
        apis.put("ai.reveng.api.FunctionsDataTypesApi", new String[]{
                "listFunctionDataTypesForAnalysis", "listFunctionDataTypesForFunctions"});
        apis.put("ai.reveng.api.FunctionsAiDecompilationApi", new String[]{
                "createAiDecompilation", "getAiDecompilation", "getAiDecompilationTokenised",
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

        requireMethods(missing, "ai.reveng.model.FunctionInfo", "fromJson", "getFuncTypes", "getFuncDeps");
        requireMethods(missing, "ai.reveng.model.FunctionType", "getName", "getHeader", "getType");
        requireMethods(missing, "ai.reveng.model.FunctionHeader", "getName", "getArgs");
        requireMethods(missing, "ai.reveng.model.FunctionDataTypesList", "getItems");
        requireMethods(missing, "ai.reveng.model.FunctionDataTypesListItem",
                "getDataTypes", "getCompleted", "getFunctionId");
        requireClass(missing, "ai.reveng.model.FuncDepsInner");

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
        Class<?> anchor = classOrNull("ai.reveng.model.FunctionInfo");
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

    private static void requireClass(List<String> missing, String className) {
        if (classOrNull(className) == null) {
            missing.add(className + " (class)");
        }
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

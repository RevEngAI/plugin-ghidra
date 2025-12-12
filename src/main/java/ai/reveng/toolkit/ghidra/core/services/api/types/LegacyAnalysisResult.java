package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import org.json.JSONObject;


/// {"analyses":[
/// {"analysis_scope":"PRIVATE","binary_id":27665,"binary_name":"true","creation":"Fri, 19 Apr 2024 08:57:18 GMT","model_id":1,"model_name":"binnet-0.2-x86-linux","sha_256_hash":"b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6","status":"Error"},{"analysis_scope":"PRIVATE","binary_id":27664,"binary_name":"true","creation":"Fri, 19 Apr 2024 08:55:28 GMT","model_id":1,"model_name":"binnet-0.2-x86-linux","sha_256_hash":"b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6","status":"Error"},{"analysis_scope":"PRIVATE","binary_id":27663,"binary_name":"true","creation":"Fri, 19 Apr 2024 08:53:33 GMT","model_id":1,"model_name":"binnet-0.2-x86-linux","sha_256_hash":"b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6","status":"Error"},{"analysis_scope":"PRIVATE","binary_id":27662,"binary_name":"true","creation":"Fri, 19 Apr 2024 08:32:34 GMT","model_id":1,"model_name":"binnet-0.2-x86-linux","sha_256_hash":"b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6","status":"Error"},{"analysis_scope":"PRIVATE","binary_id":27661,"binary_name":"true","creation":"Fri, 19 Apr 2024 08:24:44 GMT","model_id":1,"model_name":"binnet-0.2-x86-linux","sha_256_hash":"b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6","status":"Error"},{"analysis_scope":"PRIVATE","binary_id":27660,"binary_name":"true","creation":"Fri, 19 Apr 2024 08:23:54 GMT","model_id":1,"model_name":"binnet-0.2-x86-linux","sha_256_hash":"b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6","status":"Error"},{"analysis_scope":"PRIVATE","binary_id":27633,"binary_name":"true","creation":"Thu, 18 Apr 2024 17:34:42 GMT","model_id":1,"model_name":"binnet-0.2-x86-linux","sha_256_hash":"b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6","status":"Error"},{"analysis_scope":"PRIVATE","binary_id":27632,"binary_name":"true","creation":"Thu, 18 Apr 2024 17:33:36 GMT","model_id":1,"model_name":"binnet-0.2-x86-linux","sha_256_hash":"b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6","status":"Error"},{"analysis_scope":"PRIVATE","binary_id":27631,"binary_name":"ls","creation":"Thu, 18 Apr 2024 17:17:48 GMT","model_id":1,"model_name":"binnet-0.2-x86-linux","sha_256_hash":"2e7ef3da2b295c77820a0782b00c9d607cd48d5c8f7458a76b0921bec20a30ae","status":"Error"},{"analysis_scope":"PRIVATE","binary_id":27630,"binary_name":"ls","creation":"Thu, 18 Apr 2024 17:16:48 GMT","model_id":1,"model_name":"binnet-0.2-x86-linux","sha_256_hash":"2e7ef3da2b295c77820a0782b00c9d607cd48d5c8f7458a76b0921bec20a30ae","status":"Error"}]}
/// @deprecated Use {@link AnalysisResult)}
@Deprecated
public record LegacyAnalysisResult(
        TypedApiInterface.AnalysisID analysis_id,
        @Deprecated
        BinaryID binary_id,
        String binary_name,
        String creation,
        int model_id,
        String model_name,
        TypedApiInterface.BinaryHash sha_256_hash,
        AnalysisStatus status,
        long base_address,
        String function_boundaries_hash
) {
    public static LegacyAnalysisResult fromJSONObject(JSONObject json) {
        return new LegacyAnalysisResult(
                new TypedApiInterface.AnalysisID(json.getInt("analysis_id")),
                new BinaryID(json.getInt("binary_id")),
                json.getString("binary_name"),
                json.getString("creation"),
                json.getInt("model_id"),
                json.getString("model_name"),
                new TypedApiInterface.BinaryHash(json.getString("sha_256_hash")),
                AnalysisStatus.valueOf(json.getString("status")),
                json.getLong("base_address"),
                json.getString("function_boundaries_hash")
        );
    }
}

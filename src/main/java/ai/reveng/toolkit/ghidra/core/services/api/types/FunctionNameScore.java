package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import org.json.JSONObject;

public record FunctionNameScore(
        TypedApiInterface.FunctionID functionID,
        BoxPlot score
) {
    public static FunctionNameScore fromJSONObject(JSONObject jsonObject) {
        var boxplotJson = jsonObject.getJSONObject("box_plot");
        return new FunctionNameScore(
                new TypedApiInterface.FunctionID(jsonObject.getInt("function_id")),
                BoxPlot.fromJSONObject(boxplotJson)
        );
    }
}

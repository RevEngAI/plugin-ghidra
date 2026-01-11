package ai.reveng.toolkit.ghidra.core.services.api.types.binsync;

import ai.reveng.model.FunctionTypeOutput;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 *     The Function class describes a Function found a decompiler. There are three components to a function:
 *     1. Metadata
 *     2. Header
 *     3. Stack Vars
 *
 *     The metadata contains info on changes and size. The header holds the return type,
 *     and arguments (including their types). The stack vars contain StackVariables.
 */
public record FunctionArtifact(
        long addr,
        int size,
        FunctionHeader header,
        StackVariable[] stack_vars
) {
    public static FunctionArtifact fromJsonObject(JSONObject func) {

        List<StackVariable> stackVars = new ArrayList<>();
        if (!func.isNull("stack_vars")) {
            JSONObject stackVarsJson = func.getJSONObject("stack_vars");
            for (String key : stackVarsJson.keySet()) {
                stackVars.add(StackVariable.fromJsonObject(stackVarsJson.getJSONObject(key)));
            }
        }
        return new FunctionArtifact(
                func.getLong("addr"),
                func.getInt("size"),
                FunctionHeader.fromJsonObject(func.getJSONObject("header")),
                stackVars.toArray(new StackVariable[0])
        );
    }

    /**
     * Creates a C signature for the function, based on the return type, name and arguments
     * @return
     */
    public String getSignature() {
        StringBuilder signature = new StringBuilder();
        signature.append(header.type()).append(" ").append(header.name()).append("(");
        for (int i = 0; i < header.args().length; i++) {
            FunctionArgument arg = header.args()[i];
            signature.append(arg.type()).append(" ").append(arg.name());
            if (i < header.args().length - 1) {
                signature.append(", ");
            }
        }
        signature.append(")");
        return signature.toString();
    }

}


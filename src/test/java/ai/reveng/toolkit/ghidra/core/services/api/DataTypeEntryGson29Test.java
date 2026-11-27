package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.datatypes.ServerDataTypeReader;
import org.junit.Test;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * Reruns {@link ServerDataTypeReader} against Gson 2.9.0, which Ghidra < 12.1 loads ahead of the
 * plugin's own Gson. 2.9.0 cannot bind records reflectively.
 */
public class DataTypeEntryGson29Test {

    @Test
    public void readsNestedDefinitionsOnGson29() throws Exception {
        URL gson = new File(System.getProperty("reveng.test.gson29")).toURI().toURL();
        URL plugin = ServerDataTypeReader.class.getProtectionDomain().getCodeSource().getLocation();
        try (var loader = new URLClassLoader(new URL[]{gson, plugin}, ClassLoader.getPlatformClassLoader())) {
            Class<?> parser = loader.loadClass("com.google.gson.JsonParser");
            Class<?> element = loader.loadClass("com.google.gson.JsonElement");
            Object body = parser.getMethod("parseString", String.class).invoke(null, """
                    {"items": [
                      {"data_type_id": 1, "kind": "STRUCT", "name": "S", "namespace": "", "source_type": "SYSTEM",
                       "has_definition": true, "definition": {"members": [
                         {"name": "a", "offset": 0, "size": 4, "data_type_id": 2, "is_bitfield": false}]}},
                      {"data_type_id": 3, "kind": "ENUM", "name": "E", "namespace": "", "source_type": "SYSTEM",
                       "has_definition": true, "definition": {"values": [{"name": "A", "value": "-1"}]}},
                      {"data_type_id": 4, "kind": "FUNCTION_DEFINITION", "name": "F", "namespace": "",
                       "source_type": "SYSTEM", "has_definition": true, "definition": {"return_data_type_id": 2,
                       "parameters": [{"name": "p", "ordinal": 0, "size": 8, "data_type_id": 2}]}}
                    ]}""");
            List<?> types = (List<?>) loader.loadClass(ServerDataTypeReader.class.getName())
                    .getMethod("readEntries", element, String.class).invoke(null, body, "items");
            assertEquals(3, types.size());
            String text = types.toString();
            assertEquals(text, true, text.contains("Member[name=a, offset=0, size=4, dataTypeId=2, isBitfield=false"));
            assertEquals(text, true, text.contains("EnumValue[name=A, value=-1]"));
            assertEquals(text, true, text.contains("Parameter[name=p, ordinal=0, size=8, dataTypeId=2]"));
        }
    }
}

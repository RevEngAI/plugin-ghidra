package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.models.ReaiConfig;
import com.google.gson.Gson;
import org.json.JSONException;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.URI;
import java.nio.file.Path;

public record ApiInfo(
        URI hostURI,
        URI portalURI,
        String apiKey
) {
    public ApiInfo(String hostURI, String portalURI, String apiKey) {
        this(URI.create(hostURI), URI.create(portalURI), apiKey);
    }

    public static ApiInfo fromConfig(Path configFilePath) throws FileNotFoundException {
        ReaiConfig config;
        try (FileReader reader = new FileReader(configFilePath.toString())) {
            config = new Gson().fromJson(reader, ReaiConfig.class);
        } catch (FileNotFoundException e) {
            throw e;
        } catch (java.io.IOException e) {
            throw new RuntimeException("Failed to read config file: " + configFilePath, e);
        }
        var apikey = config.getPluginSettings().getApiKey();
        var hostname = config.getPluginSettings().getHostname();
        var portalHostname = config.getPluginSettings().getPortalHostname();
        if (    hostname == null || hostname.isEmpty() ||
                apikey == null || apikey.isEmpty() ||
                portalHostname == null || portalHostname.isEmpty()) {
            throw new JSONException("Invalid config file: hostname, apiKey and portal must be set");
        }
        return new ApiInfo(hostname, portalHostname, apikey);
    }
}

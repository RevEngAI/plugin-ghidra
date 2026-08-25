package ai.reveng.toolkit.ghidra.core.models;

public class ReaiConfig {
	private PluginSettings pluginSettings;
	
	public PluginSettings getPluginSettings() {
		return pluginSettings;
	}

	public void setPluginSettings(PluginSettings pluginSettings) {
		this.pluginSettings = pluginSettings;
	}

	public static class PluginSettings {
		private String apiKey;
		private String hostname;
        private String portalHostname;

		public String getApiKey() {
			return apiKey;
		}
		
		public void setApiKey(String apiKey) {
			this.apiKey = apiKey;
		}
		
		public String getHostname() {
			return hostname;
		}
		
		public void setHostname(String hostname) {
			this.hostname = hostname;
		}

        public String getPortalHostname() {
            return portalHostname;
        }

        public void setPortalHostname(String portalHostname) {
            this.portalHostname = portalHostname;
        }
	}
}

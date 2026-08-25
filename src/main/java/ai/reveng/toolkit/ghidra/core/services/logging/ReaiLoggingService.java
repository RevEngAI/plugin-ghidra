package ai.reveng.toolkit.ghidra.core.services.logging;

import ghidra.framework.plugintool.ServiceInfo;

@ServiceInfo(description = "Service for writing plugin messages to the Ghidra console")
public interface ReaiLoggingService {
	public void info(String message);
	public void warn(String message);
	public void error(String message);
}

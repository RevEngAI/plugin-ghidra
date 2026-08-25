package ai.reveng.toolkit.ghidra.core.services.logging;

import ghidra.app.services.ConsoleService;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;

public class ReaiLoggingToConsole implements ReaiLoggingService {

    private ConsoleService consoleService;

    public ReaiLoggingToConsole(@Nullable ConsoleService consoleService) {
        this.consoleService = consoleService;
    }

    private List<String> logBuffer = new ArrayList<>();

    @Override
    public void info(String message) {
        if (consoleService == null) {
            logBuffer.add("INFO: " + message);
        } else {
            consoleService.println("INFO: " + message);
        }
    }

    @Override
    public void warn(String message) {
        if (consoleService == null) {
            logBuffer.add("WARN: " + message);
        } else {
            consoleService.println("WARN: " + message);
        }
    }

    @Override
    public void error(String message) {
        if (consoleService == null) {
            logBuffer.add("ERROR: " + message);
        } else {
            consoleService.println("ERROR: " + message);
        }
    }

    public void setConsoleService(ConsoleService service) {
        this.consoleService = service;
        for (String message : logBuffer) {
            consoleService.println(message);
        }
        logBuffer.clear();
    }
}

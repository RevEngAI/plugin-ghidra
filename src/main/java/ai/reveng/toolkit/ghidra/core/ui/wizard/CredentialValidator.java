package ai.reveng.toolkit.ghidra.core.ui.wizard;

import ai.reveng.toolkit.ghidra.core.services.api.TypedApiImplementation;
import ai.reveng.toolkit.ghidra.core.services.api.types.ApiInfo;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;

/**
 * Strategy for validating API credentials.
 * Production code uses {@link #defaultValidator()} which makes a real API call;
 * tests can supply a mock that avoids network calls.
 */
@FunctionalInterface
public interface CredentialValidator {
    void validate(ApiInfo apiInfo) throws InvalidAPIInfoException;

    /** Default validator that makes a real API call. */
    static CredentialValidator defaultValidator() {
        return apiInfo -> {
            if (apiInfo.hostURI() == null || apiInfo.apiKey() == null) {
                throw new InvalidAPIInfoException("hostURI and apiKey must not be null");
            }
            var api = new TypedApiImplementation(apiInfo);
            try {
                // Validate the credentials by making a simple API call that requires authentication.
                api.getConfig();
            } catch (Exception e) {
                throw new InvalidAPIInfoException("Failed to validate API credentials: " + e.getMessage(), e);
            }
        };
    }
}

package ai.reveng.toolkit.ghidra.core.ui.wizard.panels;

import javax.swing.*;

import ai.reveng.toolkit.ghidra.core.services.api.types.ApiInfo;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ai.reveng.toolkit.ghidra.core.ui.wizard.CredentialValidator;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import docking.wizard.AbstractMageJPanel;
import docking.wizard.IllegalPanelStateException;
import docking.wizard.WizardPanelDisplayability;
import docking.wizard.WizardState;
import ghidra.framework.plugintool.PluginTool;
import java.awt.BorderLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.Desktop;
import java.net.URI;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public class UserCredentialsPanel extends AbstractMageJPanel<SetupWizardStateKey> {
	private static final long serialVersionUID = -9045013459967405703L;
	private JTextField tfApiKey;
	private JTextField tfApiHostname;
	private JTextField tfPortalHostname;
	private Boolean credentialsValidated = false;
	private CredentialValidator credentialValidator = CredentialValidator.defaultValidator();

    private ReaiLoggingService loggingService;

	public UserCredentialsPanel(PluginTool tool) {
		setLayout(new BorderLayout(0, 0));

        loggingService = tool.getService(ReaiLoggingService.class);

		JPanel userDetailsPanel = new JPanel(new GridBagLayout());
		userDetailsPanel.setBorder(BorderFactory.createEmptyBorder(20, 0, 10, 0));
		add(userDetailsPanel, BorderLayout.CENTER);

		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(2, 5, 2, 5);

		DocumentListener documentListener = new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				credentialsValidated = false;
				notifyListenersOfValidityChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				credentialsValidated = false;
				notifyListenersOfValidityChanged();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				credentialsValidated = false;
				notifyListenersOfValidityChanged();
			}
		};

		// API Key row
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.NONE;
		JLabel lblApiKey = new JLabel("API Key:");
		userDetailsPanel.add(lblApiKey, gbc);

		gbc.gridx = 1;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.weightx = 1.0;
		tfApiKey = new JTextField(30);
		tfApiKey.setName("apiKey");
		tfApiKey.getDocument().addDocumentListener(documentListener);
		tfApiKey.setToolTipText("API key from your account settings");
		userDetailsPanel.add(tfApiKey, gbc);

		// Hostname row
		gbc.gridx = 0;
		gbc.gridy = 1;
		gbc.fill = GridBagConstraints.NONE;
		gbc.weightx = 0.0;
		JLabel lblHostname = new JLabel("API Hostname:");
		userDetailsPanel.add(lblHostname, gbc);

		gbc.gridx = 1;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.weightx = 1.0;
		tfApiHostname = new JTextField(30);
		tfApiHostname.setName("apiHostname");
		tfApiHostname.getDocument().addDocumentListener(documentListener);
		tfApiHostname.setToolTipText("URL hosting the RevEng.AI Server");
		tfApiHostname.setText("https://api.reveng.ai");
		userDetailsPanel.add(tfApiHostname, gbc);

		// Portal Hostname row
		gbc.gridx = 0;
		gbc.gridy = 2;
		gbc.fill = GridBagConstraints.NONE;
		gbc.weightx = 0.0;
		JLabel lblPortalHostname = new JLabel("Portal Hostname:");
		userDetailsPanel.add(lblPortalHostname, gbc);

		gbc.gridx = 1;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.weightx = 1.0;
		tfPortalHostname = new JTextField(30);
		tfPortalHostname.setName("portalHostname");
		tfPortalHostname.getDocument().addDocumentListener(documentListener);
		tfPortalHostname.setToolTipText("URL hosting the RevEng.AI Portal");
		tfPortalHostname.setText("https://portal.reveng.ai");
		userDetailsPanel.add(tfPortalHostname, gbc);

		// Retrieve API Key link row (above validate button)
		gbc.gridx = 0;
		gbc.gridy = 3;
		gbc.gridwidth = 2;
		gbc.fill = GridBagConstraints.NONE;
		gbc.weightx = 0.0;
		gbc.anchor = GridBagConstraints.CENTER;
		gbc.insets = new Insets(10, 5, 5, 5);
		JLabel retrieveApiKeyLink = new JLabel("<html><a href=''>Retrieve API Key</a></html>");
		retrieveApiKeyLink.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
		retrieveApiKeyLink.addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
			public void mouseClicked(java.awt.event.MouseEvent e) {
				try {
					String portalHostname = tfPortalHostname.getText().trim();
					if (portalHostname.isEmpty()) {
						portalHostname = "https://portal.reveng.ai";
					}
					// Remove trailing slash if present
					if (portalHostname.endsWith("/")) {
						portalHostname = portalHostname.substring(0, portalHostname.length() - 1);
					}
					String settingsUrl = portalHostname + "/settings";
					if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
						Desktop.getDesktop().browse(new URI(settingsUrl));
					}
				} catch (Exception ex) {
					if (loggingService != null) {
						loggingService.error("Failed to open API key link: " + ex.getMessage());
					}
				}
			}
		});
		userDetailsPanel.add(retrieveApiKeyLink, gbc);

		// Validate button row
		gbc.gridx = 0;
		gbc.gridy = 4;
		gbc.gridwidth = 2;
		gbc.fill = GridBagConstraints.NONE;
		gbc.weightx = 0.0;
		gbc.anchor = GridBagConstraints.CENTER;
		gbc.insets = new Insets(5, 5, 0, 5);
		JButton runTestsButton = new JButton("Validate Credentials");
		runTestsButton.addActionListener(e -> {
			var apiInfo = new ApiInfo(tfApiHostname.getText(), tfPortalHostname.getText(), tfApiKey.getText());
			try {
				credentialValidator.validate(apiInfo);
				credentialsValidated = true;
				notifyListenersOfValidityChanged();
			} catch (InvalidAPIInfoException ex) {
				credentialsValidated = false;
				notifyListenersOfStatusMessage("Problem with user info:\n" + ex.getMessage());
			}
		});
		userDetailsPanel.add(runTestsButton, gbc);
	}

	@Override
	public void addDependencies(WizardState<SetupWizardStateKey> state) {
		// none
		return;

	}

	@Override
	public WizardPanelDisplayability getPanelDisplayabilityAndUpdateState(WizardState<SetupWizardStateKey> state) {
		return WizardPanelDisplayability.MUST_BE_DISPLAYED;
	}

	@Override
	public void enterPanel(WizardState<SetupWizardStateKey> state) throws IllegalPanelStateException {
		// Pick up credential validator from state if provided (e.g. by tests)
		CredentialValidator validator = (CredentialValidator) state.get(SetupWizardStateKey.CREDENTIAL_VALIDATOR);
		if (validator != null) {
			this.credentialValidator = validator;
		}

		// Populate fields with existing state information if present
		String existingApiKey = (String) state.get(SetupWizardStateKey.API_KEY);
		String existingHostname = (String) state.get(SetupWizardStateKey.HOSTNAME);
		String existingPortalHostname = (String) state.get(SetupWizardStateKey.PORTAL_HOSTNAME);
		Boolean existingValidationState = (Boolean) state.get(SetupWizardStateKey.CREDENTIALS_VALIDATED);

		if (existingApiKey != null && !existingApiKey.isEmpty()) {
			tfApiKey.setText(existingApiKey);
		}

		if (existingHostname != null && !existingHostname.isEmpty()) {
			tfApiHostname.setText(existingHostname);
		}

		if (existingPortalHostname != null && !existingPortalHostname.isEmpty()) {
			tfPortalHostname.setText(existingPortalHostname);
		}

		// Restore validation state from previous session if credentials match
		if (existingValidationState != null && existingValidationState &&
		    existingApiKey != null && !existingApiKey.isEmpty() &&
		    existingHostname != null && !existingHostname.isEmpty()) {
			credentialsValidated = true;
			notifyListenersOfValidityChanged();
		}
	}


	@Override
	public void leavePanel(WizardState<SetupWizardStateKey> state) {
		updateStateObjectWithPanelInfo(state);
	}

	@Override
	public void updateStateObjectWithPanelInfo(WizardState<SetupWizardStateKey> state) {
        // Save the entered information into the state object
		state.put(SetupWizardStateKey.API_KEY, tfApiKey.getText());
		state.put(SetupWizardStateKey.HOSTNAME, tfApiHostname.getText());
		state.put(SetupWizardStateKey.PORTAL_HOSTNAME, tfPortalHostname.getText());
		state.put(SetupWizardStateKey.CREDENTIALS_VALIDATED, credentialsValidated);
	}

	@Override
	public void dispose() {
		// nothing for now

	}

	@Override
	public String getTitle() {
        return "Configure your RevEng.AI API and Portal credentials";
	}

	@Override
	public boolean isValidInformation() {
		// check each of the provided fields
		if (tfApiKey.getText().isEmpty()) {
			notifyListenersOfStatusMessage("Please provide your API key");
			return false;
		}
		if (tfApiHostname.getText().isEmpty()) {
			notifyListenersOfStatusMessage("Please enter a hostname for you API server");
			return false;
		}
		if (tfPortalHostname.getText().isEmpty()) {
			notifyListenersOfStatusMessage("Please enter a portal hostname");
			return false;
		}
		if (!credentialsValidated){
			notifyListenersOfStatusMessage("Please validate your credentials");
			return false;
		}
		notifyListenersOfStatusMessage("Credentials are valid");
		return true;
	}

	@Override
	public void initialize() {
	}
}

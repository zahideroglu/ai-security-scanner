package burp;

import burp.i18n.Glyphs;
import burp.i18n.I18n;
import burp.i18n.I18nUI;
import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;
import java.io.PrintWriter;
import java.util.*;
import java.util.List;

/**
 * Settings panel for configuring API, scan options, and filters
 * 
 * @author Zahid Eroglu
 */
public class SettingsPanel extends JPanel {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private ScanManager scanManager;
    private AiApiClient aiClient;
    private DatabaseManager dbManager;
    private SettingsManager settingsManager;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    // API Configuration
    private JComboBox<String> apiProviderComboBox;
    private JComboBox<String> hostedPresetComboBox;   // base-URL presets for the Hosted API provider
    private JTextField apiEndpointField;
    private JTextField apiKeyField;
    private JComboBox<String> modelComboBox;
    private boolean modelsAutoFetched = false; // auto-discover the provider's models once per panel load
    private JComboBox<Integer> timeoutComboBox;
    
    // Gateway API Configuration
    private JTextField gatewayUsernameField;
    private JPasswordField gatewayPasswordField;
    private JTextField gatewayClientIdField;
    private JPasswordField gatewayClientSecretField;
    private JTextField gatewayRequestedSubjectField;
    private JPanel gatewayPanel;

    // Local AI Model Configuration (Ollama / LM Studio / llama.cpp)
    private JComboBox<String> localPresetComboBox;
    private JTextField localApiUrlField;
    private JComboBox<String> localModelComboBox;
    private JTextField localApiKeyField;
    private JPanel localPanel;
    private JPanel sharedModelPanel;

    // Scan Configuration
    private JCheckBox autoScanCheckBox;
    private JCheckBox useScopeCheckBox;
    private JSlider confidenceSlider;
    private JLabel confidenceValueLabel;
    
    // Filter Configuration
    private JCheckBox filterStaticFilesCheckBox;
    private JCheckBox filterCDNCheckBox;
    private JCheckBox filterAnalyticsCheckBox;
    private JCheckBox filterSocialMediaCheckBox;
    private JCheckBox filterOptionsCheckBox;
    private JTextArea customFiltersArea;
    
    // Vulnerability Type Configuration
    private JCheckBox checkSQLiCheckBox;
    private JCheckBox checkXSSCheckBox;
    private JCheckBox checkIDORCheckBox;
    private JCheckBox checkSSRFCheckBox;
    private JCheckBox checkLFICheckBox;
    private JCheckBox checkCommandInjCheckBox;

    // Dynamic Testing Configuration
    private JCheckBox businessLogicTestingCheckBox;
    private JCheckBox idorTestingCheckBox;
    private JCheckBox jwtTestingCheckBox;
    private JCheckBox wafEvasionCheckBox;

    // AI Features Configuration
    private JCheckBox heuristicScanCheckBox; // deterministic module scan opt-in (default OFF = AI-only)
    private JCheckBox aiContextAnalysisCheckBox;
    private JCheckBox aiSmartPayloadsCheckBox;
    private JCheckBox aiFalsePositiveFilterCheckBox;

    // Detection Engine (fast deterministic scan) Configuration
    private JCheckBox fastModelEnabledCheckBox;
    private JTextField fastModelField;
    private JComboBox<Integer> engineMaxTokensCombo;
    private JComboBox<Integer> parallelismCombo;
    private JComboBox<Integer> siteScanMaxCombo;
    private JComboBox<Integer> maxReqPerMinCombo; // hard per-minute request ceiling (WAF/FW protection)
    // Agentic AI Pentester config + login profiles moved to burp.authz.LoginProfilesDialog
    // (opened from the "Yetki Matrisi" tab) — no longer fields on this panel.

    // Ambient Security Copilot controls
    private JComboBox<Integer> ambientMinScoreCombo;
    private JComboBox<Integer> agentSiteConcurrencyCombo;
    private JTextField agentTokenBudgetField;
    private JComboBox<Integer> agentTimeBudgetCombo;
    private JComboBox<String> agentRouterModeCombo;
    private Runnable ambientApplyHook;
    private Runnable languageApplyHook;
    private JComboBox<String> languageComboBox;

    // AI usage statistics (read-only display)
    private JLabel aiUsageCallsLbl;
    private JLabel aiUsageTokensLbl;
    private JLabel aiUsagePromptLbl;
    private JLabel aiUsageCompletionLbl;
    private JLabel aiUsageCacheLbl;
    private JLabel aiUsageSinceLbl;

    private Settings currentSettings;
    
    public SettingsPanel(
            IBurpExtenderCallbacks callbacks,
            IExtensionHelpers helpers,
            ScanManager scanManager,
            AiApiClient aiClient,
            DatabaseManager dbManager,
            SettingsManager settingsManager,
            PrintWriter stdout,
            PrintWriter stderr) {
        
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.scanManager = scanManager;
        this.aiClient = aiClient;
        this.dbManager = dbManager;
        this.settingsManager = settingsManager;
        this.stdout = stdout;
        this.stderr = stderr;
        
        initializeUI();
        loadSettings();
    }
    
    /**
     * BoxLayout host that reports it tracks the scroll viewport's WIDTH but not its height — so the
     * settings form fills the available width (wrapping wide fields) and only ever scrolls vertically.
     * Without this the long "Advanced Settings" section overflows the tab horizontally.
     */
    private static class WidthTrackingPanel extends JPanel implements Scrollable {
        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle r, int orientation, int direction) { return 16; }
        @Override public int getScrollableBlockIncrement(Rectangle r, int orientation, int direction) { return 120; }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }

    private void initializeUI() {
        setLayout(new BorderLayout(10, 10));
        setBackground(ColorScheme.BG_LIGHT);
        setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        
        // Title
        JLabel titleLabel = I18nUI.text(new JLabel(), "settings.title");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        titleLabel.setForeground(ColorScheme.TEXT_DARK);
        
        // Create scrollable content panel. WidthTrackingPanel forces the form to follow the scroll
        // viewport WIDTH (never wider), so the long advanced section only scrolls VERTICALLY and the
        // wide fields (login textarea, combos) wrap to fit instead of overflowing the tab.
        JPanel contentPanel = new WidthTrackingPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBackground(ColorScheme.BG_LIGHT);
        
        // ── Essential controls (always visible) ──
        contentPanel.add(createAPIConfigPanel());
        contentPanel.add(Box.createVerticalStrut(15));
        contentPanel.add(createScanConfigPanel());
        contentPanel.add(Box.createVerticalStrut(15));
        contentPanel.add(createAiUsagePanel());
        contentPanel.add(Box.createVerticalStrut(15));

        // ── Gelişmiş Ayarlar (collapsible) ──
        JPanel advancedContent = createDetectionEnginePanel();
        advancedContent.setAlignmentX(Component.LEFT_ALIGNMENT);
        advancedContent.setVisible(false); // collapsed by default

        JButton advancedToggle = new JButton(I18n.t("settings.advanced.toggle") + "  ▼");
        advancedToggle.setFont(new Font("Segoe UI", Font.BOLD, 13));
        advancedToggle.setBackground(ColorScheme.BG_CARD);
        advancedToggle.setForeground(ColorScheme.PRIMARY_BLUE);
        advancedToggle.setFocusPainted(false);
        advancedToggle.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
                BorderFactory.createEmptyBorder(8, 15, 8, 15)));
        advancedToggle.setCursor(new Cursor(Cursor.HAND_CURSOR));
        advancedToggle.setHorizontalAlignment(SwingConstants.LEFT);
        advancedToggle.setAlignmentX(Component.LEFT_ALIGNMENT);
        advancedToggle.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        advancedToggle.addActionListener(e -> {
            boolean vis = !advancedContent.isVisible();
            advancedContent.setVisible(vis);
            advancedToggle.setText(I18n.t("settings.advanced.toggle") + (vis ? "  ▲" : "  ▼"));
            revalidate();
            repaint();
        });

        contentPanel.add(advancedToggle);
        contentPanel.add(Box.createVerticalStrut(5));
        contentPanel.add(advancedContent);
        contentPanel.add(Box.createVerticalGlue());
        
        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setBorder(null);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        
        // Action buttons
        JPanel actionPanel = createActionPanel();
        
        // Layout
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBackground(ColorScheme.BG_LIGHT);
        topPanel.add(titleLabel, BorderLayout.NORTH);
        topPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 15, 0));
        
        add(topPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        add(actionPanel, BorderLayout.SOUTH);
    }
    
    private JPanel createAPIConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(ColorScheme.BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        ));
        
        // Title
        JLabel titleLabel = I18nUI.text(new JLabel(), "settings.api.title");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        titleLabel.setForeground(ColorScheme.TEXT_DARK);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // API Provider Selection. Stored ids stay stable ("hosted"/"local"/"gateway");
        // the combo shows friendly, localized labels via the renderer below.
        String[] providers = {"hosted", "local", "gateway"};
        apiProviderComboBox = new JComboBox<>(providers);
        apiProviderComboBox.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        apiProviderComboBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value != null) setText(providerLabel(value.toString()));
                return this;
            }
        });
        I18nUI.tip(apiProviderComboBox, "settings.api.provider.tip");
        apiProviderComboBox.addActionListener(e -> toggleAPIProvider());

        JPanel providerPanel = createLabeledField(I18n.t("settings.api.provider"), apiProviderComboBox);
        
        // Hosted API Panel — any OpenAI-compatible provider (OpenAI, OpenRouter, Groq, Together, DeepSeek, …)
        JPanel hostedPanel = new JPanel();
        hostedPanel.setLayout(new BoxLayout(hostedPanel, BoxLayout.Y_AXIS));
        hostedPanel.setBackground(ColorScheme.BG_CARD);
        hostedPanel.setName("hostedPanel");

        // Provider preset — fills the base URL for a well-known provider (key still required)
        String[] hostedPresets = {"Custom", "OpenAI", "OpenRouter", "Groq", "Together", "DeepSeek"};
        hostedPresetComboBox = new JComboBox<>(hostedPresets);
        hostedPresetComboBox.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        I18nUI.tip(hostedPresetComboBox, "settings.api.preset.tip");
        hostedPresetComboBox.addActionListener(e -> applyHostedPreset());
        JPanel hostedPresetPanel = createLabeledField(I18n.t("settings.api.preset"), hostedPresetComboBox);

        // API Endpoint
        JPanel endpointPanel = createLabeledField(I18n.t("settings.api.endpoint"), apiEndpointField = new JTextField(30));
        I18nUI.tip(apiEndpointField, "settings.api.endpoint.tip");

        // API Key
        JPanel keyPanel = createLabeledField(I18n.t("settings.api.key"), apiKeyField = new JTextField(30));
        I18nUI.tip(apiKeyField, "settings.api.key.tip");

        hostedPanel.add(providerPanel);
        hostedPanel.add(Box.createVerticalStrut(10));
        hostedPanel.add(hostedPresetPanel);
        hostedPanel.add(Box.createVerticalStrut(10));
        hostedPanel.add(endpointPanel);
        hostedPanel.add(Box.createVerticalStrut(10));
        hostedPanel.add(keyPanel);
        
        // Gateway API Panel
        gatewayPanel = createGatewayPanel();
        gatewayPanel.setName("gatewayPanel");

        // Local AI Model Panel
        localPanel = createLocalPanel();
        localPanel.setName("localPanel");

        // Model selection - Updated with correct API model names
        // Provider-agnostic sample ids (editable). Plain ids (gpt-4o-mini) suit direct OpenAI;
        // vendor-prefixed ids (openai/…, anthropic/…) suit OpenRouter and similar aggregators.
        String[] models = {
            "gpt-4o-mini",                          // OpenAI — cheap, fast default
            "gpt-4o",                               // OpenAI
            "openai/gpt-4o-mini",                   // OpenRouter id form
            "anthropic/claude-3.5-sonnet",          // OpenRouter
            "google/gemini-2.0-flash",              // OpenRouter
            "deepseek/deepseek-chat",               // DeepSeek / OpenRouter
            "meta-llama/llama-3.1-70b-instruct",    // OpenRouter
            "qwen/qwen-2.5-72b-instruct"            // OpenRouter
        };
        modelComboBox = new JComboBox<>(models);
        modelComboBox.setEditable(true); // Allow custom model names
        modelComboBox.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        I18nUI.tip(modelComboBox, "settings.api.model.tip");

        // Model panel with refresh button
        JPanel modelInnerPanel = new JPanel(new BorderLayout(5, 0));
        modelInnerPanel.setBackground(ColorScheme.BG_CARD);
        modelInnerPanel.add(modelComboBox, BorderLayout.CENTER);

        JButton refreshModelsBtn = new JButton(Icons.getRefreshIcon(14));
        I18nUI.tip(refreshModelsBtn, "settings.api.model.refresh.tip");
        refreshModelsBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        refreshModelsBtn.setPreferredSize(new Dimension(35, 25));
        refreshModelsBtn.addActionListener(e -> refreshModels());
        modelInnerPanel.add(refreshModelsBtn, BorderLayout.EAST);

        sharedModelPanel = createLabeledField(I18n.t("settings.api.model"), modelInnerPanel);
        sharedModelPanel.setName("sharedModelPanel");

        // Timeout
        Integer[] timeouts = {30, 60, 90, 120, 180, 300};
        timeoutComboBox = new JComboBox<>(timeouts);
        timeoutComboBox.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        JPanel timeoutPanel = createLabeledField(I18n.t("settings.api.timeout"), timeoutComboBox);

        // Language selector (Türkçe / English) — applied live on Save.
        languageComboBox = new JComboBox<>(new String[]{ I18n.t("lang.tr"), I18n.t("lang.en") });
        languageComboBox.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        languageComboBox.setToolTipText(I18n.t("settings.language.tip"));
        JPanel languagePanel = createLabeledField("Dil / Language:", languageComboBox);

        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(languagePanel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(providerPanel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(hostedPanel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(gatewayPanel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(localPanel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(sharedModelPanel);
        panel.add(Box.createVerticalStrut(8));
        panel.add(timeoutPanel);

        return panel;
    }
    
    /**
     * Create Gateway API configuration panel
     */
    private JPanel createGatewayPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(ColorScheme.BG_CARD);
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
            I18n.t("settings.gateway.title"),
            TitledBorder.LEFT,
            TitledBorder.TOP,
            new Font("Segoe UI", Font.BOLD, 12),
            ColorScheme.TEXT_DARK
        ));

        // Username
        JPanel usernamePanel = createLabeledField(I18n.t("settings.gateway.username"), gatewayUsernameField = new JTextField(30));
        I18nUI.tip(gatewayUsernameField, "settings.gateway.username.tip");

        // Password
        JPanel passwordPanel = createLabeledField(I18n.t("settings.gateway.password"), gatewayPasswordField = new JPasswordField(30));
        I18nUI.tip(gatewayPasswordField, "settings.gateway.password.tip");

        // Client ID
        JPanel clientIdPanel = createLabeledField(I18n.t("settings.gateway.clientid"), gatewayClientIdField = new JTextField(30));
        I18nUI.tip(gatewayClientIdField, "settings.gateway.clientid.tip");

        // Client Secret
        JPanel clientSecretPanel = createLabeledField(I18n.t("settings.gateway.clientsecret"), gatewayClientSecretField = new JPasswordField(30));
        I18nUI.tip(gatewayClientSecretField, "settings.gateway.clientsecret.tip");

        // Requested Subject
        JPanel requestedSubjectPanel = createLabeledField(I18n.t("settings.gateway.subject"), gatewayRequestedSubjectField = new JTextField(30));
        I18nUI.tip(gatewayRequestedSubjectField, "settings.gateway.subject.tip");
        
        panel.add(usernamePanel);
        panel.add(Box.createVerticalStrut(8));
        panel.add(passwordPanel);
        panel.add(Box.createVerticalStrut(8));
        panel.add(clientIdPanel);
        panel.add(Box.createVerticalStrut(8));
        panel.add(clientSecretPanel);
        panel.add(Box.createVerticalStrut(8));
        panel.add(requestedSubjectPanel);
        
        // Initially hide Gateway panel
        panel.setVisible(false);
        
        return panel;
    }
    
    /**
     * Create Local AI Model configuration panel
     * (Ollama / LM Studio / llama.cpp - OpenAI compatible local servers)
     */
    private JPanel createLocalPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(ColorScheme.BG_CARD);
        panel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
            I18n.t("settings.local.title"),
            TitledBorder.LEFT,
            TitledBorder.TOP,
            new Font("Segoe UI", Font.BOLD, 12),
            ColorScheme.TEXT_DARK
        ));

        // Preset selector
        String[] presets = {"Ollama", "LM Studio", "llama.cpp", "Custom"};
        localPresetComboBox = new JComboBox<>(presets);
        localPresetComboBox.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        I18nUI.tip(localPresetComboBox, "settings.local.preset.tip");
        localPresetComboBox.addActionListener(e -> applyLocalPreset());
        JPanel presetPanel = createLabeledField(I18n.t("settings.local.preset"), localPresetComboBox);

        // Endpoint URL
        JPanel urlPanel = createLabeledField(I18n.t("settings.local.endpoint"), localApiUrlField = new JTextField(30));
        I18nUI.tip(localApiUrlField, "settings.local.endpoint.tip");

        // Model with refresh button
        localModelComboBox = new JComboBox<>(new String[]{"qwen2.5-coder:7b", "llama3.1:8b", "mistral:7b"});
        localModelComboBox.setEditable(true);
        localModelComboBox.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        I18nUI.tip(localModelComboBox, "settings.local.model.tip");

        JPanel localModelInner = new JPanel(new BorderLayout(5, 0));
        localModelInner.setBackground(ColorScheme.BG_CARD);
        localModelInner.add(localModelComboBox, BorderLayout.CENTER);
        JButton refreshLocalBtn = new JButton(Icons.getRefreshIcon(14));
        I18nUI.tip(refreshLocalBtn, "settings.local.model.refresh.tip");
        refreshLocalBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        refreshLocalBtn.setPreferredSize(new Dimension(35, 25));
        refreshLocalBtn.addActionListener(e -> refreshLocalModels());
        localModelInner.add(refreshLocalBtn, BorderLayout.EAST);
        JPanel modelPanel = createLabeledField(I18n.t("settings.local.model"), localModelInner);

        // Optional API key
        JPanel keyPanel = createLabeledField(I18n.t("settings.local.key"), localApiKeyField = new JTextField(30));
        I18nUI.tip(localApiKeyField, "settings.local.key.tip");

        // Info label
        JTextArea infoLabel = I18nUI.multiline("settings.local.info");
        infoLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        infoLabel.setForeground(ColorScheme.TEXT_SECONDARY);
        infoLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        panel.add(presetPanel);
        panel.add(Box.createVerticalStrut(8));
        panel.add(urlPanel);
        panel.add(Box.createVerticalStrut(8));
        panel.add(modelPanel);
        panel.add(Box.createVerticalStrut(8));
        panel.add(keyPanel);
        panel.add(Box.createVerticalStrut(8));
        panel.add(infoLabel);

        // Initially hidden
        panel.setVisible(false);

        return panel;
    }

    /**
     * Apply selected local preset URL into the endpoint field
     */
    private void applyLocalPreset() {
        String preset = (String) localPresetComboBox.getSelectedItem();
        if (preset == null) return;
        switch (preset) {
            case "Ollama":
                localApiUrlField.setText("http://localhost:11434/v1");
                break;
            case "LM Studio":
                localApiUrlField.setText("http://localhost:1234/v1");
                break;
            case "llama.cpp":
                localApiUrlField.setText("http://localhost:8080/v1");
                break;
            default:
                // Custom - leave field as-is
                break;
        }
    }

    /**
     * Apply the selected hosted-provider preset into the endpoint field. All are
     * OpenAI-compatible base URLs; the user still supplies their own API key + model.
     */
    private void applyHostedPreset() {
        String preset = (String) hostedPresetComboBox.getSelectedItem();
        if (preset == null) return;
        switch (preset) {
            case "OpenAI":     apiEndpointField.setText("https://api.openai.com/v1"); break;
            case "OpenRouter": apiEndpointField.setText("https://openrouter.ai/api/v1"); break;
            case "Groq":       apiEndpointField.setText("https://api.groq.com/openai/v1"); break;
            case "Together":   apiEndpointField.setText("https://api.together.xyz/v1"); break;
            case "DeepSeek":   apiEndpointField.setText("https://api.deepseek.com/v1"); break;
            default:           /* Custom - leave field as-is */ break;
        }
    }

    /** Friendly, localized label for a stored provider id ("hosted"/"local"/"gateway"). */
    private static String providerLabel(String id) {
        if (id == null) return "";
        String key = "settings.provider." + id;
        String label = I18n.t(key);
        return (label == null || label.equals(key)) ? id : label;   // fall back to the raw id
    }

    /**
     * Toggle API provider panels
     */
    private void toggleAPIProvider() {
        String selectedProvider = (String) apiProviderComboBox.getSelectedItem();
        
        // Find parent panel and toggle visibility
        Container parent = apiProviderComboBox.getParent();
        while (parent != null && !(parent instanceof JPanel)) {
            parent = parent.getParent();
        }
        
        if (parent instanceof JPanel) {
            Component[] components = ((JPanel) parent).getComponents();
            for (Component component : components) {
                if (component instanceof JPanel) {
                    JPanel panel = (JPanel) component;
                    if ("hostedPanel".equals(panel.getName())) {
                        panel.setVisible("hosted".equals(selectedProvider));
                    } else if ("gatewayPanel".equals(panel.getName())) {
                        panel.setVisible("gateway".equals(selectedProvider));
                    } else if ("localPanel".equals(panel.getName())) {
                        panel.setVisible("local".equals(selectedProvider));
                    } else if ("sharedModelPanel".equals(panel.getName())) {
                        // Local provider has its own model field; hide the shared one
                        panel.setVisible(!"local".equals(selectedProvider));
                    }
                }
            }
        }

        // Update model selection based on provider
        if ("gateway".equals(selectedProvider)) {
            modelComboBox.setSelectedItem("Qwen3-235B-FP8");
        } else if ("hosted".equals(selectedProvider)) {
            modelComboBox.setSelectedItem("gpt-4o-mini");
        }
        
        // Revalidate and repaint
        revalidate();
        repaint();
        
        // Log provider change
        stdout.println("[Settings] API Provider changed to: " + selectedProvider);
    }
    
    private JPanel createScanConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(ColorScheme.BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        ));
        
        // Title
        JLabel titleLabel = I18nUI.text(new JLabel(), "settings.scan.title");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        titleLabel.setForeground(ColorScheme.TEXT_DARK);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Checkboxes
        autoScanCheckBox = I18nUI.text(new JCheckBox(), "settings.scan.autoscan");
        autoScanCheckBox.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        autoScanCheckBox.setBackground(ColorScheme.BG_CARD);
        autoScanCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);

        useScopeCheckBox = I18nUI.text(new JCheckBox(), "settings.scan.usescope");
        useScopeCheckBox.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        useScopeCheckBox.setBackground(ColorScheme.BG_CARD);
        useScopeCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        // Confidence threshold slider
        JPanel confidencePanel = new JPanel(new BorderLayout(10, 5));
        confidencePanel.setBackground(ColorScheme.BG_CARD);
        confidencePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        confidencePanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 60));
        
        JLabel confidenceLabel = I18nUI.text(new JLabel(), "settings.scan.confidence");
        confidenceLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        confidenceLabel.setForeground(ColorScheme.TEXT_DARK);
        
        confidenceSlider = new JSlider(JSlider.HORIZONTAL, 0, 100, 70);
        confidenceSlider.setMajorTickSpacing(25);
        confidenceSlider.setMinorTickSpacing(5);
        confidenceSlider.setPaintTicks(true);
        confidenceSlider.setBackground(ColorScheme.BG_CARD);
        
        confidenceValueLabel = new JLabel("0.70");
        confidenceValueLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        confidenceValueLabel.setForeground(ColorScheme.PRIMARY_BLUE);
        
        confidenceSlider.addChangeListener(e -> {
            double value = confidenceSlider.getValue() / 100.0;
            confidenceValueLabel.setText(String.format("%.2f", value));
        });
        
        JPanel sliderPanel = new JPanel(new BorderLayout(5, 0));
        sliderPanel.setBackground(ColorScheme.BG_CARD);
        sliderPanel.add(confidenceSlider, BorderLayout.CENTER);
        sliderPanel.add(confidenceValueLabel, BorderLayout.EAST);
        
        confidencePanel.add(confidenceLabel, BorderLayout.NORTH);
        confidencePanel.add(sliderPanel, BorderLayout.CENTER);
        
        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(autoScanCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(useScopeCheckBox);
        panel.add(Box.createVerticalStrut(10));
        panel.add(confidencePanel);
        
        return panel;
    }
    
    private JPanel createFilterConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(ColorScheme.BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        ));
        
        // Title
        JLabel titleLabel = I18nUI.text(new JLabel(), "settings.filters.title");
        titleLabel.setFont(new Font("Segeo UI", Font.BOLD, 14));
        titleLabel.setForeground(ColorScheme.TEXT_DARK);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Filter checkboxes
        filterStaticFilesCheckBox = createCheckBox(I18n.t("settings.filters.static"));
        filterCDNCheckBox = createCheckBox(I18n.t("settings.filters.cdn"));
        filterAnalyticsCheckBox = createCheckBox(I18n.t("settings.filters.analytics"));
        filterSocialMediaCheckBox = createCheckBox(I18n.t("settings.filters.social"));
        filterOptionsCheckBox = createCheckBox(I18n.t("settings.filters.options"));

        // Custom filters
        JLabel customLabel = I18nUI.text(new JLabel(), "settings.filters.custom");
        customLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        customLabel.setForeground(ColorScheme.TEXT_DARK);
        customLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        customFiltersArea = new JTextArea(4, 30);
        customFiltersArea.setFont(new Font("Consolas", Font.PLAIN, 11));
        customFiltersArea.setBorder(BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT));
        JScrollPane customScroll = new JScrollPane(customFiltersArea);
        customScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        customScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 100));
        
        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(filterStaticFilesCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(filterCDNCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(filterAnalyticsCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(filterSocialMediaCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(filterOptionsCheckBox);
        panel.add(Box.createVerticalStrut(10));
        panel.add(customLabel);
        panel.add(Box.createVerticalStrut(5));
        panel.add(customScroll);
        
        return panel;
    }
    
    private JPanel createVulnTypeConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(ColorScheme.BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        ));
        
        // Title
        JLabel titleLabel = I18nUI.text(new JLabel(), "settings.vuln.title");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        titleLabel.setForeground(ColorScheme.TEXT_DARK);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Vulnerability checkboxes
        checkSQLiCheckBox = createCheckBox(I18n.t("settings.vuln.sqli"));
        checkXSSCheckBox = createCheckBox(I18n.t("settings.vuln.xss"));
        checkIDORCheckBox = createCheckBox(I18n.t("settings.vuln.idor"));
        checkSSRFCheckBox = createCheckBox(I18n.t("settings.vuln.ssrf"));
        checkLFICheckBox = createCheckBox(I18n.t("settings.vuln.lfi"));
        checkCommandInjCheckBox = createCheckBox(I18n.t("settings.vuln.cmdinj"));
        
        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(checkSQLiCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(checkXSSCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(checkIDORCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(checkSSRFCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(checkLFICheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(checkCommandInjCheckBox);

        return panel;
    }

    private JPanel createDynamicTestingPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(ColorScheme.BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        ));

        // Title
        JLabel titleLabel = I18nUI.text(new JLabel(), "settings.dynamic.title");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        titleLabel.setForeground(ColorScheme.TEXT_DARK);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Description
        JTextArea descLabel = I18nUI.multiline("settings.dynamic.desc");
        descLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        descLabel.setForeground(ColorScheme.TEXT_SECONDARY);
        descLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Dynamic test checkboxes
        businessLogicTestingCheckBox = createCheckBox(I18n.t("settings.dynamic.bizlogic"));
        idorTestingCheckBox = createCheckBox(I18n.t("settings.dynamic.idor"));
        jwtTestingCheckBox = createCheckBox(I18n.t("settings.dynamic.jwt"));
        wafEvasionCheckBox = createCheckBox(I18n.t("settings.dynamic.waf"));

        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(5));
        panel.add(descLabel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(businessLogicTestingCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(idorTestingCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(jwtTestingCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(wafEvasionCheckBox);

        // Usage instructions
        JTextArea usageLabel = I18nUI.multiline("settings.dynamic.usage");
        usageLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        usageLabel.setForeground(ColorScheme.PRIMARY_BLUE);
        usageLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(Box.createVerticalStrut(10));
        panel.add(usageLabel);

        return panel;
    }

    private JPanel createAIFeaturesPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(ColorScheme.BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)
        ));

        // Title
        JLabel titleLabel = I18nUI.text(new JLabel(), "settings.aifeatures.title");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        titleLabel.setForeground(ColorScheme.TEXT_DARK);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Description
        JTextArea descLabel = I18nUI.multiline("settings.aifeatures.desc");
        descLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        descLabel.setForeground(ColorScheme.TEXT_SECONDARY);
        descLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // AI feature checkboxes
        aiContextAnalysisCheckBox = createCheckBox(I18n.t("settings.aifeatures.context"));
        aiSmartPayloadsCheckBox = createCheckBox(I18n.t("settings.aifeatures.smartpayloads"));
        aiFalsePositiveFilterCheckBox = createCheckBox(I18n.t("settings.aifeatures.fpfilter"));

        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(5));
        panel.add(descLabel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(aiContextAnalysisCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(aiSmartPayloadsCheckBox);
        panel.add(Box.createVerticalStrut(5));
        panel.add(aiFalsePositiveFilterCheckBox);

        return panel;
    }

    private JPanel createDetectionEnginePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(ColorScheme.BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)));

        JLabel titleLabel = I18nUI.text(new JLabel(), "settings.engine.title");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        titleLabel.setForeground(ColorScheme.TEXT_DARK);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(10));

        // Fast model
        fastModelEnabledCheckBox = createCheckBox(I18n.t("settings.engine.fastmodel.enabled"));
        fastModelEnabledCheckBox.setToolTipText(tip(I18n.t("settings.engine.fastmodel.enabled.tip")));
        panel.add(fastModelEnabledCheckBox);
        panel.add(Box.createVerticalStrut(6));
        panel.add(createLabeledField(I18n.t("settings.engine.fastmodel"), fastModelField = new JTextField(24), I18n.t("settings.engine.fastmodel.tip")));
        panel.add(Box.createVerticalStrut(6));
        engineMaxTokensCombo = new JComboBox<>(new Integer[]{256, 512, 1024, 2048});
        engineMaxTokensCombo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        panel.add(createLabeledField(I18n.t("settings.engine.maxtokens"), engineMaxTokensCombo, I18n.t("settings.engine.maxtokens.tip")));
        panel.add(Box.createVerticalStrut(6));
        parallelismCombo = new JComboBox<>(new Integer[]{2, 4, 6, 8, 12, 16});
        parallelismCombo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        panel.add(createLabeledField(I18n.t("settings.engine.parallel"), parallelismCombo, I18n.t("settings.engine.parallel.tip")));
        panel.add(Box.createVerticalStrut(6));
        siteScanMaxCombo = new JComboBox<>(new Integer[]{20, 40, 60, 80, 100, 150, 200, 300, 500});
        siteScanMaxCombo.setEditable(true); // free-form: type any limit
        siteScanMaxCombo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        panel.add(createLabeledField(I18n.t("settings.engine.sitelimit"), siteScanMaxCombo, I18n.t("settings.engine.sitelimit.tip")));

        // HARD per-minute request ceiling shared by ALL scan paths — the firewall guard (an IP over the
        // firewall's sessions/min limit is banned for a day). Keep it safely below that limit.
        maxReqPerMinCombo = new JComboBox<>(new Integer[]{60, 100, 120, 150, 180, 200, 250, 300});
        maxReqPerMinCombo.setEditable(true); // free-form: type any per-minute ceiling
        maxReqPerMinCombo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        panel.add(createLabeledField(I18n.t("settings.engine.reqpermin"), maxReqPerMinCombo, I18n.t("settings.engine.reqpermin.tip")));
        panel.add(Box.createVerticalStrut(10));

        // OWASP modules (IDOR / access-control / injection / misconfig / SSRF / CAPTCHA),
        // the aggressive/intrusive tests (brute force / file upload / active SSRF / cmd-timing)
        // and the deep-AI pass are now ALWAYS-ON (see Settings defaults). The granular
        // checkboxes here were removed by user request ("default on"). Intrusive tests are
        // still gated at scan time by the per-scan confirmation dialog in BurpExtender.

        // ── Agentic AI Pentester + Login profiles MOVED OUT of Settings (2026-06-25) ──
        // The whole "AI Pentester (ajan ReAct)" block — agent max-steps/model AND the login
        // profiles (capture wizard + raw-JSON editor + test) — now lives in a friendly popup
        // opened from the "Yetki Matrisi" (Authorization Matrix) tab → "🔐 Login Profilleri"
        // button (burp.authz.LoginProfilesDialog). That's where login profiles are actually used
        // (they mint fresh sessions per scan for the matrix / BOLA). Only a pointer is left here.
        panel.add(Box.createVerticalStrut(12));
        JTextArea agentMovedNote = I18nUI.multiline("settings.agent.movedNote");
        agentMovedNote.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        agentMovedNote.setForeground(ColorScheme.TEXT_SECONDARY);
        agentMovedNote.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(agentMovedNote);
        panel.add(Box.createVerticalStrut(8));

        // ── Ambient Security Copilot (passive triage + autonomous hunter) ──
        panel.add(Box.createVerticalStrut(12));
        JLabel ambLabel = I18nUI.text(new JLabel(), "settings.ambient.title");
        ambLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        ambLabel.setForeground(ColorScheme.ERROR_RED);
        ambLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(ambLabel);
        JTextArea ambWarn = I18nUI.multiline("settings.ambient.warn");
        ambWarn.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        ambWarn.setForeground(ColorScheme.TEXT_SECONDARY);
        ambWarn.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(ambWarn);
        panel.add(Box.createVerticalStrut(4));
        // Passive triage, the autonomous background hunter, scope-only and share-rate-limiter
        // are now ALWAYS-ON via Settings defaults; their checkboxes were removed ("default on").
        // The hunter can still be stopped at runtime from the AI Copilot panel's kill switch.
        ambientMinScoreCombo = new JComboBox<>(new Integer[]{20, 30, 35, 45, 60, 75});
        ambientMinScoreCombo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        panel.add(createLabeledField(I18n.t("settings.ambient.minscore"), ambientMinScoreCombo, I18n.t("settings.ambient.minscore.tip")));
        panel.add(Box.createVerticalStrut(6));
        agentSiteConcurrencyCombo = new JComboBox<>(new Integer[]{1, 2, 3, 4, 6, 8});
        agentSiteConcurrencyCombo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        panel.add(createLabeledField(I18n.t("settings.ambient.concurrency"), agentSiteConcurrencyCombo, I18n.t("settings.ambient.concurrency.tip")));
        panel.add(Box.createVerticalStrut(6));
        panel.add(createLabeledField(I18n.t("settings.ambient.tokenbudget"),
                agentTokenBudgetField = new JTextField(12), I18n.t("settings.ambient.tokenbudget.tip")));
        panel.add(Box.createVerticalStrut(6));
        agentTimeBudgetCombo = new JComboBox<>(new Integer[]{0, 5, 10, 15, 30, 60, 120});
        agentTimeBudgetCombo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        panel.add(createLabeledField(I18n.t("settings.ambient.timebudget"), agentTimeBudgetCombo, I18n.t("settings.ambient.timebudget.tip")));
        panel.add(Box.createVerticalStrut(6));
        agentRouterModeCombo = new JComboBox<>(new String[]{"all", "heuristic", "ai"});
        agentRouterModeCombo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        panel.add(createLabeledField(I18n.t("settings.ambient.routermode"), agentRouterModeCombo, I18n.t("settings.ambient.routermode.tip")));

        panel.add(Box.createVerticalStrut(6));
        heuristicScanCheckBox = createCheckBox(I18n.t("settings.scan.heuristic"));
        heuristicScanCheckBox.setToolTipText(tip(I18n.t("settings.scan.heuristic.tip")));
        panel.add(heuristicScanCheckBox);

        return panel;
    }

    /** Optional hook the extension sets so saving applies ambient toggles without a restart. */
    public void setAmbientApplyHook(Runnable r) {
        this.ambientApplyHook = r;
    }

    /** Optional hook the extension sets so saving re-localizes the whole UI live (no restart). */
    public void setLanguageApplyHook(Runnable r) {
        this.languageApplyHook = r;
    }

    private JPanel createActionPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        panel.setBackground(ColorScheme.BG_LIGHT);
        panel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, ColorScheme.BORDER_LIGHT));
        
        // Save button
        JButton saveButton = I18nUI.text(new JButton(), "settings.action.save");
        saveButton.setFont(new Font("Segoe UI", Font.BOLD, 12));
        saveButton.setBackground(ColorScheme.SUCCESS_GREEN);
        saveButton.setForeground(Color.WHITE);
        saveButton.setFocusPainted(false);
        saveButton.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
        saveButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        saveButton.addActionListener(e -> saveSettings());
        
        // Test connection button
        JButton testButton = I18nUI.text(new JButton(), "settings.action.test");
        testButton.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        testButton.setBackground(ColorScheme.PRIMARY_BLUE);
        testButton.setForeground(Color.WHITE);
        testButton.setFocusPainted(false);
        testButton.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
        testButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        testButton.addActionListener(e -> testConnection());
        
        // Reset to defaults button
        JButton resetButton = I18nUI.text(new JButton(), "settings.action.reset");
        resetButton.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        resetButton.setBackground(ColorScheme.BG_CARD);
        resetButton.setForeground(ColorScheme.TEXT_DARK);
        resetButton.setFocusPainted(false);
        resetButton.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
            BorderFactory.createEmptyBorder(9, 19, 9, 19)
        ));
        resetButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        resetButton.addActionListener(e -> resetToDefaults());

        // Clear Database button
        JButton clearDbButton = I18nUI.text(new JButton(), "settings.action.cleardb");
        clearDbButton.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        clearDbButton.setBackground(ColorScheme.ERROR_RED);
        clearDbButton.setForeground(Color.WHITE);
        clearDbButton.setFocusPainted(false);
        clearDbButton.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
        clearDbButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        clearDbButton.addActionListener(e -> clearDatabase());

        panel.add(saveButton);
        panel.add(testButton);
        panel.add(resetButton);
        panel.add(clearDbButton);

        return panel;
    }
    
    private JPanel createLabeledField(String label, JComponent component) {
        JPanel panel = new JPanel(new BorderLayout(10, 0));
        panel.setBackground(ColorScheme.BG_CARD);
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 35));
        
        JLabel jLabel = new JLabel(label);
        jLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        jLabel.setForeground(ColorScheme.TEXT_DARK);
        jLabel.setPreferredSize(new Dimension(150, 25));
        
        if (component instanceof JTextField) {
            component.setMaximumSize(new Dimension(Integer.MAX_VALUE, 25));
        }
        
        panel.add(jLabel, BorderLayout.WEST);
        panel.add(component, BorderLayout.CENTER);

        return panel;
    }

    /** As {@link #createLabeledField(String, JComponent)} but also sets a hover tooltip on BOTH the
     *  label and the input, so the user can read what the field does by hovering over either. */
    private JPanel createLabeledField(String label, JComponent component, String tooltip) {
        String t = tip(tooltip);
        if (t != null) component.setToolTipText(t);
        JPanel panel = createLabeledField(label, component);
        if (t != null) {
            for (Component c : panel.getComponents()) {
                if (c instanceof JLabel) { ((JLabel) c).setToolTipText(t); break; }
            }
        }
        return panel;
    }

    /** Wrap tooltip text in fixed-width HTML so a long description wraps to several readable lines
     *  instead of one very wide line. Returns null for blank input. */
    private static String tip(String s) {
        return (s == null || s.isEmpty()) ? null : "<html><div style='width:340px'>" + s + "</div></html>";
    }
    
    private JCheckBox createCheckBox(String text) {
        JCheckBox checkBox = new JCheckBox(text);
        checkBox.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        checkBox.setBackground(ColorScheme.BG_CARD);
        checkBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        return checkBox;
    }

    /**
     * Read-only card showing how much the AI/LLM has been used and how many tokens
     * it consumed. Values come from {@link AIUsageStats}; "🔄 Yenile" re-reads them.
     */
    private JPanel createAiUsagePanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(ColorScheme.BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
            BorderFactory.createEmptyBorder(15, 15, 15, 15)));

        JLabel titleLabel = I18nUI.text(new JLabel(), "settings.usage.title");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        titleLabel.setForeground(ColorScheme.TEXT_DARK);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(10));

        aiUsageCallsLbl = usageValueLabel();
        aiUsageTokensLbl = usageValueLabel();
        aiUsageTokensLbl.setFont(new Font("Segoe UI", Font.BOLD, 13));
        aiUsageTokensLbl.setForeground(ColorScheme.PRIMARY_BLUE);
        aiUsagePromptLbl = usageValueLabel();
        aiUsageCompletionLbl = usageValueLabel();
        aiUsageCacheLbl = usageValueLabel();
        aiUsageSinceLbl = usageValueLabel();

        panel.add(createLabeledField(I18n.t("settings.usage.calls"), aiUsageCallsLbl));
        panel.add(Box.createVerticalStrut(4));
        panel.add(createLabeledField(I18n.t("settings.usage.tokens"), aiUsageTokensLbl));
        panel.add(Box.createVerticalStrut(4));
        panel.add(createLabeledField(I18n.t("settings.usage.prompt"), aiUsagePromptLbl));
        panel.add(Box.createVerticalStrut(4));
        panel.add(createLabeledField(I18n.t("settings.usage.completion"), aiUsageCompletionLbl));
        panel.add(Box.createVerticalStrut(4));
        panel.add(createLabeledField(I18n.t("settings.usage.cache"), aiUsageCacheLbl));
        panel.add(Box.createVerticalStrut(4));
        panel.add(createLabeledField(I18n.t("settings.usage.since"), aiUsageSinceLbl));
        panel.add(Box.createVerticalStrut(10));

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        btnRow.setBackground(ColorScheme.BG_CARD);
        btnRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        btnRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));

        JButton refreshBtn = I18nUI.text(new JButton(), "settings.usage.refresh");
        refreshBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        refreshBtn.setBackground(ColorScheme.PRIMARY_BLUE);
        refreshBtn.setForeground(Color.WHITE);
        refreshBtn.setFocusPainted(false);
        refreshBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        refreshBtn.addActionListener(e -> refreshAiUsage());

        JButton resetBtn = I18nUI.text(new JButton(), "settings.usage.reset");
        resetBtn.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        resetBtn.setBackground(ColorScheme.BG_CARD);
        resetBtn.setForeground(ColorScheme.TEXT_DARK);
        resetBtn.setFocusPainted(false);
        resetBtn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
            BorderFactory.createEmptyBorder(5, 14, 5, 14)));
        resetBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        resetBtn.addActionListener(e -> {
            int r = JOptionPane.showConfirmDialog(this,
                I18n.t("settings.usage.reset.confirm"), I18n.t("settings.usage.reset.confirm.title"), JOptionPane.YES_NO_OPTION);
            if (r == JOptionPane.YES_OPTION) {
                AIUsageStats.getInstance().reset();
                refreshAiUsage();
            }
        });

        btnRow.add(refreshBtn);
        btnRow.add(resetBtn);
        panel.add(btnRow);

        JTextArea note = I18nUI.multiline("settings.usage.note");
        note.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        note.setForeground(ColorScheme.TEXT_SECONDARY);
        note.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(Box.createVerticalStrut(8));
        panel.add(note);

        refreshAiUsage();
        return panel;
    }

    private JLabel usageValueLabel() {
        JLabel l = new JLabel("0");
        l.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        l.setForeground(ColorScheme.TEXT_DARK);
        return l;
    }

    /** Pull the latest counters from AIUsageStats into the display labels. */
    private void refreshAiUsage() {
        if (aiUsageCallsLbl == null) return;
        AIUsageStats s = AIUsageStats.getInstance();
        aiUsageCallsLbl.setText(String.format("%,d", s.getTotalCalls())
                + (s.getFailures() > 0 ? "  " + I18n.t("settings.usage.errors", String.valueOf(s.getFailures())) : ""));
        aiUsageTokensLbl.setText(I18n.t("settings.usage.value.tokens", String.format("%,d", s.getTotalTokens())));
        aiUsagePromptLbl.setText(String.format("%,d", s.getPromptTokens()));
        aiUsageCompletionLbl.setText(String.format("%,d", s.getCompletionTokens()));
        aiUsageCacheLbl.setText(I18n.t("settings.usage.value.calls", String.format("%,d", s.getCacheHits())));
        aiUsageSinceLbl.setText(formatSince(s.getSinceMs(), s.getLastMs()));
    }

    private String formatSince(long sinceMs, long lastMs) {
        if (sinceMs <= 0) return "—";
        java.text.SimpleDateFormat fmt = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm");
        String out = fmt.format(new java.util.Date(sinceMs));
        if (lastMs > 0) {
            out += I18n.t("settings.usage.lastseen", fmt.format(new java.util.Date(lastMs)));
        }
        return out;
    }

    private void loadSettings() {
        try {
            currentSettings = settingsManager.getSettings();

            // UI language
            if (languageComboBox != null) {
                languageComboBox.setSelectedIndex("en".equalsIgnoreCase(currentSettings.getLanguage()) ? 1 : 0);
            }

            // API Configuration
            apiProviderComboBox.setSelectedItem(currentSettings.getApiProvider());
            apiEndpointField.setText(currentSettings.getApiEndpoint());
            apiKeyField.setText(currentSettings.getApiKey());
            modelComboBox.setSelectedItem(currentSettings.getModel());
            timeoutComboBox.setSelectedItem(currentSettings.getTimeout());

            // Auto-discover the provider's models once (silent, background) so the dropdown is pre-filled
            // without clicking ↻. Only when the API key is configured (avoids a failing call when blank).
            if (!modelsAutoFetched) {
                String key = currentSettings.getApiKey();
                if (key != null && !key.trim().isEmpty()) {
                    modelsAutoFetched = true;
                    refreshModels(true);
                }
            }
            
            // Gateway API Configuration
            gatewayUsernameField.setText(currentSettings.getGatewayUsername());
            gatewayPasswordField.setText(currentSettings.getGatewayPassword());
            gatewayClientIdField.setText(currentSettings.getGatewayClientId());
            gatewayClientSecretField.setText(currentSettings.getGatewayClientSecret());
            gatewayRequestedSubjectField.setText(currentSettings.getGatewayRequestedSubject());

            // Local AI Model Configuration
            localApiUrlField.setText(currentSettings.getLocalApiUrl());
            localModelComboBox.setSelectedItem(currentSettings.getLocalModel());
            localApiKeyField.setText(currentSettings.getLocalApiKey());

            // Toggle API provider panels
            toggleAPIProvider();
            
            // Scan Configuration
            autoScanCheckBox.setSelected(currentSettings.isAutoScan());
            useScopeCheckBox.setSelected(currentSettings.isUseScope());
            if (heuristicScanCheckBox != null) heuristicScanCheckBox.setSelected(currentSettings.isHeuristicScanEnabled());
            confidenceSlider.setValue((int) (currentSettings.getMinConfidence() * 100));

            // Detection Engine
            fastModelEnabledCheckBox.setSelected(currentSettings.isFastModelEnabled());
            fastModelField.setText(currentSettings.getFastModel());
            engineMaxTokensCombo.setSelectedItem(currentSettings.getEngineMaxTokens());
            parallelismCombo.setSelectedItem(currentSettings.getActiveScanParallelism());
            siteScanMaxCombo.setSelectedItem(currentSettings.getSiteScanMaxEndpoints());
            maxReqPerMinCombo.setSelectedItem(currentSettings.getMaxRequestsPerMinute());

            // Agentic AI Pentester config + login profiles are loaded/edited in the
            // "Yetki Matrisi" tab popup (burp.authz.LoginProfilesDialog), not here.

            ambientMinScoreCombo.setSelectedItem(currentSettings.getAmbientMinScore());
            agentSiteConcurrencyCombo.setSelectedItem(currentSettings.getAgentSiteConcurrency());
            agentTokenBudgetField.setText(String.valueOf(currentSettings.getAgentSiteTokenBudget()));
            agentTimeBudgetCombo.setSelectedItem(currentSettings.getAgentSiteTimeBudgetMin());
            agentRouterModeCombo.setSelectedItem(currentSettings.getAgentRouterMode());

            stdout.println("[Settings] Loaded successfully");
        } catch (Exception e) {
            stderr.println("[Settings] Error loading: " + e.getMessage());
        }
    }
    
    /**
     * Save settings to SettingsManager
     */
    private void saveSettings() {
        try {
            // Update current settings
            currentSettings.setApiProvider((String) apiProviderComboBox.getSelectedItem());
            currentSettings.setApiEndpoint(apiEndpointField.getText().trim());
            currentSettings.setApiKey(apiKeyField.getText().trim());
            currentSettings.setModel((String) modelComboBox.getSelectedItem());
            currentSettings.setTimeout((Integer) timeoutComboBox.getSelectedItem());

            // UI language — only trigger the (expensive) live rebuild when it actually changed.
            boolean langChanged = false;
            if (languageComboBox != null) {
                String prevLang = currentSettings.getLanguage();
                String lang = languageComboBox.getSelectedIndex() == 1 ? "en" : "tr";
                langChanged = !lang.equals(prevLang);
                currentSettings.setLanguage(lang);
                I18n.setLang(lang);
            }

            // Gateway API Configuration
            currentSettings.setGatewayUsername(gatewayUsernameField.getText().trim());
            currentSettings.setGatewayPassword(new String(gatewayPasswordField.getPassword()));
            currentSettings.setGatewayClientId(gatewayClientIdField.getText().trim());
            currentSettings.setGatewayClientSecret(new String(gatewayClientSecretField.getPassword()));
            currentSettings.setGatewayRequestedSubject(gatewayRequestedSubjectField.getText().trim());

            // Local AI Model Configuration
            currentSettings.setLocalApiUrl(localApiUrlField.getText().trim());
            Object localModelSel = localModelComboBox.getSelectedItem();
            currentSettings.setLocalModel(localModelSel != null ? localModelSel.toString().trim() : "");
            currentSettings.setLocalApiKey(localApiKeyField.getText().trim());

            currentSettings.setAutoScan(autoScanCheckBox.isSelected());
            currentSettings.setUseScope(useScopeCheckBox.isSelected());
            if (heuristicScanCheckBox != null) currentSettings.setHeuristicScanEnabled(heuristicScanCheckBox.isSelected());
            currentSettings.setMinConfidence(confidenceSlider.getValue() / 100.0);

            // Detection Engine
            currentSettings.setFastModelEnabled(fastModelEnabledCheckBox.isSelected());
            currentSettings.setFastModel(fastModelField.getText().trim());
            currentSettings.setEngineMaxTokens((Integer) engineMaxTokensCombo.getSelectedItem());
            currentSettings.setActiveScanParallelism((Integer) parallelismCombo.getSelectedItem());
            // Editable combo: selected item may be an Integer or a typed String.
            Object siteMaxSel = siteScanMaxCombo.getSelectedItem();
            try {
                int n = Integer.parseInt(String.valueOf(siteMaxSel).trim());
                if (n > 0) currentSettings.setSiteScanMaxEndpoints(n);
            } catch (NumberFormatException ignore) { }
            // Editable combo: per-minute request ceiling (WAF/FW guard).
            Object reqPerMinSel = maxReqPerMinCombo.getSelectedItem();
            try {
                int n = Integer.parseInt(String.valueOf(reqPerMinSel).trim());
                if (n > 0) currentSettings.setMaxRequestsPerMinute(n);
            } catch (NumberFormatException ignore) { }

            // Agentic AI Pentester (max-steps / model) and login profiles are saved by the
            // "Yetki Matrisi" tab popup (burp.authz.LoginProfilesDialog) directly via
            // SettingsManager — this panel no longer owns those fields, so their values on the
            // shared Settings instance are preserved untouched across a Settings save.
            // Agentic-focus + ambient on/off flags are always-on (checkboxes removed); their
            // values stay as loaded. The ambient apply-hook below still consent-gates the hunter.

            currentSettings.setAmbientMinScore((Integer) ambientMinScoreCombo.getSelectedItem());
            currentSettings.setAgentSiteConcurrency((Integer) agentSiteConcurrencyCombo.getSelectedItem());
            try {
                currentSettings.setAgentSiteTokenBudget(Long.parseLong(agentTokenBudgetField.getText().trim()));
            } catch (Exception ex) {
                currentSettings.setAgentSiteTokenBudget(0L);
            }
            currentSettings.setAgentSiteTimeBudgetMin((Integer) agentTimeBudgetCombo.getSelectedItem());
            currentSettings.setAgentRouterMode((String) agentRouterModeCombo.getSelectedItem());

            // Save to file
            settingsManager.saveSettings(currentSettings);

            // Propagate model/endpoint/key changes to the live client instance so every
            // component (ScanManager, AssistantPanel, etc.) picks up the new settings
            // without requiring an extension reload.
            aiClient.rebuildFromSettings(currentSettings);

            // Apply ambient toggles (start/stop triage + hunter) without a restart.
            if (ambientApplyHook != null) {
                try { ambientApplyHook.run(); } catch (Exception ignore) {}
            }

            // Apply the UI language live — only when it changed (rebuilds the deep panels).
            if (langChanged && languageApplyHook != null) {
                try { languageApplyHook.run(); } catch (Exception ignore) {}
            }

            stdout.println("[Settings] Saved successfully");
            JOptionPane.showMessageDialog(
                this,
                I18n.t("settings.save.success"),
                I18n.t("settings.title"),
                JOptionPane.INFORMATION_MESSAGE
            );
        } catch (Exception e) {
            stderr.println("[Settings] Error saving: " + e.getMessage());
            JOptionPane.showMessageDialog(
                this,
                I18n.t("settings.save.error", e.getMessage()),
                I18n.t("settings.dialog.error.title"),
                JOptionPane.ERROR_MESSAGE
            );
        }
    }
    
    /**
     * Test API connection with detailed error reporting
     */
    // Models known to work well for this tool (eval 2026-06-22) — used to steer the user when their
    // selected model fails. The combo is editable, so anyone can still type a custom model name.
    /**
     * Models in SECURITY order, most-secure first (rank 1) → least-secure last (rank 10). Stored as
     * distinctive id fragments so they match the gateway's prefixed ids (e.g. "qwen/qwen3-next-80b")
     * via {@code contains}. Drives both the probe set and the per-model security score shown to the user.
     */
    private static final String[] MODEL_SECURITY_RANK = {
            "qwen3-next-80b",     // 1  (most secure)
            "qwen3-coder-next",   // 2  (current)
            "gemma-4-26b-a4b",    // 3
            "qwen3-coder-30b",    // 4
            "qwen3.6-35b-a3b",    // 5
            "foundation-sec",     // 6
            "qwen3.6-27b",        // 7
            "qwen3.5-35b-a3b",    // 8
            "llama-3.3-70b",      // 9
            "gpt-oss-120b",       // 10 (least secure)
    };

    /** Security rank 1..10 for a model id (lower = more secure), or 0 if not in the ranking. */
    private static int securityRank(String id) {
        if (id == null) return 0;
        String low = id.toLowerCase();
        for (int i = 0; i < MODEL_SECURITY_RANK.length; i++) {
            if (low.contains(MODEL_SECURITY_RANK[i])) return i + 1;
        }
        return 0;
    }

    /** Display score 1..10 (10 = most secure), or 0 if unknown. */
    private static int securityScore(String id) {
        int r = securityRank(id);
        return r == 0 ? 0 : (MODEL_SECURITY_RANK.length + 1 - r);
    }

    /** Foreground colour for a security score (green = secure → red = insecure → grey = unknown). */
    private static Color securityColor(int score) {
        if (score >= 8) return new Color(0x43A047);
        if (score >= 5) return new Color(0xF9A825);
        if (score >= 1) return new Color(0xE53935);
        return Color.GRAY;
    }

    private static class ModelProbeResult {
        final String model; final boolean ok; final long ms; final String error;
        ModelProbeResult(String model, boolean ok, long ms, String error) {
            this.model = model; this.ok = ok; this.ms = ms; this.error = error;
        }
    }

    /** Send a tiny chat completion to verify the model actually GENERATES (not just /models reachable). */
    private ModelProbeResult probeModel(AiApiClient client, String model) {
        long t0 = System.currentTimeMillis();
        try {
            java.util.List<AiApiClient.Message> msgs = new java.util.ArrayList<>();
            msgs.add(new AiApiClient.Message("user", "Reply with exactly: OK"));
            org.json.JSONObject resp = client.chatCompletion(msgs, 0.0, 8, model, 1);
            long ms = System.currentTimeMillis() - t0;
            if (resp == null || resp.has("error")) {
                return new ModelProbeResult(model, false, ms, resp == null
                        ? I18n.t("settings.probe.emptyresponse")
                        : cleanProbeError(String.valueOf(resp.opt("error"))));
            }
            // A valid 200 completion (a non-empty choices array) = the model is up and serving — even
            // if the text content is empty. Reasoning/MoE models (…-a3b) can spend a tiny max_tokens=8
            // budget entirely on internal thinking and return empty content; for an availability probe
            // a 200 still means "working", so don't false-negative those as "boş içerik döndü".
            org.json.JSONArray choices = resp.optJSONArray("choices");
            boolean ok = choices != null && choices.length() > 0;
            return new ModelProbeResult(model, ok, ms, ok ? null : I18n.t("settings.probe.emptycontent"));
        } catch (Exception e) {
            Throwable c = e.getCause() != null ? e.getCause() : e;
            return new ModelProbeResult(model, false, System.currentTimeMillis() - t0,
                    cleanProbeError(String.valueOf(c.getMessage())));
        }
    }

    /**
     * Turn a raw probe error (an exception message or error blob — often an HTML error page or a JSON
     * error body) into a short, human-readable reason for the ✗ rows.
     */
    private static String cleanProbeError(String raw) {
        if (raw == null || raw.isEmpty() || "null".equals(raw)) return I18n.t("settings.probe.err.unknown");
        String low = raw.toLowerCase();
        if (low.contains("timed out") || low.contains("timeout"))
            return I18n.t("settings.probe.err.timeout");
        java.util.regex.Matcher cm = java.util.regex.Pattern.compile("\\b([45]\\d\\d)\\b").matcher(raw);
        String code = cm.find() ? cm.group(1) : null;
        // A JSON error body → surface the actual {"error":{"message":"..."}} text.
        java.util.regex.Matcher mm =
                java.util.regex.Pattern.compile("\"message\"\\s*:\\s*\"([^\"]{1,90})").matcher(raw);
        if (mm.find()) {
            String msg = mm.group(1).trim();
            return code != null ? ("HTTP " + code + ": " + msg) : msg;
        }
        // An HTML error page (gateway/proxy) → no useful text, just say "server error".
        if (low.contains("<!doctype") || low.contains("<html"))
            return I18n.t("settings.probe.err.server", code != null ? code : "5xx");
        if (code != null) {
            return code.startsWith("4")
                    ? I18n.t("settings.probe.err.notfound", code)
                    : I18n.t("settings.probe.err.server", code);
        }
        // Transport-level failures (no HTTP response): server unreachable / connection dropped.
        if (low.contains("reset") || low.contains("refused") || low.contains("unexpected end")
                || low.contains("failed to connect") || low.contains("unable to connect")
                || low.contains("no route to host") || low.contains("unreachable")
                || low.contains("connect timed out") || low.contains("eof"))
            return I18n.t("settings.probe.err.conn");
        String s = raw.replaceAll("<[^>]+>", " ").replaceAll("\\s+", " ").trim();
        return s.length() > 60 ? s.substring(0, 60) + "…" : s;
    }

    /**
     * Modeless dialog shown the INSTANT "Test Connection" is clicked: an indeterminate progress bar,
     * a live status line, and a list of working models that grows as each model responds. Replaces
     * the old "frozen, then a popup" behaviour — the user sees it working immediately and watches
     * results stream in.
     */
    private class LiveTestDialog {
        private final JDialog dialog;
        private final JTextArea statusArea = new JTextArea(2, 1);
        private final JProgressBar bar = new JProgressBar();
        private final DefaultListModel<String> listModel = new DefaultListModel<>();
        private final JList<String> list = new JList<>(listModel);
        private final JButton retryBtn = new JButton(I18n.t("settings.live.retry"));
        private final java.util.List<ModelProbeResult> results =
                java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        /** EDT-only: mirrors the on-screen list order (security-sorted) so a selection maps to a model. */
        private final java.util.List<ModelProbeResult> displayed = new java.util.ArrayList<>();
        private volatile int total;   // models being probed this run (for the live progress line)
        private volatile boolean done; // true once a finish*/fail set the terminal status (don't overwrite)

        LiveTestDialog() {
            dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(SettingsPanel.this),
                    I18n.t("settings.live.title"), false); // modeless → does NOT block the EDT
            dialog.setSize(560, 440);
            dialog.setLocationRelativeTo(SettingsPanel.this);

            JPanel p = new JPanel(new BorderLayout(10, 10));
            p.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
            p.setBackground(ColorScheme.BG_CARD);

            // Status is a wrapping, read-only text area — Burp's L&F does NOT render <html> in a
            // JLabel (the raw tags would show), so we never use HTML here.
            statusArea.setFont(new Font("Segoe UI", Font.BOLD, 13));
            statusArea.setEditable(false);
            statusArea.setLineWrap(true);
            statusArea.setWrapStyleWord(true);
            statusArea.setOpaque(false);
            statusArea.setFocusable(false);
            statusArea.setBorder(null);
            bar.setIndeterminate(true);
            JLabel listLabel = new JLabel(I18n.t("settings.live.workinglist"));
            listLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            JPanel top = new JPanel(new BorderLayout(0, 8));
            top.setOpaque(false);
            top.add(statusArea, BorderLayout.NORTH);
            top.add(bar, BorderLayout.CENTER);
            top.add(listLabel, BorderLayout.SOUTH);
            p.add(top, BorderLayout.NORTH);

            list.setFont(new Font("Consolas", Font.PLAIN, 12));
            list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            // Colour each row by its security score (green = most secure → red = least → grey = unknown).
            list.setCellRenderer(new DefaultListCellRenderer() {
                @Override public Component getListCellRendererComponent(JList<?> l, Object val, int idx,
                                                                        boolean sel, boolean foc) {
                    Component c = super.getListCellRendererComponent(l, val, idx, sel, foc);
                    if (!sel && idx >= 0 && idx < displayed.size()) {
                        ModelProbeResult w = displayed.get(idx);
                        c.setForeground(w.ok ? securityColor(securityScore(w.model)) : Color.GRAY);
                    }
                    return c;
                }
            });
            p.add(new JScrollPane(list), BorderLayout.CENTER);

            retryBtn.setEnabled(false);
            retryBtn.addActionListener(e -> runConnectionTest(LiveTestDialog.this)); // re-run on the same dialog
            JButton closeBtn = new JButton(I18n.t("settings.live.close"));
            closeBtn.addActionListener(e -> dialog.dispose());
            JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
            btns.setOpaque(false);
            btns.add(closeBtn);
            btns.add(retryBtn);

            JLabel legend = new JLabel(I18n.t("settings.live.seclegend"));
            legend.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            legend.setForeground(ColorScheme.TEXT_SECONDARY);
            JPanel south = new JPanel(new BorderLayout(0, 6));
            south.setOpaque(false);
            south.add(legend, BorderLayout.NORTH);
            south.add(btns, BorderLayout.SOUTH);
            p.add(south, BorderLayout.SOUTH);

            dialog.setContentPane(p);
            setStatus(I18n.t("settings.live.starting"), ColorScheme.TEXT_DARK);
        }

        void show() { dialog.setVisible(true); }

        private void setStatus(String text, Color c) {
            statusArea.setText(text);
            statusArea.setForeground(c);
        }

        /** Reset to the initial "running" state so the test can be re-run (Retry button). */
        void reset() {
            SwingUtilities.invokeLater(() -> {
                results.clear();
                displayed.clear();
                listModel.clear();
                total = 0;
                done = false;
                retryBtn.setEnabled(false);
                bar.setValue(0);
                bar.setIndeterminate(true);
                setStatus(I18n.t("settings.live.starting"), ColorScheme.TEXT_DARK);
            });
        }

        /** Update the status line (called from the worker thread → marshalled to the EDT). */
        void status(String key, Object... args) {
            SwingUtilities.invokeLater(() -> setStatus(I18n.t(key, args), ColorScheme.TEXT_DARK));
        }

        /** Set how many models will be probed this run (drives the live progress line). */
        void setTotal(int n) { total = n; }

        /** A probe finished (working OR failed) — add it to the live, security-sorted list. Thread-safe. */
        void addResult(ModelProbeResult r) {
            results.add(r);
            SwingUtilities.invokeLater(() -> {
                java.util.List<ModelProbeResult> snap;
                synchronized (results) { snap = new java.util.ArrayList<>(results); }
                // most-secure first (rank 1); unknown models (rank 0) last; tie-break by speed.
                snap.sort((a, b) -> {
                    int ra = securityRank(a.model), rb = securityRank(b.model);
                    int ka = (ra == 0) ? Integer.MAX_VALUE : ra;
                    int kb = (rb == 0) ? Integer.MAX_VALUE : rb;
                    if (ka != kb) return Integer.compare(ka, kb);
                    return Long.compare(a.ms, b.ms);
                });
                String prevModel = (list.getSelectedIndex() >= 0 && list.getSelectedIndex() < displayed.size())
                        ? displayed.get(list.getSelectedIndex()).model : null;
                displayed.clear();
                displayed.addAll(snap);
                listModel.clear();
                for (ModelProbeResult w : snap) listModel.addElement(rowText(w));
                int keep = -1;
                if (prevModel != null) {
                    for (int i = 0; i < displayed.size(); i++) {
                        if (displayed.get(i).model.equals(prevModel)) { keep = i; break; }
                    }
                }
                if (keep < 0) keep = firstOkIndex();   // default selection = most-secure WORKING model
                if (keep >= 0) list.setSelectedIndex(keep);
                if (total > 0 && !done) setStatus(I18n.t("settings.live.progress",
                        String.valueOf(snap.size()), String.valueOf(total)), ColorScheme.TEXT_DARK);
            });
        }

        /** Index of the first working row in the displayed order, or -1 if none. */
        private int firstOkIndex() {
            for (int i = 0; i < displayed.size(); i++) if (displayed.get(i).ok) return i;
            return -1;
        }

        /** A list row: working → 🛡 score + id + latency; failed → ✗ + id + short error. */
        private String rowText(ModelProbeResult w) {
            if (w.ok) {
                int score = securityScore(w.model);
                String shield = Glyphs.emojiOk() ? "🛡 " : "";
                String badge = score > 0 ? (shield + score + "/10") : (shield + "—");
                return badge + "   " + w.model + "   (" + w.ms + " ms)";
            }
            String err = (w.error == null || w.error.isEmpty()) ? "—" : w.error;
            if (err.length() > 44) err = err.substring(0, 44) + "…";
            return Glyphs.fail() + "   " + w.model + "   (" + err + ")";
        }

        /** Stop the spinner and offer Retry (run on the EDT inside the finish* helpers). */
        private void terminal() {
            done = true;
            bar.setIndeterminate(false);
            retryBtn.setEnabled(true);
        }

        /** Terminal success (selected model works, or gateway endpoint reachable). */
        void finishOk(String key, Object... args) {
            SwingUtilities.invokeLater(() -> {
                terminal(); bar.setValue(100);
                setStatus(I18n.t(key, args), ColorScheme.SUCCESS_GREEN);
            });
        }

        /** Terminal failure. */
        void fail(String key, Object... args) {
            SwingUtilities.invokeLater(() -> {
                terminal(); bar.setValue(0);
                setStatus(I18n.t(key, args), ColorScheme.ERROR_RED);
            });
        }

    }

    private void testConnection() {
        stdout.println("[Settings] === Test Connection clicked (build: live-test v2) ===");
        final LiveTestDialog live = new LiveTestDialog();
        live.show(); // appears instantly, modeless — no more frozen wait
        runConnectionTest(live);
    }

    /** Run (or re-run via the dialog's Retry button) the connection + model probe, streaming results
     *  into {@code live}. Reads the current API/model fields on each run. */
    private void runConnectionTest(LiveTestDialog live) {
        live.reset();
        new Thread(() -> {
            try {
                // Temporary client for testing only — never reassign this.aiClient (would detach the
                // shared instance used by ScanManager/AssistantPanel and break rebuildFromSettings()).
                String selectedProvider = (String) apiProviderComboBox.getSelectedItem();
                live.status("settings.live.checking.models");

                AiApiClient testClient;
                if ("gateway".equals(selectedProvider)) {
                    testClient = new AiApiClient(
                        "https://your-keycloak.example.com/realms/your-realm/protocol/openid-connect/token",
                        "https://your-llm-gateway.example.com/v1",
                        gatewayUsernameField.getText().trim(),
                        new String(gatewayPasswordField.getPassword()),
                        gatewayClientIdField.getText().trim(),
                        new String(gatewayClientSecretField.getPassword()),
                        gatewayRequestedSubjectField.getText().trim(),
                        (Integer) timeoutComboBox.getSelectedItem(),
                        currentSettings != null && currentSettings.isAllowInsecureSsl()
                    );
                } else if ("local".equals(selectedProvider)) {
                    Object localModelSel = localModelComboBox.getSelectedItem();
                    testClient = new AiApiClient(
                        localApiUrlField.getText().trim(),
                        localApiKeyField.getText().trim(),
                        localModelSel != null ? localModelSel.toString().trim() : "",
                        (Integer) timeoutComboBox.getSelectedItem(),
                        currentSettings != null && currentSettings.isAllowInsecureSsl()
                    );
                } else {
                    testClient = new AiApiClient(
                        apiEndpointField.getText().trim(),
                        apiKeyField.getText().trim(),
                        (String) modelComboBox.getSelectedItem(),
                        (Integer) timeoutComboBox.getSelectedItem(),
                        currentSettings != null && currentSettings.isAllowInsecureSsl()
                    );
                }

                // Step 1: /models reachability.
                AiApiClient.ConnectionTestResult result = testClient.testConnectionDetailed();
                if (!result.success) { live.fail("settings.live.failed", result.message); return; }

                if ("gateway".equals(selectedProvider)) {
                    live.finishOk("settings.live.gw.ok", result.endpoint, String.valueOf(result.responseTime));
                    return;
                }

                // Step 2: probe ONLY the selected model and measure its latency. We deliberately do
                // NOT touch any other model: requesting an unloaded model forces the gateway to spin
                // it up on demand, which slows down the whole AI server. Test just the one the user
                // picked — the list shows that single model with its response time.
                final boolean isLocal = "local".equals(selectedProvider);
                final String selModel = isLocal
                        ? String.valueOf(localModelComboBox.getSelectedItem())
                        : String.valueOf(modelComboBox.getSelectedItem());
                testClient.setTimeout(60); // 60s so a slow-but-working model isn't falsely failed

                live.status("settings.live.checking.selected", selModel);
                ModelProbeResult sel = probeModel(testClient, selModel);
                live.addResult(sel);
                if (sel.ok) {
                    live.finishOk("settings.live.selectedok", selModel, String.valueOf(sel.ms));
                } else if (isLocal) {
                    live.fail("settings.conn.local.notworking", selModel, sel.error);
                } else {
                    live.fail("settings.live.selectedfail", selModel, sel.error);
                }

            } catch (Exception e) {
                stderr.println("[Settings] Connection test error: " + e.getMessage());
                live.fail("settings.live.failed", String.valueOf(e.getMessage()));
            }
        }).start();
    }

    /**
     * Show detailed connection error dialog
     */
    private void showConnectionErrorDialog(AiApiClient.ConnectionTestResult result) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this),
                                     I18n.t("settings.conn.failed.title"), true);
        dialog.setSize(600, 450);
        dialog.setLocationRelativeTo(this);

        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        panel.setBackground(ColorScheme.BG_CARD);

        // Header with error icon
        JLabel headerLabel = new JLabel(I18n.t("settings.conn.failed.header", result.message));
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        headerLabel.setForeground(ColorScheme.ERROR_RED);
        panel.add(headerLabel, BorderLayout.NORTH);

        // Details text area
        JTextArea detailsArea = new JTextArea(result.getDetailedReport());
        detailsArea.setEditable(false);
        detailsArea.setFont(new Font("Consolas", Font.PLAIN, 11));
        detailsArea.setBackground(ColorScheme.BG_LIGHT);
        detailsArea.setForeground(ColorScheme.TEXT_DARK);
        detailsArea.setCaretPosition(0);

        JScrollPane scrollPane = new JScrollPane(detailsArea);
        scrollPane.setBorder(BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT));
        panel.add(scrollPane, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        buttonPanel.setBackground(ColorScheme.BG_CARD);

        JButton copyBtn = I18nUI.text(new JButton(), "settings.dialog.copy");
        copyBtn.addActionListener(e -> {
            java.awt.datatransfer.StringSelection selection =
                new java.awt.datatransfer.StringSelection(result.getDetailedReport());
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            JOptionPane.showMessageDialog(dialog, I18n.t("settings.dialog.copied"), I18n.t("settings.dialog.success.title"), JOptionPane.INFORMATION_MESSAGE);
        });
        buttonPanel.add(copyBtn);

        JButton closeBtn = I18nUI.text(new JButton(), "settings.dialog.close");
        closeBtn.addActionListener(e -> dialog.dispose());
        buttonPanel.add(closeBtn);

        panel.add(buttonPanel, BorderLayout.SOUTH);

        dialog.add(panel);
        dialog.setVisible(true);
    }

    /**
     * Show generic error details dialog
     */
    private void showErrorDetailsDialog(String title, String message, String details) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), title, true);
        dialog.setSize(500, 350);
        dialog.setLocationRelativeTo(this);

        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        panel.setBackground(ColorScheme.BG_CARD);

        JLabel headerLabel = new JLabel(message);
        headerLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        headerLabel.setForeground(ColorScheme.ERROR_RED);
        panel.add(headerLabel, BorderLayout.NORTH);

        JTextArea detailsArea = new JTextArea(details);
        detailsArea.setEditable(false);
        detailsArea.setFont(new Font("Consolas", Font.PLAIN, 11));
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);

        JScrollPane scrollPane = new JScrollPane(detailsArea);
        panel.add(scrollPane, BorderLayout.CENTER);

        JButton closeBtn = I18nUI.text(new JButton(), "settings.dialog.close");
        closeBtn.addActionListener(e -> dialog.dispose());
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.setBackground(ColorScheme.BG_CARD);
        buttonPanel.add(closeBtn);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        dialog.add(panel);
        dialog.setVisible(true);
    }
    
    /**
     * Refresh available models from API
     */
    private void refreshModels() { refreshModels(false); }

    /** Fetch the provider's model list (GET /models — a catalog query, does NOT wake/load models) and
     *  populate the dropdown. {@code silent} = no success/error popups (used for the automatic fetch on
     *  settings load). */
    private void refreshModels(boolean silent) {
        new Thread(() -> {
            try {
                // Update API client with current endpoint
                aiClient.setApiEndpoint(apiEndpointField.getText().trim());
                aiClient.setApiKey(apiKeyField.getText().trim());

                stdout.println("[Settings] Fetching available models from API...");

                org.json.JSONArray modelsArray = aiClient.getModels();

                SwingUtilities.invokeLater(() -> {
                    if (modelsArray != null && modelsArray.length() > 0) {
                        // Save current selection
                        String currentSelection = (String) modelComboBox.getSelectedItem();

                        // Clear and repopulate
                        modelComboBox.removeAllItems();

                        for (int i = 0; i < modelsArray.length(); i++) {
                            try {
                                org.json.JSONObject modelObj = modelsArray.getJSONObject(i);
                                String modelId = modelObj.optString("id", "");
                                if (!modelId.isEmpty()) {
                                    modelComboBox.addItem(modelId);
                                }
                            } catch (Exception e) {
                                // Try as string
                                String modelId = modelsArray.optString(i);
                                if (!modelId.isEmpty()) {
                                    modelComboBox.addItem(modelId);
                                }
                            }
                        }

                        // Restore selection if still available
                        if (currentSelection != null) {
                            for (int i = 0; i < modelComboBox.getItemCount(); i++) {
                                if (currentSelection.equals(modelComboBox.getItemAt(i))) {
                                    modelComboBox.setSelectedIndex(i);
                                    break;
                                }
                            }
                        }

                        stdout.println("[Settings] Found " + modelsArray.length() + " models");
                        if (!silent) JOptionPane.showMessageDialog(
                            this,
                            I18n.t("settings.models.found", String.valueOf(modelsArray.length())),
                            I18n.t("settings.models.refreshed.title"),
                            JOptionPane.INFORMATION_MESSAGE
                        );
                    } else {
                        if (!silent) JOptionPane.showMessageDialog(
                            this,
                            I18n.t("settings.models.none.api"),
                            I18n.t("settings.models.none.title"),
                            JOptionPane.WARNING_MESSAGE
                        );
                    }
                });
            } catch (Exception e) {
                stderr.println("[Settings] Error fetching models: " + e.getMessage());
                if (!silent) SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(
                        this,
                        I18n.t("settings.models.error.api", e.getMessage()),
                        I18n.t("settings.dialog.error.title"),
                        JOptionPane.ERROR_MESSAGE
                    );
                });
            }
        }).start();
    }

    /**
     * Refresh available models from the local model server
     */
    private void refreshLocalModels() {
        new Thread(() -> {
            try {
                AiApiClient localClient = new AiApiClient(
                    localApiUrlField.getText().trim(),
                    localApiKeyField.getText().trim(),
                    "",
                    (Integer) timeoutComboBox.getSelectedItem(),
                    currentSettings != null && currentSettings.isAllowInsecureSsl()
                );

                stdout.println("[Settings] Fetching models from local server...");
                org.json.JSONArray modelsArray = localClient.getModels();

                SwingUtilities.invokeLater(() -> {
                    if (modelsArray != null && modelsArray.length() > 0) {
                        String currentSelection = (String) localModelComboBox.getSelectedItem();
                        localModelComboBox.removeAllItems();
                        for (int i = 0; i < modelsArray.length(); i++) {
                            try {
                                org.json.JSONObject modelObj = modelsArray.getJSONObject(i);
                                String modelId = modelObj.optString("id", "");
                                if (!modelId.isEmpty()) {
                                    localModelComboBox.addItem(modelId);
                                }
                            } catch (Exception ex) {
                                String modelId = modelsArray.optString(i);
                                if (!modelId.isEmpty()) {
                                    localModelComboBox.addItem(modelId);
                                }
                            }
                        }
                        if (currentSelection != null && !currentSelection.isEmpty()) {
                            localModelComboBox.setSelectedItem(currentSelection);
                        }
                        stdout.println("[Settings] Found " + modelsArray.length() + " local models");
                        JOptionPane.showMessageDialog(this,
                            I18n.t("settings.models.found", String.valueOf(modelsArray.length())),
                            I18n.t("settings.models.refreshed.title"), JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(this,
                            I18n.t("settings.models.none.local", localApiUrlField.getText().trim()),
                            I18n.t("settings.models.none.title"), JOptionPane.WARNING_MESSAGE);
                    }
                });
            } catch (Exception e) {
                stderr.println("[Settings] Error fetching local models: " + e.getMessage());
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(this,
                        I18n.t("settings.models.error.local", e.getMessage()),
                        I18n.t("settings.dialog.error.title"), JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();
    }

    /**
     * Reset all settings to defaults
     */
    private void resetToDefaults() {
        int result = JOptionPane.showConfirmDialog(
            this,
            I18n.t("settings.reset.confirm"),
            I18n.t("settings.reset.confirm.title"),
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE
        );

        if (result == JOptionPane.YES_OPTION) {
            currentSettings = Settings.getDefaults();
            settingsManager.saveSettings(currentSettings);
            loadSettings();
            stdout.println("[Settings] Reset to defaults");
        }
    }

    /**
     * Clear all data from database
     */
    private void clearDatabase() {
        int result = JOptionPane.showConfirmDialog(
            this,
            I18n.t("settings.cleardb.confirm"),
            I18n.t("settings.cleardb.confirm.title"),
            JOptionPane.YES_NO_OPTION,
            JOptionPane.ERROR_MESSAGE
        );

        if (result == JOptionPane.YES_OPTION) {
            // Double confirmation for safety
            int doubleCheck = JOptionPane.showConfirmDialog(
                this,
                I18n.t("settings.cleardb.confirm2"),
                I18n.t("settings.cleardb.confirm2.title"),
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );

            if (doubleCheck == JOptionPane.YES_OPTION) {
                try {
                    // Clear all tables
                    dbManager.clearAllData();

                    stdout.println("[Database] All data cleared successfully");

                    JOptionPane.showMessageDialog(
                        this,
                        I18n.t("settings.cleardb.success"),
                        I18n.t("settings.dialog.success.title"),
                        JOptionPane.INFORMATION_MESSAGE
                    );
                } catch (Exception e) {
                    stderr.println("[Database] Error clearing database: " + e.getMessage());
                    JOptionPane.showMessageDialog(
                        this,
                        I18n.t("settings.cleardb.error", e.getMessage()),
                        I18n.t("settings.dialog.error.title"),
                        JOptionPane.ERROR_MESSAGE
                    );
                }
            }
        }
    }
}

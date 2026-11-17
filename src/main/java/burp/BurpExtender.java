package burp;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.Map;
import java.util.HashMap;
import java.util.List;

import burp.i18n.I18n;
import burp.i18n.I18nUI;
import burp.ambient.AmbientCoordinator;
import burp.ambient.BackgroundHunter;
import burp.ambient.OpportunityQueue;
import burp.ambient.PassiveTriage;
import burp.ambient.TargetModel;

/**
 * AppSecHunter
 * Advanced Burp Suite Extension for AI-Powered Vulnerability Detection
 *
 * @author Zahid Eroglu
 * @version 2.1
 * @since 2025
 */
public class BurpExtender implements IBurpExtender, ITab, IHttpListener, 
                                      IContextMenuFactory, IScannerCheck, IExtensionStateListener {
    
    // Core components
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    // UI Components
    private JTabbedPane mainTabbedPane;
    private DetectionPanel detectionPanel;
    private FindingsPanel globalFindingsPanel;
    private burp.authz.AuthMatrixPanel authMatrixPanel;
    private AssistantPanel assistantPanel;
    private SettingsPanel settingsPanel;

    // Managers
    private AiApiClient aiClient;
    private DatabaseManager databaseManager;
    private ScanManager scanManager;
    private SettingsManager settingsManager;
    private FilterEngine filterEngine;
    private MultiSessionTester multiSessionTester;
    private burp.session.CredentialStore credentialStore;
    private burp.session.SessionKeeper sessionKeeper;

    // Ambient Security Copilot
    private TargetModel targetModel;
    private OpportunityQueue opportunityQueue;
    private PassiveTriage passiveTriage;
    private AmbientCoordinator ambientCoordinator;
    private BackgroundHunter backgroundHunter;

    // Extension info
    private static final String EXTENSION_NAME = "AppSecHunter";
    private static final String AUTHOR = "Zahid Eroglu";
    private static final String VERSION = "2.1";
    
    /**
     * Extension entry point
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // Save callbacks and helpers
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // Wire up AI usage tracking (loads persisted token totals)
        AIUsageStats.getInstance().init(callbacks);

        // Set up output streams
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // Set extension name
        callbacks.setExtensionName(EXTENSION_NAME);
        
        // Print banner
        printBanner();
        
        try {
            // Initialize managers
            stdout.println("[*] Initializing managers...");
            initializeManagers();
            
            // Create UI and register tab on EDT
            stdout.println("[*] Creating user interface...");
            Runnable uiInit = () -> {
                try {
                    createUI();
                    stdout.println("[✓] UI initialized successfully");

                    callbacks.addSuiteTab(BurpExtender.this);
                    stdout.println("[✓] Suite tab registered");
                } catch (Exception e) {
                    stderr.println("[✗] UI initialization failed: " + e.getMessage());
                    e.printStackTrace(stderr);
                }
            };
            if (SwingUtilities.isEventDispatchThread()) {
                uiInit.run();
            } else {
                SwingUtilities.invokeAndWait(uiInit);
            }

            // Background hunter (needs the detection panel built in createUI for its live view)
            Settings liveSettings = settingsManager.getSettings();
            backgroundHunter = new BackgroundHunter(callbacks, helpers, aiClient, liveSettings, scanManager,
                    multiSessionTester, opportunityQueue, targetModel, scanManager.getGlobalRateLimiter(),
                    detectionPanel, stdout, stderr);
            if (assistantPanel != null) {
                assistantPanel.setHunter(backgroundHunter); // kill switch + budget meter
            }
            if (settingsPanel != null) {
                settingsPanel.setAmbientApplyHook(this::applyAmbientToggles); // apply toggles on Save
            }
            if (liveSettings.isAmbientHunterEnabled()) {
                backgroundHunter.start();
            }

            // Register extension components
            stdout.println("[*] Registering Burp Suite integration...");
            callbacks.registerHttpListener(this);
            callbacks.registerContextMenuFactory(this);
            callbacks.registerScannerCheck(this);
            callbacks.registerExtensionStateListener(this);
            
            stdout.println("[✓] " + EXTENSION_NAME + " loaded successfully!");
            stdout.println("[✓] Created by " + AUTHOR);
            stdout.println("[✓] Version " + VERSION);
            stdout.println("[📝] Tarama logları kaydediliyor: " + ScanLogger.get().currentFilePath());
            stdout.println("[i] Ready to scan!");
            
        } catch (Exception e) {
            stderr.println("[✗] Extension initialization failed: " + e.getMessage());
            e.printStackTrace(stderr);
        }
    }
    
    /**
     * Print extension banner
     */
    private void printBanner() {
        stdout.println("\n" +
            "╔══════════════════════════════════════════════════════════════╗\n" +
            "║                                                              ║\n" +
            "║                         AppSecHunter                         ║\n" +
            "║        AI-Powered Web Security Scanner for Burp Suite        ║\n" +
            "║                                                              ║\n" +
            "║    Providers: Local LLM · OpenAI · OpenRouter · and more     ║\n" +
            "║                   Created by Zahid Eroglu                    ║\n" +
            "║                    Version " + VERSION + "\n" +
            "║                                                              ║\n" +
            "╚══════════════════════════════════════════════════════════════╝\n");
    }
    
    /**
     * Initialize all managers
     */
    private void initializeManagers() throws Exception {
        // Load settings
        settingsManager = new SettingsManager(callbacks);
        Settings settings = settingsManager.loadSettings();
        
        // Initialize database
        databaseManager = new DatabaseManager();
        databaseManager.initialize();
        
        // Initialize AI API client
        aiClient = AiApiClient.createClient(settings);
        
        // Initialize filter engine
        filterEngine = new FilterEngine(callbacks, settings);
        
        // Initialize scan manager
        scanManager = new ScanManager(
            callbacks,
            helpers,
            aiClient,
            databaseManager,
            filterEngine,
            settings,
            stdout,
            stderr
        );

        // Initialize AI-powered PoC Generator
        PoCGenerator.initialize(aiClient, stdout, stderr);
        stdout.println("[✓] AI-powered PoC Generator initialized");

        multiSessionTester = new MultiSessionTester(callbacks, helpers, aiClient, stdout, stderr);
        scanManager.setMultiSessionTester(multiSessionTester); // agentic pentester reuses saved identities
        // Faz 2: encrypted login-profile store + session freshness / auto-relogin keeper.
        credentialStore = new burp.session.CredentialStore(callbacks, stderr);
        sessionKeeper = new burp.session.SessionKeeper(callbacks, helpers, multiSessionTester, credentialStore, stdout, stderr);
        scanManager.setSessionKeeper(sessionKeeper);
        stdout.println("[✓] Multi-Session Tester + SessionKeeper initialized");

        // Ambient Security Copilot: passive triage over proxy traffic (LLM-free hot path)
        targetModel = new TargetModel();
        opportunityQueue = new OpportunityQueue(targetModel);
        passiveTriage = new PassiveTriage(helpers, filterEngine, settings, targetModel,
                opportunityQueue, databaseManager, stdout, stderr);
        passiveTriage.setMinScore(settings.getAmbientMinScore());
        ambientCoordinator = new AmbientCoordinator(passiveTriage, stdout, stderr);
        if (settings.isAmbientEnabled()) {
            ambientCoordinator.start();
        }
        stdout.println("[✓] Ambient Security Copilot initialized"
                + (settings.isAmbientEnabled() ? " (active)" : " (disabled)"));

        stdout.println("[✓] Managers initialized");
    }
    
    /**
     * Create main UI
     */
    /** Tab order ↔ i18n keys, used both to caption tabs and to re-caption them on a language switch. */
    private static final String[] TAB_KEYS = {
        "tab.scanner", "tab.findings", "tab.authmatrix", "tab.copilot", "tab.settings"
    };

    private void createUI() {
        // Load the persisted UI language before building any text.
        I18n.setLang(settingsManager.getSettings().getLanguage());

        // Re-detect light/dark NOW that Burp's Look-and-Feel is active, so every panel built
        // below picks up colors matching the real theme (the static init can run too early).
        ColorScheme.refreshTheme();

        // Main tabbed pane with modern look
        mainTabbedPane = new JTabbedPane();
        mainTabbedPane.setFont(new Font("Segoe UI", Font.PLAIN, 13));

        // Each tab is built defensively: a single failing panel must NOT abort the whole UI —
        // that would leave Burp with no AppSecHunter tab at all (the symptom we just debugged).
        // On failure the panel is replaced by a visible error placeholder, and the exact cause is
        // logged to BOTH the Output and the Errors panes so it's diagnosable from either one.

        // Scanner tab = unified launcher toolbar + live active-scan run list (formerly two
        // separate tabs, Scanner + Detection). Every campaign — full-auto, single-request and
        // whole-domain — is launched from the toolbar here and surfaces as a run in the same list.
        try {
            detectionPanel = new DetectionPanel();
            detectionPanel.setLauncherActions(
                () -> pickRequestThen(I18n.t("scan.launch.everything"), this::startEverything),
                () -> pickRequestThen(I18n.t("scan.launch.thisreq"), this::startFullScan),
                () -> pickRequestThen(I18n.t("scan.launch.domain"), this::startSiteScan)
            );
            mainTabbedPane.addTab(I18n.t("tab.scanner"), detectionPanel);
        } catch (Throwable t) {
            logUiBuildError("Scanner", t);
            mainTabbedPane.addTab(I18n.t("tab.scanner"), buildErrorPanel("Scanner", t));
        }

        // Findings tab - single global view of ALL findings (engine, scans, multi-session)
        try {
            globalFindingsPanel = new FindingsPanel(callbacks, helpers, databaseManager);
            globalFindingsPanel.setAiClient(aiClient);
            scanManager.setFindingsPanel(globalFindingsPanel);
            mainTabbedPane.addTab(I18n.t("tab.findings"), globalFindingsPanel);
        } catch (Throwable t) {
            logUiBuildError("Findings", t);
            mainTabbedPane.addTab(I18n.t("tab.findings"), buildErrorPanel("Findings", t));
        }

        // Authorization Matrix tab - role × endpoint access-control grid
        try {
            authMatrixPanel = new burp.authz.AuthMatrixPanel();
            authMatrixPanel.setSessionTester(multiSessionTester); // Faz 4: embedded identity manager
            authMatrixPanel.setLoginAccess(callbacks, helpers, stdout, stderr, settingsManager);
            mainTabbedPane.addTab(I18n.t("tab.authmatrix"), authMatrixPanel);
        } catch (Throwable t) {
            logUiBuildError("Authorization Matrix", t);
            mainTabbedPane.addTab(I18n.t("tab.authmatrix"), buildErrorPanel("Authorization Matrix", t));
        }

        // Copilot tab - ambient security copilot (opportunities feed + context-aware chat)
        try {
            assistantPanel = new AssistantPanel(callbacks, aiClient, scanManager, databaseManager,
                    targetModel, opportunityQueue, detectionPanel, settingsManager, stdout, stderr);
            mainTabbedPane.addTab(I18n.t("tab.copilot"), assistantPanel);
            // Feed every confirmed (non-suppressed) finding to the Copilot so it can announce IDOR/BOLA.
            // Field-deref (not a method ref) so it auto-follows the panel rebuilt on a language switch.
            scanManager.setFindingObserver((f, m) -> {
                AssistantPanel ap = assistantPanel;
                if (ap != null) ap.onFindingReported(f, m);
            });
        } catch (Throwable t) {
            logUiBuildError("Copilot", t);
            mainTabbedPane.addTab(I18n.t("tab.copilot"), buildErrorPanel("Copilot", t));
        }

        // Settings tab
        try {
            settingsPanel = new SettingsPanel(
                callbacks,
                helpers,
                scanManager,
                aiClient,
                databaseManager,
                settingsManager,
                stdout,
                stderr
            );
            settingsPanel.setLanguageApplyHook(this::applyLanguage); // live language switch
            mainTabbedPane.addTab(I18n.t("tab.settings"), settingsPanel);
        } catch (Throwable t) {
            logUiBuildError("Settings", t);
            mainTabbedPane.addTab(I18n.t("tab.settings"), buildErrorPanel("Settings", t));
        }

        // Scanner is the primary interface
        if (mainTabbedPane.getTabCount() > 0) {
            mainTabbedPane.setSelectedIndex(0);
        }
    }

    /**
     * Report a panel-build failure to BOTH the Output and the Errors panes. Burp routes
     * {@code stdout}/{@code stderr} to two separate sub-tabs; a stack trace printed only to
     * stderr is invisible to anyone looking at Output, so we name the failure in both.
     */
    private void logUiBuildError(String panel, Throwable t) {
        stdout.println("[✗] UI panel '" + panel + "' failed to build: " + t
                + "  (full stack trace in the Errors tab)");
        stderr.println("[✗] UI panel '" + panel + "' failed to build:");
        t.printStackTrace(stderr);
    }

    /**
     * A visible placeholder shown in place of a panel that threw during construction, so the user
     * gets a working AppSecHunter tab (with the healthy panels) plus an on-screen explanation of
     * what went wrong instead of a silently missing tab.
     */
    private Component buildErrorPanel(String panel, Throwable t) {
        java.io.StringWriter sw = new java.io.StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        JTextArea area = new JTextArea(
                "The \"" + panel + "\" panel failed to load.\n\n"
                + "This is a bug in the extension, not your setup. The other tabs still work.\n"
                + "Full details (also in Extensions → AppSecHunter → Errors):\n\n"
                + sw);
        area.setEditable(false);
        area.setFont(new Font("Monospaced", Font.PLAIN, 12));
        area.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));
        return new JScrollPane(area);
    }

    /**
     * Apply a language change live (called from SettingsPanel save ONLY when the language actually
     * changed). The Scanner tab ({@link DetectionPanel}) is fully I18nUI-bound and is referenced by
     * the background hunter / copilot, so it is NEVER recreated — only re-localized in place (active
     * runs survive). The other four tabs mix plain {@code I18n.t(...)} literals the relocalize walker
     * can't reach, so they are disposed (timers) and rebuilt fresh in the new language, re-wired
     * exactly as in {@link #createUI()}. Findings reload from the DB; copilot/matrix views reset.
     */
    private void applyLanguage() {
        SwingUtilities.invokeLater(() -> {
            I18n.setLang(settingsManager.getSettings().getLanguage());

            // Scanner tab: re-localize in place (keep the instance + its active runs).
            if (detectionPanel != null) {
                burp.i18n.I18nUI.relocalize(detectionPanel);
                detectionPanel.applyLanguage();
            }

            final int selected = mainTabbedPane.getSelectedIndex();

            // Findings (tab 1) — dispose old timer, rebuild, re-register as the global sink.
            if (globalFindingsPanel != null) globalFindingsPanel.cleanup();
            globalFindingsPanel = new FindingsPanel(callbacks, helpers, databaseManager);
            globalFindingsPanel.setAiClient(aiClient);
            scanManager.setFindingsPanel(globalFindingsPanel);
            mainTabbedPane.setComponentAt(1, globalFindingsPanel);

            // Authorization Matrix (tab 2).
            authMatrixPanel = new burp.authz.AuthMatrixPanel();
            authMatrixPanel.setSessionTester(multiSessionTester);
            authMatrixPanel.setLoginAccess(callbacks, helpers, stdout, stderr, settingsManager);
            mainTabbedPane.setComponentAt(2, authMatrixPanel);

            // Copilot (tab 3) — stop old refresh timer, rebuild, re-attach the hunter.
            if (assistantPanel != null) assistantPanel.stopRefreshTimer();
            assistantPanel = new AssistantPanel(callbacks, aiClient, scanManager, databaseManager,
                    targetModel, opportunityQueue, detectionPanel, settingsManager, stdout, stderr);
            if (backgroundHunter != null) assistantPanel.setHunter(backgroundHunter);
            mainTabbedPane.setComponentAt(3, assistantPanel);

            // Settings (tab 4) — rebuild, re-wire its apply hooks.
            settingsPanel = new SettingsPanel(callbacks, helpers, scanManager, aiClient,
                    databaseManager, settingsManager, stdout, stderr);
            settingsPanel.setAmbientApplyHook(this::applyAmbientToggles);
            settingsPanel.setLanguageApplyHook(this::applyLanguage);
            mainTabbedPane.setComponentAt(4, settingsPanel);

            // Re-caption tabs + restore the previously selected tab.
            for (int i = 0; i < TAB_KEYS.length && i < mainTabbedPane.getTabCount(); i++) {
                mainTabbedPane.setTitleAt(i, I18n.t(TAB_KEYS[i]));
            }
            if (selected >= 0 && selected < mainTabbedPane.getTabCount()) {
                mainTabbedPane.setSelectedIndex(selected);
            }
            mainTabbedPane.revalidate();
            mainTabbedPane.repaint();
            stdout.println("[*] UI language → " + I18n.code() + " (deep panels rebuilt)");
        });
    }
    
    /**
     * Get tab caption for Burp Suite
     */
    @Override
    public String getTabCaption() {
        return "AppSecHunter";
    }
    
    /**
     * Get UI component for Burp Suite
     */
    @Override
    public Component getUiComponent() {
        return mainTabbedPane;
    }
    
    /**
     * HTTP listener - for background scanning
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest,
                                   IHttpRequestResponse messageInfo) {
        // Tag our own outgoing scan traffic so the target's defenders can distinguish authorized
        // AppSecHunter requests from a real attack (responsible-testing hygiene). Only extender
        // traffic is tagged; AI-provider calls use a separate client and are never touched.
        if (messageIsRequest && toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER) {
            burp.scan.ScanMarker.tag(messageInfo, settingsManager.getSettings(), helpers);
            return;
        }

        // Only process Proxy responses
        if (messageIsRequest || toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) {
            return;
        }

        Settings settings = settingsManager.getSettings();

        // Ambient passive triage: non-blocking hand-off to the triage worker (LLM-free).
        if (settings.isAmbientEnabled() && ambientCoordinator != null) {
            ambientCoordinator.onProxyResponse(messageInfo);
        }

        // Legacy per-response AI auto-scan (kept behind its own flag; default OFF).
        if (settings.isAutoScanEnabled()) {
            new Thread(() -> {
                try {
                    scanManager.backgroundScan(messageInfo);
                } catch (Exception e) {
                    stderr.println("[✗] Background scan error: " + e.getMessage());
                }
            }).start();
        }
    }
    
    /**
     * Context menu factory - right-click menu
     */
    @Override
    public java.util.List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        java.util.List<JMenuItem> menuItems = new java.util.ArrayList<>();

        // Only show for requests
        byte context = invocation.getInvocationContext();
        if (context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
            context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST ||
            context == IContextMenuInvocation.CONTEXT_PROXY_HISTORY ||
            context == IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE) {

            // ===== One submenu, 3 items. One click = everything runs in the background. =====
            JMenu menu = new JMenu("AppSecHunter");
            boolean aiOn = isAiConfigured();

            // 1) THE button: run every campaign in the background with a single confirm.
            JMenuItem everything = new JMenuItem(I18n.t("menu.everything"));
            everything.setToolTipText(I18n.t("menu.everything.tip")
                    + (aiOn ? I18n.t("menu.everything.tip.ai") : I18n.t("menu.everything.tip.noai")));
            everything.addActionListener(e -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) startEverything(messages[0]);
            });
            menu.add(everything);

            // 2) Quick path: just the selected request, no site-wide campaigns.
            JMenuItem thisReq = new JMenuItem(I18n.t("menu.thisreq"));
            thisReq.setToolTipText(I18n.t("menu.thisreq.tip") + (aiOn ? I18n.t("menu.thisreq.tip.ai") : ""));
            thisReq.addActionListener(e -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) startFullScan(messages[0]);
            });
            menu.add(thisReq);

            menu.addSeparator();

            // 3) Optional helper: register this request's identity as a role for the matrix.
            JMenuItem addSessionItem = new JMenuItem(I18n.t("menu.addsession"));
            addSessionItem.setToolTipText(I18n.t("menu.addsession.tip"));
            addSessionItem.addActionListener(e -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) addSessionFromRequest(messages[0]);
            });
            menu.add(addSessionItem);

            // 4) Faz 2: capture this request as an ENCRYPTED login profile for auto re-login on logout.
            JMenuItem loginProfileItem = new JMenuItem(I18n.t("menu.loginprofile"));
            loginProfileItem.setToolTipText(I18n.t("menu.loginprofile.tip"));
            loginProfileItem.addActionListener(e -> {
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                if (messages != null && messages.length > 0) captureLoginProfile(messages[0]);
            });
            menu.add(loginProfileItem);

            menuItems.add(menu);

        }

        return menuItems;
    }

    
    /**
     * Passive scanner - for Burp Scanner integration
     */
    @Override
    public java.util.List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // AppSecHunter uses active scanning through UI
        // Return null to not interfere with Burp's native scanner
        return null;
    }
    
    /**
     * Active scanner - not implemented
     */
    @Override
    public java.util.List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
                                                    IScannerInsertionPoint insertionPoint) {
        return null;
    }
    
    /**
     * Consolidate duplicate issues
     */
    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // If same issue name and URL, consider them duplicate
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()) &&
            existingIssue.getUrl().equals(newIssue.getUrl())) {
            return -1; // Issues are the same
        }
        return 0; // Issues are different
    }
    


    /**
     * One-click background scan: the deterministic engine (all modules) and, if AI
     * is configured, the playbook-driven AI pentester — both on background threads.
     * Few foreground clicks, lots of background work.
     */
    private void startFullScan(IHttpRequestResponse message) {
        if (!confirmIntrusiveIfNeeded()) {
            stdout.println("[*] Tara iptal (agresif test onayı reddedildi)");
            return;
        }
        String url = helpers.analyzeRequest(message).getUrl().toString();
        boolean aiOn = isAiConfigured();
        SwingUtilities.invokeLater(() -> {
            mainTabbedPane.setSelectedComponent(detectionPanel);
            // Deterministic module scan is opt-in (default OFF — it is the WAF-tripping probe barrage);
            // default scan is AI-only.
            if (settingsManager.getSettings().isHeuristicScanEnabled()) {
                DetectionRunView view = detectionPanel.beginSingle(url, false);
                scanManager.runActiveScan(message, view);          // deterministic (background)
            }
            if (aiOn) {
                DetectionRunView aiView = detectionPanel.beginSingle(url + "  ·  AI", false);
                scanManager.runPlaybookHunt(message, aiView);      // AI pentester (background)
            }
        });
        stdout.println("[*] Full background scan started (AI"
                + (settingsManager.getSettings().isHeuristicScanEnabled() ? " + deterministic" : "-only") + "): " + url);
    }

    /** Deterministic whole-site + proxy-history scan for the seed request's host (shows as a run). */
    private void startSiteScan(IHttpRequestResponse message) {
        if (!confirmIntrusiveIfNeeded()) {
            stdout.println("[*] Site taraması iptal (agresif test onayı reddedildi)");
            return;
        }
        String host = helpers.analyzeRequest(message).getUrl().getHost();
        SwingUtilities.invokeLater(() -> {
            mainTabbedPane.setSelectedComponent(detectionPanel);
            if (settingsManager.getSettings().isHeuristicScanEnabled()) {
                scanManager.runSiteScan(message, detectionPanel.beginSite(host + " (site+history)"));
            } else {
                // AI-only default: agentic per-endpoint playbook hunt across the site instead of the
                // deterministic module barrage.
                scanManager.runSiteHunt(message, "both", detectionPanel.beginSite(host + " (site+history · AI)"));
            }
        });
        stdout.println("[*] Site+history scan started: " + host);
    }

    /**
     * Show a Proxy-history picker (recent 50, newest first) and run {@code action} on the chosen
     * request. Shared by the Scanner tab's launcher buttons (Hepsini Tara / Tara — Sadece bu istek /
     * Scan Domain) so each one starts a campaign that surfaces in the active-scan run list.
     */
    private void pickRequestThen(String title, java.util.function.Consumer<IHttpRequestResponse> action) {
        IHttpRequestResponse[] history = callbacks.getProxyHistory();
        if (history == null || history.length == 0) {
            JOptionPane.showMessageDialog(mainTabbedPane,
                    I18n.t("dialog.pick.emptyHistory"),
                    title, JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(mainTabbedPane),
                title + " — " + I18n.t("dialog.pick.titleSuffix"), true);
        dialog.setSize(640, 420);
        dialog.setLocationRelativeTo(mainTabbedPane);

        JPanel content = new JPanel(new BorderLayout(10, 10));
        content.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));
        content.add(new JLabel(I18n.t("dialog.pick.selectLabel")), BorderLayout.NORTH);

        DefaultListModel<String> model = new DefaultListModel<>();
        int start = Math.max(0, history.length - 50);
        for (int i = history.length - 1; i >= start; i--) {
            try {
                IRequestInfo info = helpers.analyzeRequest(history[i]);
                String url = info.getUrl().toString();
                model.addElement(info.getMethod() + "  " + (url.length() > 80 ? url.substring(0, 80) + "…" : url));
            } catch (Exception ignore) {
                model.addElement(I18n.t("dialog.pick.unparsable"));
            }
        }
        JList<String> list = new JList<>(model);
        list.setFont(new Font("Consolas", Font.PLAIN, 12));
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setSelectedIndex(0);
        content.add(new JScrollPane(list), BorderLayout.CENTER);

        JButton run = new JButton(I18n.t("dialog.pick.run"));
        run.addActionListener(e -> {
            int sel = list.getSelectedIndex();
            if (sel < 0) { JOptionPane.showMessageDialog(dialog, I18n.t("dialog.pick.selectOne")); return; }
            int idx = history.length - 1 - sel;   // list is newest-first
            dialog.dispose();
            if (idx >= 0 && idx < history.length) action.accept(history[idx]);
        });
        JButton cancel = new JButton(I18n.t("dialog.pick.cancel"));
        cancel.addActionListener(e -> dialog.dispose());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.add(cancel);
        buttons.add(run);
        content.add(buttons, BorderLayout.SOUTH);

        dialog.setContentPane(content);
        dialog.setVisible(true);
    }

    /** True if an AI endpoint is configured (so AI passes can be chained silently). */
    private boolean isAiConfigured() {
        try {
            Settings s = settingsManager.getSettings();
            return s != null && s.getApiUrl() != null && !s.getApiUrl().trim().isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * One-click "everything": after a single consolidated authorization confirm, launch every
     * campaign in the background — this request (deterministic + AI), whole site + proxy history,
     * the autonomous authorization matrix, and (when AI is configured) AI surface discovery plus
     * the ground-truth & agentic BOLA/BAC scenario hunts. Each campaign
     * gets its own live Detection sub-tab. Few foreground clicks, lots of background work.
     */
    /** Launch a single-target run wired so its tab's ↻ re-fires the same scan into a fresh tab. */
    private void rerunnableSingle(String title, boolean guided, IHttpRequestResponse seed,
                                  java.util.function.BiConsumer<IHttpRequestResponse, DetectionRunView> scan) {
        DetectionRunView v = detectionPanel.beginSingle(title, guided);
        v.setRerunAction(() -> rerunnableSingle(title, guided, seed, scan));
        scan.accept(seed, v);
    }

    /** Launch a whole-site run wired so its tab's ↻ re-fires the same scan into a fresh tab. */
    private void rerunnableSite(String title, IHttpRequestResponse seed,
                                java.util.function.BiConsumer<IHttpRequestResponse, DetectionRunView> scan) {
        DetectionRunView v = detectionPanel.beginSite(title);
        v.setRerunAction(() -> rerunnableSite(title, seed, scan));
        scan.accept(seed, v);
    }

    private void startEverything(IHttpRequestResponse seed) {
        final boolean aiOn = isAiConfigured();
        int r = JOptionPane.showConfirmDialog(mainTabbedPane,
                I18n.t("dialog.everything.intro") + "\n"
                        + I18n.t("dialog.everything.line.thisreq")
                            + (aiOn ? I18n.t("dialog.everything.line.thisreq.ai") : "") + ")\n"
                        + I18n.t("dialog.everything.line.site") + "\n"
                        + I18n.t("dialog.everything.line.authmatrix") + "\n"
                        + (aiOn ? I18n.t("dialog.everything.line.ai") : "")
                        + "\n" + I18n.t("dialog.everything.warning") + "\n\n" + I18n.t("dialog.common.proceed"),
                I18n.t("dialog.everything.title"), JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (r != JOptionPane.YES_OPTION) {
            stdout.println("[*] Tam otomatik tarama iptal edildi.");
            return;
        }

        // Faz 4: aggression is opt-in. Mutating (PUT/DELETE/POST) tests run ONLY after an explicit
        // test-environment affirmation; otherwise the campaign still runs but in safe/read-only mode.
        final boolean aggressive = confirmTestEnvironment();
        stdout.println("[*] Tarama modu: " + (aggressive
                ? "AGRESİF (durum-değiştiren açık, test ortamı onaylandı)"
                : "GÜVENLİ (salt-okunur / yalnız GET-HEAD-OPTIONS)"));

        final String url = helpers.analyzeRequest(seed).getUrl().toString();
        final String host = helpers.analyzeRequest(seed).getUrl().getHost();
        SwingUtilities.invokeLater(() -> {
            mainTabbedPane.setSelectedComponent(detectionPanel);

            // Default is AI-only; the deterministic module engine (the WAF-tripping probe barrage) runs
            // ONLY when explicitly enabled in Settings.
            final boolean heuristic = settingsManager.getSettings().isHeuristicScanEnabled();

            // Each run is wired so its tab's ↻ button re-fires that exact campaign into a fresh tab.
            // This exact request — deterministic engine (opt-in). The seed's AI pentester is NOT launched
            // separately here: the whole-site hunt below already covers the seed endpoint (it was a
            // redundant concurrent run). The seed-only AI pentester stays on the "Sadece bu istek" menu.
            if (heuristic) rerunnableSingle(url, false, seed, (s, v) -> scanManager.runActiveScan(s, v));

            // Whole site + proxy history: deterministic (opt-in) OR agentic AI site hunt (default)
            if (heuristic) rerunnableSite(host + " (site+history)", seed, (s, v) -> scanManager.runSiteScan(s, v));
            else if (aiOn) rerunnableSite(host + " (site+history · AI)", seed, (s, v) -> scanManager.runSiteHunt(s, "both", v));

            // Autonomous authorization matrix (roles: manual sessions + login-profiles + validated history)
            rerunnableSite(host + " (oto yetki matrisi)", seed,
                    (s, v) -> scanManager.runAutoAuthMatrix(s, "both", aggressive, multiSessionTester, authMatrixPanel, v));

            if (aiOn) {
                // Merged BOLA/BAC: ownership-model + negative-control ground-truth, the AI-driven
                // cross-owner/multi-step agent, AND AI surface discovery — all over ONE shared AccessModel.
                // (Was 3 separate concurrent campaigns that each rebuilt harvest+validate+AccessModel and
                // hammered the host 3×.) Mutating cross-owner / write-IDOR tests run ONLY when the test
                // environment was affirmed (aggressive); read-only cross-owner BOLA always runs. The old
                // standalone "AI yüzey keşfi" / "agentic BOLA/BAC" runs stay reachable via their own reruns.
                rerunnableSite(host + " (BOLA/BAC)", seed,
                        (s, v) -> scanManager.runScenarioAccessHunt(s, aggressive, multiSessionTester, v, true));
            }
        });
        stdout.println("[*] FULL AUTO scan launched for " + host
                + (settingsManager.getSettings().isHeuristicScanEnabled() ? " (AI + deterministic)" : " (AI-only)"));
    }

    /** Faz 4: explicit test-environment affirmation before sending mutating (PUT/DELETE/POST) requests. */
    private boolean confirmTestEnvironment() {
        int r = JOptionPane.showConfirmDialog(mainTabbedPane,
                I18n.t("dialog.testenv.message"),
                I18n.t("dialog.testenv.title"), JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        return r == JOptionPane.YES_OPTION;
    }

    /**
     * Stronger consent for autonomous hunting: it sends background requests within a
     * budget. Shown for the whole-site hunt and when enabling the always-on hunter.
     */
    private boolean confirmAutonomousHuntConsent() {
        Settings s = settingsManager.getSettings();
        long tok = s.getAgentSiteTokenBudget();
        int min = s.getAgentSiteTimeBudgetMin();
        String budget = "Token bütçesi: " + (tok > 0 ? tok : "sınırsız")
                + "\nSüre: " + (min > 0 ? min + " dk" : "sınırsız")
                + "\nEşzamanlılık: " + s.getAgentSiteConcurrency()
                + "\nKapsam: " + (s.isAmbientScopeOnly() ? "yalnızca kapsam içi" : "Burp scope ayarına göre");
        int r = JOptionPane.showConfirmDialog(mainTabbedPane,
                "OTONOM AVLAMA arka planda otomatik test isteği gönderir.\n"
                        + "Yalnızca yetkili / kapsamdaki hedeflerde kullanın.\n\n" + budget
                        + "\n\nDevam edilsin mi?",
                "Otonom Avlama Onayı", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        return r == JOptionPane.YES_OPTION;
    }

    /**
     * Apply ambient toggles from Settings without a restart (invoked after Save).
     * Starts/stops the passive triage worker and the autonomous hunter to match the
     * persisted flags, refreshes the triage threshold, and gates the hunter on consent.
     */
    private void applyAmbientToggles() {
        Settings s = settingsManager.getSettings();
        if (passiveTriage != null) {
            passiveTriage.setMinScore(s.getAmbientMinScore());
        }
        if (ambientCoordinator != null) {
            if (s.isAmbientEnabled() && !ambientCoordinator.isRunning()) {
                ambientCoordinator.start();
            } else if (!s.isAmbientEnabled() && ambientCoordinator.isRunning()) {
                ambientCoordinator.stop();
            }
        }
        if (backgroundHunter != null) {
            boolean want = s.isAmbientHunterEnabled();
            if (want && !backgroundHunter.isRunning()) {
                if (confirmAutonomousHuntConsent()) {
                    backgroundHunter.start();
                } else {
                    s.setAmbientHunterEnabled(false);
                    settingsManager.saveSettings(s);
                }
            } else if (!want && backgroundHunter.isRunning()) {
                backgroundHunter.kill();
            }
        }
    }

    /**
     * If any intrusive test is enabled, ask the user to confirm (per scan).
     * Returns true to proceed, false to cancel the scan.
     */
    private boolean confirmIntrusiveIfNeeded() {
        Settings s = settingsManager.getSettings();
        if (s == null || !s.hasAnyIntrusiveEnabled()) {
            return true;
        }
        java.util.List<String> on = new java.util.ArrayList<>();
        if (s.isBruteForceEnabled()) on.add(I18n.t("dialog.intrusive.test.bruteforce"));
        if (s.isFileUploadTestEnabled()) on.add(I18n.t("dialog.intrusive.test.fileupload"));
        if (s.isSsrfActiveEnabled()) on.add(I18n.t("dialog.intrusive.test.ssrf"));
        if (s.isModuleMassAssignmentEnabled()) on.add(I18n.t("dialog.intrusive.test.massassignment"));
        int r = JOptionPane.showConfirmDialog(mainTabbedPane,
                I18n.t("dialog.intrusive.message", String.join("\n  • ", on)),
                I18n.t("dialog.intrusive.title"), JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        return r == JOptionPane.YES_OPTION;
    }

    /**
     * Add session from request
     */
    private void addSessionFromRequest(IHttpRequestResponse message) {
        if (multiSessionTester == null) {
            stderr.println("[✗] MultiSessionTester null! Extension başlatılmadı.");
            return;
        }

        String role = javax.swing.JOptionPane.showInputDialog(
            null,
            I18n.t("dialog.addsession.prompt"),
            I18n.t("dialog.addsession.title"),
            javax.swing.JOptionPane.QUESTION_MESSAGE
        );

        if (role != null && !role.trim().isEmpty()) {
            // Extract tokens from request first
            Map<String, String> extractedTokens = extractAuthTokensFromRequest(message);

            String sessionId = multiSessionTester.addSession(
                role,
                "Burp Proxy'den eklenen oturum",
                extractedTokens
            );

            stdout.println("[✓] Oturum eklendi: " + role + " (" + sessionId + ")");
            stdout.println("[+] Token sayısı: " + extractedTokens.size());

            IRequestInfo reqInfo = helpers.analyzeRequest(message);
            String sessionName = reqInfo.getUrl().getHost();

            // Build token info for dialog
            StringBuilder tokenInfo = new StringBuilder();
            if (extractedTokens.isEmpty()) {
                tokenInfo.append("\n").append(I18n.t("dialog.addsession.noTokens"));
            } else {
                tokenInfo.append("\n\n").append(I18n.t("dialog.addsession.foundTokens"));
                for (Map.Entry<String, String> entry : extractedTokens.entrySet()) {
                    String value = entry.getValue();
                    if (value.length() > 40) {
                        value = value.substring(0, 40) + "...";
                    }
                    tokenInfo.append("\n  • ").append(entry.getKey()).append(": ").append(value);
                }
            }

            javax.swing.JOptionPane.showMessageDialog(
                null,
                I18n.t("dialog.addsession.success", role, sessionName, tokenInfo.toString()),
                I18n.t("dialog.addsession.success.title"),
                javax.swing.JOptionPane.INFORMATION_MESSAGE
            );
        }
    }

    /**
     * Faz 2: capture the selected request as an encrypted login profile (keyed by host) so the
     * SessionKeeper can auto re-login by replaying it when a session dies mid-scan.
     */
    private void captureLoginProfile(IHttpRequestResponse message) {
        if (credentialStore == null || message == null) {
            stderr.println("[✗] CredentialStore null! Extension başlatılmadı.");
            return;
        }
        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(message);
            String host = reqInfo.getUrl().getHost();
            String role = javax.swing.JOptionPane.showInputDialog(null,
                    I18n.t("dialog.loginprofile.prompt", host),
                    I18n.t("dialog.loginprofile.title"), javax.swing.JOptionPane.QUESTION_MESSAGE);
            if (role == null || role.trim().isEmpty()) return;

            burp.session.LoginProfile p = new burp.session.LoginProfile();
            p.host = host;
            p.roleLabel = role.trim();
            p.capturedLoginRequest = message.getRequest();
            IHttpService svc = message.getHttpService();
            p.loginHost = svc.getHost();
            p.loginPort = svc.getPort();
            p.loginHttps = "https".equalsIgnoreCase(svc.getProtocol());
            credentialStore.save(p);

            javax.swing.JOptionPane.showMessageDialog(null,
                    I18n.t("dialog.loginprofile.success", host, p.roleLabel),
                    I18n.t("dialog.loginprofile.success.title"), javax.swing.JOptionPane.INFORMATION_MESSAGE);
            stdout.println("[✓] Login profile saved (encrypted) for " + host + " role=" + p.roleLabel);
        } catch (Exception ex) {
            stderr.println("[✗] Login profili kaydedilemedi: " + ex.getMessage());
            javax.swing.JOptionPane.showMessageDialog(null,
                    I18n.t("dialog.loginprofile.error", ex.getMessage()),
                    I18n.t("dialog.common.error.title"), javax.swing.JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Extract authentication tokens from request
     */
    private Map<String, String> extractAuthTokensFromRequest(IHttpRequestResponse request) {
        Map<String, String> tokens = new HashMap<>();

        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(request);
            List<String> headers = reqInfo.getHeaders();

            for (String header : headers) {
                String lower = header.toLowerCase();

                if (lower.startsWith("cookie:")) {
                    String cookieValue = header.substring(7).trim();
                    tokens.put("Cookie", cookieValue);
                }
                else if (lower.startsWith("authorization:")) {
                    String authValue = header.substring(14).trim();
                    tokens.put("Authorization", authValue);
                }
                else if (lower.startsWith("x-auth-token:")) {
                    String tokenValue = header.substring(13).trim();
                    tokens.put("X-Auth-Token", tokenValue);
                }
                else if (lower.startsWith("x-api-key:")) {
                    String keyValue = header.substring(10).trim();
                    tokens.put("X-API-Key", keyValue);
                }
                else if (lower.startsWith("x-access-token:")) {
                    String tokenValue = header.substring(15).trim();
                    tokens.put("X-Access-Token", tokenValue);
                }
                else if (lower.startsWith("x-csrf-token:")) {
                    String csrfValue = header.substring(13).trim();
                    tokens.put("X-CSRF-Token", csrfValue);
                }
            }

        } catch (Exception e) {
            stderr.println("[!] Token extraction failed: " + e.getMessage());
        }

        return tokens;
    }

    /**
     * Extension unload - cleanup
     */
    public void extensionUnloaded() {
        try {
            PrintWriter out = stdout != null ? stdout : new PrintWriter(System.out, true);
            PrintWriter err = stderr != null ? stderr : new PrintWriter(System.err, true);

            out.println("[*] AppSecHunter is unloading...");

            // Stop ambient hunter + triage worker
            if (backgroundHunter != null) {
                backgroundHunter.kill();
            }
            if (ambientCoordinator != null) {
                ambientCoordinator.stop();
            }

            // Save session data to Burp project
            if (databaseManager != null) {
                String sessionData = databaseManager.exportSessionData();
                callbacks.saveExtensionSetting("appsechunter_session_data", sessionData);
                out.println("[✓] Session data saved to Burp project");
            }
            
            // Close database
            if (databaseManager != null) {
                databaseManager.close();
                out.println("[✓] Database closed");
            }
            
            out.println("[✓] AppSecHunter unloaded successfully");
            out.println("[i] Created by Zahid Eroglu - Thank you for using!");
            
        } catch (Exception e) {
            if (stderr != null) {
                stderr.println("[✗] Error during unload: " + e.getMessage());
                e.printStackTrace(stderr);
            }
        }
    }
}

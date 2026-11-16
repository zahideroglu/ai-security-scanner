package burp;

import org.json.*;
import java.util.*;

/**
 * Settings Model - Extension configuration
 * 
 * @author Zahid Eroglu
 */
public class Settings {
    
    // API Configuration
    private String apiUrl;
    private String apiKey;
    private String model;
    private int timeout;
    private boolean allowInsecureSsl;

    // UI language: "tr" (Türkçe) or "en" (English). Applied live via burp.i18n.I18n.
    private String language;
    
    // NEW: Dual API Support - Gateway API
    private String apiProvider; // "hosted" (OpenAI-compatible + API key), "local" or "gateway"
    private String gatewayApiUrl;
    private String gatewayUsername;
    private String gatewayPassword;
    private String gatewayClientId;
    private String gatewayClientSecret;
    private String gatewayRequestedSubject;

    // NEW: Local AI Model Support (Ollama / LM Studio / llama.cpp - OpenAI compatible)
    private String localApiUrl;
    private String localModel;
    private String localApiKey;

    // NEW: Fast detection engine config
    private boolean fastModelEnabled;
    private String fastModel;
    private int engineMaxTokens;
    private int activeScanParallelism;
    private int siteScanMaxEndpoints;   // max endpoints/inputs scanned per site/history scan
    private boolean deepAiPassEnabled;

    // NEW: Agentic AI Pentester (ReAct loop) — focuses on Burp's blind spots
    private int agentMaxSteps;
    private boolean agentUseMultiSession;
    private boolean agentAllowRawRequest;      // advanced; OFF = safe mode (no raw/method change)
    private String agentModel;                 // blank => use getEngineModel()
    private String loginProfilesJson;          // JSON array of LoginProfile (auto-login for fresh sessions)
    private boolean agentFocusAccessControl;
    private boolean agentFocusBusinessLogic;
    private boolean agentFocusAuthJwt;
    private boolean agentFocusMultiStep;

    // NEW: Whole-site multi-agent orchestration + performance
    private int agentSiteConcurrency;       // parallel specialized agents
    private String agentPlaybookDir;        // external .md playbook folder
    private boolean agentLoadExternalPlaybooks;
    private long agentSiteTokenBudget;      // cumulative token ceiling per site scan; 0 = unlimited
    private String agentRouterMode;         // heuristic | ai | all
    private boolean heuristicScanEnabled;   // deterministic ActiveScanEngine module scan; default OFF (AI-only)
    private boolean contentDiscoveryEnabled; // forced-browsing / endpoint dir-scan (/logs,/api…); default OFF — AI mode focuses on IDOR/BOLA/BAC
    private int agentTurnTimeoutSec;        // hard per-LLM-turn timeout
    private int agentSiteTimeBudgetMin;     // wall-clock ceiling per site scan (minutes); 0 = unlimited

    // NEW: Ambient Security Copilot (passive triage + autonomous background hunter)
    private boolean ambientEnabled;                    // master switch for passive triage
    private boolean ambientHunterEnabled;              // autonomous background hunting on/off
    private int ambientMinScore;                       // opportunity-queue threshold (0..100)
    private boolean ambientScopeOnly;                  // hard scope gate for autonomy
    private boolean ambientShareRateLimiterWithManual; // global RPS coupling manual<->autonomous

    // NEW: Scan module toggles (default ON)
    private boolean moduleIdorEnabled;
    private boolean moduleAccessControlEnabled;
    private boolean moduleInjectionEnabled;
    private boolean moduleMisconfigEnabled;
    private boolean moduleSsrfRedirectEnabled;
    private boolean moduleCaptchaBypassEnabled; // AI-assisted CAPTCHA / auth-step bypass on login-type requests

    // NEW: Aggressive/intrusive test toggles (default OFF - confirmed per scan)
    private boolean bruteForceEnabled;
    private boolean moduleMassAssignmentEnabled; // intrusive: injects privileged body properties (BOPLA)
    private boolean fileUploadTestEnabled;
    private boolean ssrfActiveEnabled;
    private boolean commandInjectionTimingEnabled;
    
    // Scan Configuration
    private boolean autoScanEnabled;
    private boolean useBurpScope;
    private double minConfidence;
    private int maxConcurrent;
    
    // Filter Configuration
    private boolean excludeStatic;
    private boolean excludeCDN;
    private boolean excludeAnalytics;
    private boolean excludeSocial;
    private boolean excludeOptions;
    private boolean excludeWebSocket;
    private List<String> customExclusions;
    
    // Vulnerability Types
    private Map<String, Boolean> enabledVulnTypes;

    // NEW: Dynamic Testing Configuration
    private boolean businessLogicTestingEnabled;
    private boolean idorTestingEnabled;
    private boolean jwtTestingEnabled;
    private boolean wafEvasionEnabled;

    // NEW: AI Features
    private boolean aiContextAnalysisEnabled;
    private boolean aiSmartPayloadsEnabled;
    private boolean aiFalsePositiveFilterEnabled;

    // NEW: Request Throttling Configuration
    private int maxRequestsPerMinute;   // HARD per-minute ceiling (FW protection): total target requests/min across ALL paths
    private int maxRequestsPerSecond;   // burst smoothing on top of the per-minute budget
    private int slowModeDelayMs;
    private int wafDetectionThreshold;

    /**
     * Constructor
     */
    public Settings() {
        this.customExclusions = new ArrayList<>();
        this.enabledVulnTypes = new HashMap<>();
        initializeDefaultVulnTypes();
    }
    
    /**
     * Initialize default vulnerability types
     */
    private void initializeDefaultVulnTypes() {
        // SQL Injection and XSS are disabled extension-wide (covered by Burp's own scanner);
        // they are also hard-dropped at the reporting layer — see ScanManager.isDisabledVulnType.
        enabledVulnTypes.put("SQL", false);
        enabledVulnTypes.put("XSS", false);
        enabledVulnTypes.put("Command", true);
        enabledVulnTypes.put("Path", true);
        enabledVulnTypes.put("SSRF", true);
        enabledVulnTypes.put("IDOR", true);
        enabledVulnTypes.put("Auth", true);
        enabledVulnTypes.put("Info", true);
        enabledVulnTypes.put("CSRF", false);
        enabledVulnTypes.put("XXE", true);
    }
    
    /**
     * Get default settings
     */
    public static Settings getDefaults() {
        Settings settings = new Settings();
        
        // Default to a hosted, OpenAI-compatible API (OpenAI / OpenRouter / Groq / … + API key)
        settings.apiProvider = "hosted";
        settings.apiUrl = "https://api.openai.com/v1";
        settings.apiKey = SecretsProvider.apiKey();   // from env / ~/.appsechunter/secrets.json (never hardcoded)
        settings.model = "gpt-4o-mini";  // neutral, low-cost default; user picks their own model/provider
        settings.timeout = 120;
        settings.allowInsecureSsl = false;
        settings.language = "tr"; // default UI language: Turkish

        // Gateway API defaults — credentials come from SecretsProvider (env / secrets.json), NOT source.
        settings.gatewayApiUrl = "https://your-llm-gateway.example.com/v1";
        settings.gatewayUsername = SecretsProvider.gatewayUsername();
        settings.gatewayPassword = SecretsProvider.gatewayPassword();
        settings.gatewayClientId = SecretsProvider.gatewayClientId();
        settings.gatewayClientSecret = SecretsProvider.gatewayClientSecret();
        settings.gatewayRequestedSubject = SecretsProvider.gatewayRequestedSubject();

        // Local AI Model defaults (Ollama)
        settings.localApiUrl = "http://localhost:11434/v1";
        settings.localModel = "qwen2.5-coder:7b";
        settings.localApiKey = "";

        // Fast detection engine defaults
        settings.fastModelEnabled = true;
        settings.fastModel = "";              // empty => use the main model
        settings.engineMaxTokens = 512;
        settings.activeScanParallelism = 2;  // burst smoothing (was 8→4→2); fewer simultaneous probes -> gentler footprint
        settings.siteScanMaxEndpoints = 40;
        settings.deepAiPassEnabled = true;
        settings.agentMaxSteps = 20;
        settings.agentUseMultiSession = true;
        settings.agentAllowRawRequest = true; // default-on (settings checkbox removed)
        settings.agentModel = "";
        settings.loginProfilesJson = "";
        settings.agentFocusAccessControl = true;
        settings.agentFocusBusinessLogic = true;
        settings.agentFocusAuthJwt = true;
        settings.agentFocusMultiStep = true;
        settings.agentSiteConcurrency = 2;  // parallel agents (was 4); fewer concurrent streams -> gentler burst
        settings.agentPlaybookDir = System.getProperty("user.home") + "/.burp_ai_scanner_playbooks";
        settings.agentLoadExternalPlaybooks = false;
        settings.agentSiteTokenBudget = 0L;
        settings.agentRouterMode = "ai";        // LLM triages 1-3 relevant playbooks (was "all")
        settings.heuristicScanEnabled = false;  // default: AI-only scanning, no deterministic module barrage
        settings.contentDiscoveryEnabled = false; // default: no /logs,/api dir-scan — focus on IDOR/BOLA/BAC
        settings.agentTurnTimeoutSec = 120;
        settings.agentSiteTimeBudgetMin = 0;
        settings.ambientEnabled = true;       // default-on (settings checkbox removed)
        settings.ambientHunterEnabled = true; // default-on; autonomous hunter (kill switch lives in the Copilot panel)
        settings.ambientMinScore = 35;
        settings.ambientScopeOnly = true;
        settings.ambientShareRateLimiterWithManual = true;
        settings.moduleIdorEnabled = true;
        settings.moduleAccessControlEnabled = true;
        settings.moduleInjectionEnabled = true;
        settings.moduleMisconfigEnabled = true;
        settings.moduleSsrfRedirectEnabled = true;
        settings.moduleCaptchaBypassEnabled = true; // ON: user wants CAPTCHA bypass attempted (low-volume, ~4 reqs)
        settings.bruteForceEnabled = true;
        settings.moduleMassAssignmentEnabled = false;
        settings.fileUploadTestEnabled = true;
        settings.ssrfActiveEnabled = true;
        settings.commandInjectionTimingEnabled = true;

        settings.autoScanEnabled = false;
        settings.useBurpScope = true;
        settings.minConfidence = 0.7;
        settings.maxConcurrent = 1;
        settings.excludeStatic = true;
        settings.excludeCDN = true;
        settings.excludeAnalytics = true;
        settings.excludeSocial = true;
        settings.excludeOptions = true;
        settings.excludeWebSocket = true;
        settings.customExclusions = Arrays.asList("/health", "/metrics", "/favicon.ico");

        // NEW: Enable all dynamic testing by default
        settings.businessLogicTestingEnabled = true;
        settings.idorTestingEnabled = true;
        settings.jwtTestingEnabled = true;
        settings.wafEvasionEnabled = true;

        // NEW: Enable AI features by default
        settings.aiContextAnalysisEnabled = true;
        settings.aiSmartPayloadsEnabled = true;
        settings.aiFalsePositiveFilterEnabled = true;

        // NEW: Request throttling defaults. The per-minute ceiling is the FW guard (firewall bans the IP
        // for a day past ~200-300 sessions/min) — kept safely below that and applied to EVERY request path.
        settings.maxRequestsPerMinute = 100; // hard per-minute ceiling across all paths (FW protection; was 150)
        settings.maxRequestsPerSecond = 3;  // burst smoothing (was 5); per-minute budget is the binding cap
        settings.slowModeDelayMs = 4000;    // 4 seconds delay in slow mode (WAF detected)
        settings.wafDetectionThreshold = 3; // 3 consecutive blocks to detect WAF

        return settings;
    }
    
    /**
     * Convert to JSON
     */
    public JSONObject toJSON() {
        JSONObject json = new JSONObject();
        
        json.put("apiProvider", apiProvider);
        json.put("apiUrl", apiUrl);
        json.put("language", language);
        json.put("apiKey", apiKey);
        json.put("model", model);
        json.put("timeout", timeout);
        json.put("allowInsecureSsl", allowInsecureSsl);
        
        // Gateway API settings
        json.put("gatewayApiUrl", gatewayApiUrl);
        json.put("gatewayUsername", gatewayUsername);
        json.put("gatewayPassword", gatewayPassword);
        json.put("gatewayClientId", gatewayClientId);
        json.put("gatewayClientSecret", gatewayClientSecret);
        json.put("gatewayRequestedSubject", gatewayRequestedSubject);

        // Local AI Model settings
        json.put("localApiUrl", localApiUrl);
        json.put("localModel", localModel);
        json.put("localApiKey", localApiKey);

        // Fast detection engine settings
        json.put("fastModelEnabled", fastModelEnabled);
        json.put("fastModel", fastModel);
        json.put("engineMaxTokens", engineMaxTokens);
        json.put("activeScanParallelism", activeScanParallelism);
        json.put("siteScanMaxEndpoints", siteScanMaxEndpoints);
        json.put("deepAiPassEnabled", deepAiPassEnabled);
        json.put("agentMaxSteps", agentMaxSteps);
        json.put("agentUseMultiSession", agentUseMultiSession);
        json.put("agentAllowRawRequest", agentAllowRawRequest);
        json.put("agentModel", agentModel);
        json.put("loginProfilesJson", loginProfilesJson);
        json.put("agentFocusAccessControl", agentFocusAccessControl);
        json.put("agentFocusBusinessLogic", agentFocusBusinessLogic);
        json.put("agentFocusAuthJwt", agentFocusAuthJwt);
        json.put("agentFocusMultiStep", agentFocusMultiStep);
        json.put("agentSiteConcurrency", agentSiteConcurrency);
        json.put("agentPlaybookDir", agentPlaybookDir);
        json.put("agentLoadExternalPlaybooks", agentLoadExternalPlaybooks);
        json.put("agentSiteTokenBudget", agentSiteTokenBudget);
        json.put("agentRouterMode", agentRouterMode);
        json.put("heuristicScanEnabled", heuristicScanEnabled);
        json.put("contentDiscoveryEnabled", contentDiscoveryEnabled);
        json.put("agentTurnTimeoutSec", agentTurnTimeoutSec);
        json.put("agentSiteTimeBudgetMin", agentSiteTimeBudgetMin);
        json.put("ambientEnabled", ambientEnabled);
        json.put("ambientHunterEnabled", ambientHunterEnabled);
        json.put("ambientMinScore", ambientMinScore);
        json.put("ambientScopeOnly", ambientScopeOnly);
        json.put("ambientShareRateLimiterWithManual", ambientShareRateLimiterWithManual);
        json.put("moduleIdorEnabled", moduleIdorEnabled);
        json.put("moduleAccessControlEnabled", moduleAccessControlEnabled);
        json.put("moduleInjectionEnabled", moduleInjectionEnabled);
        json.put("moduleMisconfigEnabled", moduleMisconfigEnabled);
        json.put("moduleSsrfRedirectEnabled", moduleSsrfRedirectEnabled);
        json.put("moduleCaptchaBypassEnabled", moduleCaptchaBypassEnabled);
        json.put("bruteForceEnabled", bruteForceEnabled);
        json.put("moduleMassAssignmentEnabled", moduleMassAssignmentEnabled);
        json.put("fileUploadTestEnabled", fileUploadTestEnabled);
        json.put("ssrfActiveEnabled", ssrfActiveEnabled);
        json.put("commandInjectionTimingEnabled", commandInjectionTimingEnabled);

        json.put("autoScanEnabled", autoScanEnabled);
        json.put("useBurpScope", useBurpScope);
        json.put("minConfidence", minConfidence);
        json.put("maxConcurrent", maxConcurrent);
        json.put("excludeStatic", excludeStatic);
        json.put("excludeCDN", excludeCDN);
        json.put("excludeAnalytics", excludeAnalytics);
        json.put("excludeSocial", excludeSocial);
        json.put("excludeOptions", excludeOptions);
        json.put("excludeWebSocket", excludeWebSocket);
        json.put("customExclusions", new JSONArray(customExclusions));
        json.put("enabledVulnTypes", new JSONObject(enabledVulnTypes));

        // Dynamic Testing
        json.put("businessLogicTestingEnabled", businessLogicTestingEnabled);
        json.put("idorTestingEnabled", idorTestingEnabled);
        json.put("jwtTestingEnabled", jwtTestingEnabled);
        json.put("wafEvasionEnabled", wafEvasionEnabled);

        // AI Features
        json.put("aiContextAnalysisEnabled", aiContextAnalysisEnabled);
        json.put("aiSmartPayloadsEnabled", aiSmartPayloadsEnabled);
        json.put("aiFalsePositiveFilterEnabled", aiFalsePositiveFilterEnabled);

        // Request Throttling
        json.put("maxRequestsPerMinute", maxRequestsPerMinute);
        json.put("maxRequestsPerSecond", maxRequestsPerSecond);
        json.put("slowModeDelayMs", slowModeDelayMs);
        json.put("wafDetectionThreshold", wafDetectionThreshold);

        return json;
    }
    
    /**
     * Create from JSON
     */
    public static Settings fromJSON(JSONObject json) {
        Settings settings = new Settings();
        
        settings.apiProvider = json.optString("apiProvider", "hosted");
        if ("qwen".equals(settings.apiProvider)) settings.apiProvider = "hosted";  // legacy id → hosted
        settings.language = json.optString("language", "tr");
        settings.apiUrl = json.optString("apiUrl", "https://api.openai.com/v1");
        settings.apiKey = json.optString("apiKey", SecretsProvider.apiKey());
        settings.model = json.optString("model", "gpt-4o-mini");  // neutral default; user picks their model

        // Auto-heal known-bad legacy values saved by older versions (sources the key from
        // SecretsProvider — env / ~/.appsechunter/secrets.json — never a hardcoded literal).
        if (settings.apiKey == null || settings.apiKey.trim().isEmpty() || "test-key".equals(settings.apiKey)) {
            settings.apiKey = SecretsProvider.apiKey();
        }
        settings.timeout = json.optInt("timeout", 120);
        settings.allowInsecureSsl = json.optBoolean("allowInsecureSsl", false);
        
        // Gateway API settings — credentials from SecretsProvider (env / ~/.appsechunter/secrets.json), not source.
        settings.gatewayApiUrl = json.optString("gatewayApiUrl", "https://your-llm-gateway.example.com/v1");
        settings.gatewayUsername = json.optString("gatewayUsername", SecretsProvider.gatewayUsername());
        settings.gatewayPassword = json.optString("gatewayPassword", SecretsProvider.gatewayPassword());
        settings.gatewayClientId = json.optString("gatewayClientId", SecretsProvider.gatewayClientId());
        settings.gatewayClientSecret = json.optString("gatewayClientSecret", SecretsProvider.gatewayClientSecret());
        settings.gatewayRequestedSubject = json.optString("gatewayRequestedSubject", SecretsProvider.gatewayRequestedSubject());
        // Auto-heal configs saved empty by older builds.
        if (settings.gatewayApiUrl == null || settings.gatewayApiUrl.trim().isEmpty()) {
            settings.gatewayApiUrl = "https://your-llm-gateway.example.com/v1";
        }
        if (settings.gatewayUsername == null || settings.gatewayUsername.trim().isEmpty())
            settings.gatewayUsername = SecretsProvider.gatewayUsername();
        if (settings.gatewayPassword == null || settings.gatewayPassword.trim().isEmpty())
            settings.gatewayPassword = SecretsProvider.gatewayPassword();
        if (settings.gatewayClientId == null || settings.gatewayClientId.trim().isEmpty())
            settings.gatewayClientId = SecretsProvider.gatewayClientId();
        if (settings.gatewayClientSecret == null || settings.gatewayClientSecret.trim().isEmpty())
            settings.gatewayClientSecret = SecretsProvider.gatewayClientSecret();
        if (settings.gatewayRequestedSubject == null || settings.gatewayRequestedSubject.trim().isEmpty())
            settings.gatewayRequestedSubject = SecretsProvider.gatewayRequestedSubject();

        // Local AI Model settings
        settings.localApiUrl = json.optString("localApiUrl", "http://localhost:11434/v1");
        settings.localModel = json.optString("localModel", "qwen2.5-coder:7b");
        settings.localApiKey = json.optString("localApiKey", "");

        // Fast detection engine settings
        settings.fastModelEnabled = json.optBoolean("fastModelEnabled", true);
        settings.fastModel = json.optString("fastModel", "");
        settings.engineMaxTokens = json.optInt("engineMaxTokens", 512);
        settings.activeScanParallelism = json.optInt("activeScanParallelism", 2);
        settings.siteScanMaxEndpoints = json.optInt("siteScanMaxEndpoints", 40);
        settings.deepAiPassEnabled = true; // always-on (settings UI removed; "default on")
        settings.agentMaxSteps = json.optInt("agentMaxSteps", 20);
        settings.agentUseMultiSession = json.optBoolean("agentUseMultiSession", true);
        settings.agentAllowRawRequest = json.optBoolean("agentAllowRawRequest", true); // default-on (checkbox removed)
        settings.agentModel = json.optString("agentModel", "");
        settings.loginProfilesJson = json.optString("loginProfilesJson", "");
        settings.agentFocusAccessControl = json.optBoolean("agentFocusAccessControl", true);
        settings.agentFocusBusinessLogic = json.optBoolean("agentFocusBusinessLogic", true);
        settings.agentFocusAuthJwt = json.optBoolean("agentFocusAuthJwt", true);
        settings.agentFocusMultiStep = json.optBoolean("agentFocusMultiStep", true);
        settings.agentSiteConcurrency = json.optInt("agentSiteConcurrency", 2);
        settings.agentPlaybookDir = json.optString("agentPlaybookDir",
                System.getProperty("user.home") + "/.burp_ai_scanner_playbooks");
        settings.agentLoadExternalPlaybooks = json.optBoolean("agentLoadExternalPlaybooks", false);
        settings.agentSiteTokenBudget = json.optLong("agentSiteTokenBudget", 0L);
        settings.agentRouterMode = json.optString("agentRouterMode", "ai");
        settings.heuristicScanEnabled = json.optBoolean("heuristicScanEnabled", false);
        settings.contentDiscoveryEnabled = json.optBoolean("contentDiscoveryEnabled", false);
        settings.agentTurnTimeoutSec = json.optInt("agentTurnTimeoutSec", 120);
        settings.agentSiteTimeBudgetMin = json.optInt("agentSiteTimeBudgetMin", 0);
        settings.ambientEnabled = json.optBoolean("ambientEnabled", true); // default-on (checkbox removed)
        settings.ambientHunterEnabled = json.optBoolean("ambientHunterEnabled", true); // default-on; declining the hunt-consent still persists false
        settings.ambientMinScore = json.optInt("ambientMinScore", 35);
        settings.ambientScopeOnly = json.optBoolean("ambientScopeOnly", true);
        settings.ambientShareRateLimiterWithManual = json.optBoolean("ambientShareRateLimiterWithManual", true);
        // OWASP modules, aggressive/intrusive tests and the deep-AI pass are always-on:
        // their settings UI was removed (user request "default on"). Forced on regardless
        // of any older saved value; intrusive tests stay gated by the per-scan confirmation
        // dialog (see BurpExtender). Mass-assignment is not part of that section -> unchanged.
        settings.moduleIdorEnabled = true;
        settings.moduleAccessControlEnabled = true;
        settings.moduleInjectionEnabled = true;
        settings.moduleMisconfigEnabled = true;
        settings.moduleSsrfRedirectEnabled = true;
        settings.moduleCaptchaBypassEnabled = true;
        settings.bruteForceEnabled = true;
        settings.moduleMassAssignmentEnabled = json.optBoolean("moduleMassAssignmentEnabled", false);
        settings.fileUploadTestEnabled = true;
        settings.ssrfActiveEnabled = true;
        settings.commandInjectionTimingEnabled = true;

        settings.autoScanEnabled = json.optBoolean("autoScanEnabled", false);
        settings.useBurpScope = json.optBoolean("useBurpScope", true);
        settings.minConfidence = json.optDouble("minConfidence", 0.7);
        settings.maxConcurrent = json.optInt("maxConcurrent", 1);
        settings.excludeStatic = json.optBoolean("excludeStatic", true);
        settings.excludeCDN = json.optBoolean("excludeCDN", true);
        settings.excludeAnalytics = json.optBoolean("excludeAnalytics", true);
        settings.excludeSocial = json.optBoolean("excludeSocial", true);
        settings.excludeOptions = json.optBoolean("excludeOptions", true);
        settings.excludeWebSocket = json.optBoolean("excludeWebSocket", true);
        
        // Custom exclusions
        JSONArray exclusions = json.optJSONArray("customExclusions");
        if (exclusions != null) {
            settings.customExclusions = new ArrayList<>();
            for (int i = 0; i < exclusions.length(); i++) {
                settings.customExclusions.add(exclusions.getString(i));
            }
        }
        
        // Vuln types
        JSONObject vulnTypes = json.optJSONObject("enabledVulnTypes");
        if (vulnTypes != null) {
            for (String key : vulnTypes.keySet()) {
                settings.enabledVulnTypes.put(key, vulnTypes.getBoolean(key));
            }
        }

        // Dynamic Testing
        settings.businessLogicTestingEnabled = json.optBoolean("businessLogicTestingEnabled", true);
        settings.idorTestingEnabled = json.optBoolean("idorTestingEnabled", true);
        settings.jwtTestingEnabled = json.optBoolean("jwtTestingEnabled", true);
        settings.wafEvasionEnabled = json.optBoolean("wafEvasionEnabled", true);

        // AI Features
        settings.aiContextAnalysisEnabled = json.optBoolean("aiContextAnalysisEnabled", true);
        settings.aiSmartPayloadsEnabled = json.optBoolean("aiSmartPayloadsEnabled", true);
        settings.aiFalsePositiveFilterEnabled = json.optBoolean("aiFalsePositiveFilterEnabled", true);

        // Request Throttling
        settings.maxRequestsPerMinute = json.optInt("maxRequestsPerMinute", 100);
        settings.maxRequestsPerSecond = json.optInt("maxRequestsPerSecond", 3);
        settings.slowModeDelayMs = json.optInt("slowModeDelayMs", 4000);
        settings.wafDetectionThreshold = json.optInt("wafDetectionThreshold", 3);

        return settings;
    }
    
    // Getters and Setters
    public String getApiProvider() { return apiProvider; }
    public void setApiProvider(String apiProvider) { this.apiProvider = apiProvider; }
    
    public String getApiUrl() { return apiUrl; }
    public void setApiUrl(String apiUrl) { this.apiUrl = apiUrl; }
    
    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }
    
    public String getModel() { return model; }
    public void setModel(String model) { this.model = model; }
    
    public int getTimeout() { return timeout; }
    public void setTimeout(int timeout) { this.timeout = timeout; }

    public boolean isAllowInsecureSsl() { return allowInsecureSsl; }
    public void setAllowInsecureSsl(boolean allowInsecureSsl) { this.allowInsecureSsl = allowInsecureSsl; }
    
    // Gateway API Getters/Setters
    public String getGatewayApiUrl() { return gatewayApiUrl; }
    public void setGatewayApiUrl(String gatewayApiUrl) { this.gatewayApiUrl = gatewayApiUrl; }
    
    public String getGatewayUsername() { return gatewayUsername; }
    public void setGatewayUsername(String gatewayUsername) { this.gatewayUsername = gatewayUsername; }
    
    public String getGatewayPassword() { return gatewayPassword; }
    public void setGatewayPassword(String gatewayPassword) { this.gatewayPassword = gatewayPassword; }
    
    public String getGatewayClientId() { return gatewayClientId; }
    public void setGatewayClientId(String gatewayClientId) { this.gatewayClientId = gatewayClientId; }
    
    public String getGatewayClientSecret() { return gatewayClientSecret; }
    public void setGatewayClientSecret(String gatewayClientSecret) { this.gatewayClientSecret = gatewayClientSecret; }
    
    public String getGatewayRequestedSubject() { return gatewayRequestedSubject; }
    public void setGatewayRequestedSubject(String gatewayRequestedSubject) { this.gatewayRequestedSubject = gatewayRequestedSubject; }

    // Local AI Model Getters/Setters
    public String getLocalApiUrl() { return localApiUrl; }
    public void setLocalApiUrl(String localApiUrl) { this.localApiUrl = localApiUrl; }

    public String getLocalModel() { return localModel; }
    public void setLocalModel(String localModel) { this.localModel = localModel; }

    public String getLocalApiKey() { return localApiKey; }
    public void setLocalApiKey(String localApiKey) { this.localApiKey = localApiKey; }

    // Fast detection engine getters/setters
    public boolean isFastModelEnabled() { return fastModelEnabled; }
    public void setFastModelEnabled(boolean v) { this.fastModelEnabled = v; }

    public String getFastModel() { return fastModel; }
    public void setFastModel(String v) { this.fastModel = v; }

    /** The model the fast engine should use: fastModel if enabled+set, else main model. */
    public String getEngineModel() {
        if (fastModelEnabled && fastModel != null && !fastModel.trim().isEmpty()) {
            return fastModel.trim();
        }
        return "local".equals(apiProvider) ? localModel : model;
    }

    public int getEngineMaxTokens() { return engineMaxTokens; }
    public void setEngineMaxTokens(int v) { this.engineMaxTokens = v; }

    public int getActiveScanParallelism() { return activeScanParallelism; }
    public void setActiveScanParallelism(int v) { this.activeScanParallelism = v; }

    public int getSiteScanMaxEndpoints() { return siteScanMaxEndpoints; }
    public void setSiteScanMaxEndpoints(int v) { this.siteScanMaxEndpoints = v; }

    public int getAgentMaxSteps() { return agentMaxSteps; }
    public void setAgentMaxSteps(int v) { this.agentMaxSteps = v; }
    public boolean isAgentUseMultiSession() { return agentUseMultiSession; }
    public void setAgentUseMultiSession(boolean v) { this.agentUseMultiSession = v; }
    public boolean isAgentAllowRawRequest() { return agentAllowRawRequest; }
    public void setAgentAllowRawRequest(boolean v) { this.agentAllowRawRequest = v; }
    /** Agent model override; falls back to the engine model when blank. */
    public String getAgentModel() {
        return (agentModel != null && !agentModel.trim().isEmpty()) ? agentModel.trim() : getEngineModel();
    }
    public void setAgentModel(String v) { this.agentModel = v; }
    /** Raw JSON array of auto-login profiles (blank if unset). */
    public String getLoginProfilesJson() { return loginProfilesJson == null ? "" : loginProfilesJson; }
    public void setLoginProfilesJson(String v) { this.loginProfilesJson = v; }
    /** Parsed, valid auto-login profiles (empty if none configured). */
    public java.util.List<burp.authz.LoginProfile> getLoginProfiles() {
        return burp.authz.LoginProfile.listFromJson(getLoginProfilesJson());
    }
    /** Raw stored override (blank if unset) — for the settings text field. */
    public String getAgentModelRaw() { return agentModel == null ? "" : agentModel; }
    public boolean isAgentFocusAccessControl() { return agentFocusAccessControl; }
    public void setAgentFocusAccessControl(boolean v) { this.agentFocusAccessControl = v; }
    public boolean isAgentFocusBusinessLogic() { return agentFocusBusinessLogic; }
    public void setAgentFocusBusinessLogic(boolean v) { this.agentFocusBusinessLogic = v; }
    public boolean isAgentFocusAuthJwt() { return agentFocusAuthJwt; }
    public void setAgentFocusAuthJwt(boolean v) { this.agentFocusAuthJwt = v; }
    public boolean isAgentFocusMultiStep() { return agentFocusMultiStep; }
    public void setAgentFocusMultiStep(boolean v) { this.agentFocusMultiStep = v; }

    public int getAgentSiteConcurrency() { return agentSiteConcurrency; }
    public void setAgentSiteConcurrency(int v) { this.agentSiteConcurrency = v; }
    /** External playbook dir; falls back to the default when blank. */
    public String getAgentPlaybookDir() {
        return (agentPlaybookDir != null && !agentPlaybookDir.trim().isEmpty())
                ? agentPlaybookDir.trim()
                : System.getProperty("user.home") + "/.burp_ai_scanner_playbooks";
    }
    public void setAgentPlaybookDir(String v) { this.agentPlaybookDir = v; }
    public boolean isAgentLoadExternalPlaybooks() { return agentLoadExternalPlaybooks; }
    public void setAgentLoadExternalPlaybooks(boolean v) { this.agentLoadExternalPlaybooks = v; }
    public long getAgentSiteTokenBudget() { return agentSiteTokenBudget; }
    public void setAgentSiteTokenBudget(long v) { this.agentSiteTokenBudget = v; }
    public String getAgentRouterMode() {
        return (agentRouterMode != null && !agentRouterMode.trim().isEmpty()) ? agentRouterMode.trim() : "ai";
    }
    public void setAgentRouterMode(String v) { this.agentRouterMode = v; }

    public boolean isHeuristicScanEnabled() { return heuristicScanEnabled; }
    public void setHeuristicScanEnabled(boolean v) { this.heuristicScanEnabled = v; }
    public boolean isContentDiscoveryEnabled() { return contentDiscoveryEnabled; }
    public void setContentDiscoveryEnabled(boolean v) { this.contentDiscoveryEnabled = v; }
    public int getAgentTurnTimeoutSec() { return agentTurnTimeoutSec > 0 ? agentTurnTimeoutSec : 120; }
    public void setAgentTurnTimeoutSec(int v) { this.agentTurnTimeoutSec = v; }
    public int getAgentSiteTimeBudgetMin() { return agentSiteTimeBudgetMin; }
    public void setAgentSiteTimeBudgetMin(int v) { this.agentSiteTimeBudgetMin = v; }

    // Ambient Security Copilot getters/setters
    public boolean isAmbientEnabled() { return ambientEnabled; }
    public void setAmbientEnabled(boolean v) { this.ambientEnabled = v; }

    /** UI language code: "tr" or "en" (defaults to "tr" if unset). */
    public String getLanguage() { return (language == null || language.isEmpty()) ? "tr" : language; }
    public void setLanguage(String v) { this.language = (v != null && v.toLowerCase().startsWith("en")) ? "en" : "tr"; }
    public boolean isAmbientHunterEnabled() { return ambientHunterEnabled; }
    public void setAmbientHunterEnabled(boolean v) { this.ambientHunterEnabled = v; }
    public int getAmbientMinScore() { return ambientMinScore > 0 ? ambientMinScore : 35; }
    public void setAmbientMinScore(int v) { this.ambientMinScore = v; }
    public boolean isAmbientScopeOnly() { return ambientScopeOnly; }
    public void setAmbientScopeOnly(boolean v) { this.ambientScopeOnly = v; }
    public boolean isAmbientShareRateLimiterWithManual() { return ambientShareRateLimiterWithManual; }
    public void setAmbientShareRateLimiterWithManual(boolean v) { this.ambientShareRateLimiterWithManual = v; }

    public boolean isDeepAiPassEnabled() { return deepAiPassEnabled; }
    public void setDeepAiPassEnabled(boolean v) { this.deepAiPassEnabled = v; }

    public boolean isModuleIdorEnabled() { return moduleIdorEnabled; }
    public void setModuleIdorEnabled(boolean v) { this.moduleIdorEnabled = v; }

    public boolean isModuleAccessControlEnabled() { return moduleAccessControlEnabled; }
    public void setModuleAccessControlEnabled(boolean v) { this.moduleAccessControlEnabled = v; }

    public boolean isModuleInjectionEnabled() { return moduleInjectionEnabled; }
    public void setModuleInjectionEnabled(boolean v) { this.moduleInjectionEnabled = v; }

    public boolean isModuleMisconfigEnabled() { return moduleMisconfigEnabled; }
    public void setModuleMisconfigEnabled(boolean v) { this.moduleMisconfigEnabled = v; }

    public boolean isModuleCaptchaBypassEnabled() { return moduleCaptchaBypassEnabled; }
    public void setModuleCaptchaBypassEnabled(boolean v) { this.moduleCaptchaBypassEnabled = v; }

    public boolean isModuleSsrfRedirectEnabled() { return moduleSsrfRedirectEnabled; }
    public void setModuleSsrfRedirectEnabled(boolean v) { this.moduleSsrfRedirectEnabled = v; }

    public boolean isBruteForceEnabled() { return bruteForceEnabled; }
    public void setBruteForceEnabled(boolean v) { this.bruteForceEnabled = v; }

    public boolean isModuleMassAssignmentEnabled() { return moduleMassAssignmentEnabled; }
    public void setModuleMassAssignmentEnabled(boolean v) { this.moduleMassAssignmentEnabled = v; }

    public boolean isFileUploadTestEnabled() { return fileUploadTestEnabled; }
    public void setFileUploadTestEnabled(boolean v) { this.fileUploadTestEnabled = v; }

    public boolean isSsrfActiveEnabled() { return ssrfActiveEnabled; }
    public void setSsrfActiveEnabled(boolean v) { this.ssrfActiveEnabled = v; }

    public boolean isCommandInjectionTimingEnabled() { return commandInjectionTimingEnabled; }
    public void setCommandInjectionTimingEnabled(boolean v) { this.commandInjectionTimingEnabled = v; }

    /** True if any intrusive module is enabled (drives the per-scan confirmation dialog). */
    public boolean hasAnyIntrusiveEnabled() {
        return bruteForceEnabled || fileUploadTestEnabled || ssrfActiveEnabled
                || moduleMassAssignmentEnabled;
    }

    public boolean isAutoScanEnabled() { return autoScanEnabled; }
    public void setAutoScanEnabled(boolean autoScanEnabled) { this.autoScanEnabled = autoScanEnabled; }
    
    public boolean isUseBurpScope() { return useBurpScope; }
    public void setUseBurpScope(boolean useBurpScope) { this.useBurpScope = useBurpScope; }
    
    public double getMinConfidence() { return minConfidence; }
    public void setMinConfidence(double minConfidence) { this.minConfidence = minConfidence; }
    
    public int getMaxConcurrent() { return maxConcurrent; }
    public void setMaxConcurrent(int maxConcurrent) { this.maxConcurrent = maxConcurrent; }
    
    public boolean isExcludeStatic() { return excludeStatic; }
    public void setExcludeStatic(boolean excludeStatic) { this.excludeStatic = excludeStatic; }
    
    public boolean isExcludeCDN() { return excludeCDN; }
    public void setExcludeCDN(boolean excludeCDN) { this.excludeCDN = excludeCDN; }
    
    public boolean isExcludeAnalytics() { return excludeAnalytics; }
    public void setExcludeAnalytics(boolean excludeAnalytics) { this.excludeAnalytics = excludeAnalytics; }
    
    public boolean isExcludeSocial() { return excludeSocial; }
    public void setExcludeSocial(boolean excludeSocial) { this.excludeSocial = excludeSocial; }
    
    public boolean isExcludeOptions() { return excludeOptions; }
    public void setExcludeOptions(boolean excludeOptions) { this.excludeOptions = excludeOptions; }
    
    public boolean isExcludeWebSocket() { return excludeWebSocket; }
    public void setExcludeWebSocket(boolean excludeWebSocket) { this.excludeWebSocket = excludeWebSocket; }
    
    public List<String> getCustomExclusions() { return customExclusions; }
    public void setCustomExclusions(List<String> customExclusions) { this.customExclusions = customExclusions; }
    
    public Map<String, Boolean> getEnabledVulnTypes() { return enabledVulnTypes; }
    public void setEnabledVulnTypes(Map<String, Boolean> enabledVulnTypes) { this.enabledVulnTypes = enabledVulnTypes; }

    // Alias methods for compatibility
    public String getApiEndpoint() { return apiUrl; }
    public void setApiEndpoint(String apiUrl) { this.apiUrl = apiUrl; }

    public boolean isAutoScan() { return autoScanEnabled; }
    public void setAutoScan(boolean autoScanEnabled) { this.autoScanEnabled = autoScanEnabled; }

    public boolean isUseScope() { return useBurpScope; }
    public void setUseScope(boolean useBurpScope) { this.useBurpScope = useBurpScope; }

    public boolean isFilterStaticFiles() { return excludeStatic; }
    public void setFilterStaticFiles(boolean excludeStatic) { this.excludeStatic = excludeStatic; }

    public boolean isFilterCDN() { return excludeCDN; }
    public void setFilterCDN(boolean excludeCDN) { this.excludeCDN = excludeCDN; }

    public boolean isFilterAnalytics() { return excludeAnalytics; }
    public void setFilterAnalytics(boolean excludeAnalytics) { this.excludeAnalytics = excludeAnalytics; }

    public boolean isFilterSocialMedia() { return excludeSocial; }
    public void setFilterSocialMedia(boolean excludeSocial) { this.excludeSocial = excludeSocial; }

    public boolean isFilterOptions() { return excludeOptions; }
    public void setFilterOptions(boolean excludeOptions) { this.excludeOptions = excludeOptions; }

    public List<String> getCustomFilters() { return customExclusions; }
    public void setCustomFilters(List<String> customExclusions) { this.customExclusions = customExclusions; }

    // NEW: Dynamic Testing Getters/Setters
    public boolean isBusinessLogicTestingEnabled() { return businessLogicTestingEnabled; }
    public void setBusinessLogicTestingEnabled(boolean enabled) { this.businessLogicTestingEnabled = enabled; }

    public boolean isIdorTestingEnabled() { return idorTestingEnabled; }
    public void setIdorTestingEnabled(boolean enabled) { this.idorTestingEnabled = enabled; }

    public boolean isJwtTestingEnabled() { return jwtTestingEnabled; }
    public void setJwtTestingEnabled(boolean enabled) { this.jwtTestingEnabled = enabled; }

    public boolean isWafEvasionEnabled() { return wafEvasionEnabled; }
    public void setWafEvasionEnabled(boolean enabled) { this.wafEvasionEnabled = enabled; }

    // NEW: AI Features Getters/Setters
    public boolean isAiContextAnalysisEnabled() { return aiContextAnalysisEnabled; }
    public void setAiContextAnalysisEnabled(boolean enabled) { this.aiContextAnalysisEnabled = enabled; }

    public boolean isAiSmartPayloadsEnabled() { return aiSmartPayloadsEnabled; }
    public void setAiSmartPayloadsEnabled(boolean enabled) { this.aiSmartPayloadsEnabled = enabled; }

    public boolean isAiFalsePositiveFilterEnabled() { return aiFalsePositiveFilterEnabled; }
    public void setAiFalsePositiveFilterEnabled(boolean enabled) { this.aiFalsePositiveFilterEnabled = enabled; }

    // NEW: Request Throttling Getters/Setters
    public int getMaxRequestsPerMinute() { return maxRequestsPerMinute; }
    public void setMaxRequestsPerMinute(int max) { this.maxRequestsPerMinute = max; }

    public int getMaxRequestsPerSecond() { return maxRequestsPerSecond; }
    public void setMaxRequestsPerSecond(int max) { this.maxRequestsPerSecond = max; }

    public int getSlowModeDelayMs() { return slowModeDelayMs; }
    public void setSlowModeDelayMs(int delayMs) { this.slowModeDelayMs = delayMs; }

    public int getWafDetectionThreshold() { return wafDetectionThreshold; }
    public void setWafDetectionThreshold(int threshold) { this.wafDetectionThreshold = threshold; }
}

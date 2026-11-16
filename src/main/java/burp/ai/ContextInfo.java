package burp.ai;

import java.util.*;

/**
 * Context Information Model
 * Stores analyzed context about the target application
 *
 * @author Zahid Eroglu
 */
public class ContextInfo {

    // Technology Stack
    private String technology;        // PHP, Java, .NET, Node.js, Python, Ruby
    private String framework;         // Laravel, Spring, Django, Express, Rails
    private String webServer;         // Apache, Nginx, IIS, Tomcat

    // Database
    private String database;          // MySQL, PostgreSQL, MSSQL, MongoDB, Oracle
    private String databaseVersion;

    // Security
    private String wafSignature;      // Cloudflare, Akamai, ModSecurity, AWS WAF
    private boolean wafDetected;
    private List<String> securityHeaders;

    // Application Type
    private String applicationType;   // e-commerce, banking, social, api, cms
    private List<String> businessLogic;

    // Custom Findings
    private Map<String, String> customFindings;

    // Framework-specific info
    private String templateEngine;    // Blade, Thymeleaf, Jinja2, EJS
    private String ormFramework;      // Hibernate, Eloquent, SQLAlchemy

    // API Detection
    private boolean isRestAPI;
    private boolean isSOAP;
    private String apiVersion;

    // Authentication
    private String authType;          // JWT, Session, OAuth, Basic, Custom
    private boolean hasMFA;

    // Confidence
    private double confidence;        // 0.0 - 1.0

    public ContextInfo() {
        this.securityHeaders = new ArrayList<>();
        this.businessLogic = new ArrayList<>();
        this.customFindings = new HashMap<>();
        this.confidence = 0.0;
    }

    // Getters and Setters

    public String getTechnology() {
        return technology;
    }

    public void setTechnology(String technology) {
        this.technology = technology;
    }

    public String getFramework() {
        return framework;
    }

    public void setFramework(String framework) {
        this.framework = framework;
    }

    public String getWebServer() {
        return webServer;
    }

    public void setWebServer(String webServer) {
        this.webServer = webServer;
    }

    public String getDatabase() {
        return database;
    }

    public void setDatabase(String database) {
        this.database = database;
    }

    public String getDatabaseVersion() {
        return databaseVersion;
    }

    public void setDatabaseVersion(String databaseVersion) {
        this.databaseVersion = databaseVersion;
    }

    public String getWafSignature() {
        return wafSignature;
    }

    public void setWafSignature(String wafSignature) {
        this.wafSignature = wafSignature;
    }

    public boolean isWafDetected() {
        return wafDetected;
    }

    public void setWafDetected(boolean wafDetected) {
        this.wafDetected = wafDetected;
    }

    public List<String> getSecurityHeaders() {
        return securityHeaders;
    }

    public void setSecurityHeaders(List<String> securityHeaders) {
        this.securityHeaders = securityHeaders;
    }

    public void addSecurityHeader(String header) {
        this.securityHeaders.add(header);
    }

    public String getApplicationType() {
        return applicationType;
    }

    public void setApplicationType(String applicationType) {
        this.applicationType = applicationType;
    }

    public List<String> getBusinessLogic() {
        return businessLogic;
    }

    public void setBusinessLogic(List<String> businessLogic) {
        this.businessLogic = businessLogic;
    }

    public void addBusinessLogic(String logic) {
        this.businessLogic.add(logic);
    }

    public Map<String, String> getCustomFindings() {
        return customFindings;
    }

    public void setCustomFindings(Map<String, String> customFindings) {
        this.customFindings = customFindings;
    }

    public void addCustomFinding(String key, String value) {
        this.customFindings.put(key, value);
    }

    public String getTemplateEngine() {
        return templateEngine;
    }

    public void setTemplateEngine(String templateEngine) {
        this.templateEngine = templateEngine;
    }

    public String getOrmFramework() {
        return ormFramework;
    }

    public void setOrmFramework(String ormFramework) {
        this.ormFramework = ormFramework;
    }

    public boolean isRestAPI() {
        return isRestAPI;
    }

    public void setRestAPI(boolean isRestAPI) {
        this.isRestAPI = isRestAPI;
    }

    public boolean isSOAP() {
        return isSOAP;
    }

    public void setSOAP(boolean isSOAP) {
        this.isSOAP = isSOAP;
    }

    public String getApiVersion() {
        return apiVersion;
    }

    public void setApiVersion(String apiVersion) {
        this.apiVersion = apiVersion;
    }

    public String getAuthType() {
        return authType;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public boolean isHasMFA() {
        return hasMFA;
    }

    public void setHasMFA(boolean hasMFA) {
        this.hasMFA = hasMFA;
    }

    public double getConfidence() {
        return confidence;
    }

    public void setConfidence(double confidence) {
        this.confidence = confidence;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Context Analysis ===\n");
        sb.append("Technology: ").append(technology).append("\n");
        sb.append("Framework: ").append(framework).append("\n");
        sb.append("Web Server: ").append(webServer).append("\n");
        sb.append("Database: ").append(database);
        if (databaseVersion != null) {
            sb.append(" (").append(databaseVersion).append(")");
        }
        sb.append("\n");

        if (wafDetected) {
            sb.append("WAF Detected: ").append(wafSignature).append("\n");
        }

        if (!securityHeaders.isEmpty()) {
            sb.append("Security Headers: ").append(String.join(", ", securityHeaders)).append("\n");
        }

        if (applicationType != null) {
            sb.append("Application Type: ").append(applicationType).append("\n");
        }

        if (isRestAPI) {
            sb.append("API Type: REST");
            if (apiVersion != null) {
                sb.append(" v").append(apiVersion);
            }
            sb.append("\n");
        }

        if (authType != null) {
            sb.append("Authentication: ").append(authType);
            if (hasMFA) {
                sb.append(" (MFA Enabled)");
            }
            sb.append("\n");
        }

        sb.append("Confidence: ").append(String.format("%.2f", confidence * 100)).append("%\n");

        return sb.toString();
    }
}

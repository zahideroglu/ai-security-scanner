package burp;

import org.json.*;
import java.util.*;

/**
 * Finding Model - Represents a security vulnerability
 * Enhanced with CVSS, Priority, and References for professional reporting
 *
 * @author Zahid Eroglu
 */
public class Finding {

    private String type;
    private String severity;
    private double confidence;
    private String description;
    private String affectedUrl;
    private String evidence;
    private String exploitation;
    private String remediation;
    private boolean isFalsePositive;
    private String httpRequest;
    private String httpResponse;
    private String controlResponse; // negative-control (invalid-id) body, for AI BOLA/IDOR judging
    private int dbId = -1; // row id in the findings table once persisted (-1 = not saved)

    // ===== Faz 1: deterministic evidence model =====
    /** Whether a deterministic oracle/comparison backed this finding. NONE = no oracle was run. */
    public enum OracleVerdict { CONFIRMED, REFUTED, INCONCLUSIVE, NONE }
    /** Confidence tier surfaced in reports (maps numeric confidence + oracle). */
    public enum ConfidenceTier { CONFIRMED, FIRM, TENTATIVE }
    private String baselineResponse; // legitimate/owner response body, for comparison evidence
    private OracleVerdict oracleVerdict = OracleVerdict.NONE;
    private final List<String> verificationSteps = new ArrayList<>();
    /** Ordered, developer-replayable proof transactions (own → attack → control → public[/victim]) — the
     *  "reproduction bundle" a defender can re-run in Repeater / as curl / as HAR. Runtime-only; not persisted. */
    private final List<burp.report.ReproStep> reproSteps = new ArrayList<>();
    /** Candidate that is only worth reporting if the AI CONFIRMS it (e.g. a single-session IDOR with foreign
     *  owner tokens but no ownership ground truth). If the AI refutes / is unavailable / is undecided, the
     *  reporting layer suppresses it (suppress-unless-confirmed). Runtime-only; not persisted. */
    private boolean needsAiConfirmation = false;

    // ===== Retest state (on-demand "is it fixed yet?" re-check; session-scoped, not persisted) =====
    /** Outcome of the most recent retest of this finding. */
    public enum RetestStatus { NOT_TESTED, FIXED, STILL_VULNERABLE, INCONCLUSIVE }
    private RetestStatus retestStatus = RetestStatus.NOT_TESTED;
    private String retestDetail = "";   // short technical reason from the last retest
    private long retestAtMs = 0L;       // epoch ms of the last retest (0 = never)

    // NEW: Enhanced fields for professional reporting
    private double cvssScore;
    private String priority; // P1, P2, P3, P4, P5
    private List<String> references; // OWASP, NIST, CWE references
    private String cweId;
    private String owaspCategory;

    public Finding(String type, String severity, double confidence,
                   String description, String affectedUrl, String evidence,
                   String exploitation, String remediation) {
        this.type = normalizeType(type, description, evidence);
        this.severity = severity;
        this.confidence = confidence;
        this.description = description;
        this.affectedUrl = affectedUrl;
        this.evidence = evidence;
        this.exploitation = exploitation;
        this.remediation = remediation;
        this.isFalsePositive = false;
        this.references = new ArrayList<>();

        // Auto-calculate CVSS and priority based on severity and type
        calculateCVSSAndPriority();
        // Auto-assign references
        assignReferences();
    }

    // Constructor for backward compatibility
    public Finding(String type, String severity, double confidence,
                   String description, String evidence, String exploitation,
                   String remediation) {
        this(type, severity, confidence, description, "", evidence, exploitation, remediation);
    }

    /**
     * Calculate CVSS score and priority based on vulnerability type and severity
     */
    private void calculateCVSSAndPriority() {
        String lowerType = type.toLowerCase();

        // CVSS scoring based on vulnerability type
        if (lowerType.contains("rce") || lowerType.contains("remote code") ||
            lowerType.contains("command injection") || lowerType.contains("deserialization")) {
            this.cvssScore = 9.8;
            this.priority = "P1";
        } else if (lowerType.contains("sql injection") || lowerType.contains("sqli")) {
            this.cvssScore = 9.1;
            this.priority = "P1";
        } else if (lowerType.contains("authentication bypass") || lowerType.contains("auth bypass")) {
            this.cvssScore = 9.0;
            this.priority = "P1";
        } else if (lowerType.contains("cors") && lowerType.contains("wildcard")) {
            this.cvssScore = 7.5;
            this.priority = "P1";
        } else if (lowerType.contains("token") && lowerType.contains("url")) {
            this.cvssScore = 8.1;
            this.priority = "P1";
        } else if (lowerType.contains("ssrf")) {
            this.cvssScore = 8.6;
            this.priority = "P1";
        } else if (lowerType.contains("xxe") || lowerType.contains("xml external")) {
            this.cvssScore = 8.2;
            this.priority = "P1";
        } else if (lowerType.contains("xss") || lowerType.contains("cross-site scripting")) {
            this.cvssScore = 6.1;
            this.priority = "P2";
        } else if (lowerType.contains("idor") || lowerType.contains("insecure direct")) {
            this.cvssScore = 6.5;
            this.priority = "P2";
        } else if (lowerType.contains("information disclosure") || lowerType.contains("info disclosure")) {
            this.cvssScore = 5.3;
            this.priority = "P2";
        } else if (lowerType.contains("user enumeration") || lowerType.contains("username enumeration")) {
            this.cvssScore = 5.3;
            this.priority = "P2";
        } else if (lowerType.contains("jwt") || lowerType.contains("weak token")) {
            this.cvssScore = 4.3;
            this.priority = "P3";
        } else if (lowerType.contains("missing") && lowerType.contains("header")) {
            this.cvssScore = 4.0;
            this.priority = "P3";
        } else if (lowerType.contains("csrf")) {
            this.cvssScore = 4.3;
            this.priority = "P3";
        } else if (lowerType.contains("captcha") || lowerType.contains("rate limit")) {
            this.cvssScore = 3.7;
            this.priority = "P4";
        } else if (lowerType.contains("version disclosure") || lowerType.contains("server version")) {
            this.cvssScore = 3.5;
            this.priority = "P4";
        } else {
            // Default based on severity
            switch (severity.toLowerCase()) {
                case "critical":
                    this.cvssScore = 9.0;
                    this.priority = "P1";
                    break;
                case "high":
                    this.cvssScore = 7.5;
                    this.priority = "P1";
                    break;
                case "medium":
                    this.cvssScore = 5.0;
                    this.priority = "P2";
                    break;
                case "low":
                    this.cvssScore = 3.0;
                    this.priority = "P3";
                    break;
                default:
                    this.cvssScore = 2.0;
                    this.priority = "P4";
            }
        }
    }

    /**
     * True for finding types that are a systemic property of the whole host/app —
     * security headers, transport/HSTS, CORS, cookie flags, version/info disclosure,
     * or a token/credential carried in the URL — rather than a property of one
     * endpoint. Such findings are deduped ONCE PER HOST: the same issue on a
     * different path of the same domain is the same finding, but a different
     * sub-domain or domain is reported separately. Per-endpoint issues (injection,
     * IDOR, broken access control, ...) return false and are keyed per URL.
     *
     * <p>Shared by the run-level dedup ({@code ScanManager}) and the global Findings
     * panel so both agree on what "one per host" means.
     */
    public static boolean isHostScopedType(String type) {
        if (type == null) return false;
        String t = type.toLowerCase();
        // Sensitive material carried in the URL is an app-wide property, not one
        // path's (e.g. "Authentication Token in URL" fires on every socket.io poll).
        if (t.contains("url") && (t.contains("token") || t.contains("session")
                || t.contains("credential") || t.contains("password")
                || t.contains("api key") || t.contains("apikey")
                || t.contains("secret") || t.contains("sensitive") || t.contains("jwt"))) {
            return true;
        }
        return t.contains("header") || t.contains("csp") || t.contains("content-security")
                || t.contains("hsts") || t.contains("transport security") || t.contains("clickjack")
                || t.contains("version disclosure") || t.contains("technology")
                || t.contains("component disclosure") || t.contains("security misconfiguration")
                || t.contains("server version") || t.contains("x-frame") || t.contains("x-content-type")
                || t.contains("referrer-policy") || t.contains("permissions-policy")
                || t.contains("information disclosure") || t.contains("info disclosure")
                || t.contains("cors") || t.contains("cookie");
    }

    /** Query params that change every request (cache-busters, polling timestamps, socket.io t/sid) and
     *  must NOT make two otherwise-identical findings look distinct. */
    private static final java.util.Set<String> VOLATILE_PARAMS = new java.util.HashSet<>(java.util.Arrays.asList(
            "t", "_", "ts", "time", "timestamp", "sid", "cb", "cache", "cachebuster", "cache_buster",
            "nonce", "rand", "random", "_t", "__", "rnd", "ms", "now"));

    /**
     * URL with known volatile/cache-busting query params stripped, so the same logical endpoint
     * (e.g. {@code /socket.io/?EIO=4&transport=polling&t=Py0UkKZ}) keys identically across requests.
     * Keeps every other param so genuinely different endpoints stay distinct.
     */
    public static String normalizeUrlForDedup(String url) {
        if (url == null) return "";
        int q = url.indexOf('?');
        if (q < 0) return url;
        String base = url.substring(0, q);
        String query = url.substring(q + 1);
        StringBuilder kept = new StringBuilder();
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String name = (eq >= 0 ? pair.substring(0, eq) : pair).toLowerCase();
            if (VOLATILE_PARAMS.contains(name)) continue;
            if (kept.length() > 0) kept.append('&');
            kept.append(pair);
        }
        return kept.length() > 0 ? base + "?" + kept : base;
    }

    /**
     * Coarse, volatile-insensitive signature of finding evidence for host-scoped dedup: lower-cased,
     * with digit runs and long hex/token strings removed and whitespace collapsed, then truncated. The
     * same site-wide finding reported on many requests — where only a per-request id/token/timestamp in
     * the evidence differs — collapses to one, while genuinely different evidence stays distinct.
     */
    public static String evidenceSignature(String evidence) {
        if (evidence == null) return "";
        String s = evidence.toLowerCase();
        s = s.replaceAll("[0-9a-f]{8,}", "");   // hex ids / tokens
        s = s.replaceAll("[0-9]+", "");          // versions / timestamps / counts
        s = s.replaceAll("\\s+", " ").trim();
        return s.length() > 80 ? s.substring(0, 80) : s;
    }

    /**
     * Host (authority) of a URL, lower-cased; "" if null/unparseable. Different
     * sub-domains and domains yield different hosts, so host-keyed dedup still
     * reports the same issue separately per sub-domain and domain.
     */
    public static String hostOf(String url) {
        if (url == null || url.isEmpty()) return "";
        try {
            String h = new java.net.URI(url).getHost();
            if (h != null) return h.toLowerCase();
        } catch (Exception ignore) {
            // malformed URI (spaces, illegal chars) — fall back to the manual parse below
        }
        try {
            String s = url;
            int scheme = s.indexOf("://");
            if (scheme >= 0) s = s.substring(scheme + 3);
            int slash = s.indexOf('/');
            if (slash >= 0) s = s.substring(0, slash);
            int at = s.indexOf('@');
            if (at >= 0) s = s.substring(at + 1);
            int colon = s.indexOf(':');
            if (colon >= 0) s = s.substring(0, colon);
            return s.toLowerCase();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Assign OWASP, CWE, and NIST references based on vulnerability type
     */
    private void assignReferences() {
        String lowerType = type.toLowerCase();

        // SQL Injection
        if (lowerType.contains("sql injection") || lowerType.contains("sqli")) {
            this.cweId = "CWE-89";
            this.owaspCategory = "A03:2021 - Injection";
            this.references.add("https://owasp.org/Top10/A03_2021-Injection/");
            this.references.add("https://cwe.mitre.org/data/definitions/89.html");
            this.references.add("https://nvd.nist.gov/vuln/detail/cwe-89");
        }
        // XSS
        else if (lowerType.contains("xss") || lowerType.contains("cross-site scripting")) {
            this.cweId = "CWE-79";
            this.owaspCategory = "A03:2021 - Injection";
            this.references.add("https://owasp.org/Top10/A03_2021-Injection/");
            this.references.add("https://cwe.mitre.org/data/definitions/79.html");
            this.references.add("https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html");
        }
        // CORS
        else if (lowerType.contains("cors")) {
            this.cweId = "CWE-942";
            this.owaspCategory = "A05:2021 - Security Misconfiguration";
            this.references.add("https://owasp.org/Top10/A05_2021-Security_Misconfiguration/");
            this.references.add("https://cwe.mitre.org/data/definitions/942.html");
            this.references.add("https://portswigger.net/web-security/cors");
        }
        // Token in URL
        else if (lowerType.contains("token") && lowerType.contains("url")) {
            this.cweId = "CWE-598";
            this.owaspCategory = "A07:2021 - Identification and Authentication Failures";
            this.references.add("https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/");
            this.references.add("https://cwe.mitre.org/data/definitions/598.html");
            this.references.add("https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html");
        }
        // Information Disclosure
        else if (lowerType.contains("information disclosure") || lowerType.contains("info disclosure") ||
                 lowerType.contains("version disclosure")) {
            this.cweId = "CWE-200";
            this.owaspCategory = "A05:2021 - Security Misconfiguration";
            this.references.add("https://owasp.org/Top10/A05_2021-Security_Misconfiguration/");
            this.references.add("https://cwe.mitre.org/data/definitions/200.html");
        }
        // User Enumeration
        else if (lowerType.contains("user enumeration") || lowerType.contains("username enumeration")) {
            this.cweId = "CWE-204";
            this.owaspCategory = "A07:2021 - Identification and Authentication Failures";
            this.references.add("https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/");
            this.references.add("https://cwe.mitre.org/data/definitions/204.html");
        }
        // JWT Issues
        else if (lowerType.contains("jwt")) {
            this.cweId = "CWE-347";
            this.owaspCategory = "A02:2021 - Cryptographic Failures";
            this.references.add("https://owasp.org/Top10/A02_2021-Cryptographic_Failures/");
            this.references.add("https://cwe.mitre.org/data/definitions/347.html");
            this.references.add("https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html");
        }
        // Missing Security Headers
        else if (lowerType.contains("missing") && lowerType.contains("header")) {
            this.cweId = "CWE-693";
            this.owaspCategory = "A05:2021 - Security Misconfiguration";
            this.references.add("https://owasp.org/Top10/A05_2021-Security_Misconfiguration/");
            this.references.add("https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html");
            this.references.add("https://securityheaders.com/");
        }
        // CAPTCHA Issues
        else if (lowerType.contains("captcha")) {
            this.cweId = "CWE-804";
            this.owaspCategory = "A07:2021 - Identification and Authentication Failures";
            this.references.add("https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/");
            this.references.add("https://cwe.mitre.org/data/definitions/804.html");
        }
        // IDOR
        else if (lowerType.contains("idor") || lowerType.contains("insecure direct")) {
            this.cweId = "CWE-639";
            this.owaspCategory = "A01:2021 - Broken Access Control";
            this.references.add("https://owasp.org/Top10/A01_2021-Broken_Access_Control/");
            this.references.add("https://cwe.mitre.org/data/definitions/639.html");
            this.references.add("https://portswigger.net/web-security/access-control/idor");
        }
        // SSRF
        else if (lowerType.contains("ssrf")) {
            this.cweId = "CWE-918";
            this.owaspCategory = "A10:2021 - Server-Side Request Forgery (SSRF)";
            this.references.add("https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/");
            this.references.add("https://cwe.mitre.org/data/definitions/918.html");
            this.references.add("https://portswigger.net/web-security/ssrf");
        }
        // Command Injection
        else if (lowerType.contains("command injection") || lowerType.contains("os command")) {
            this.cweId = "CWE-78";
            this.owaspCategory = "A03:2021 - Injection";
            this.references.add("https://owasp.org/Top10/A03_2021-Injection/");
            this.references.add("https://cwe.mitre.org/data/definitions/78.html");
        }
        // CSRF
        else if (lowerType.contains("csrf")) {
            this.cweId = "CWE-352";
            this.owaspCategory = "A01:2021 - Broken Access Control";
            this.references.add("https://owasp.org/Top10/A01_2021-Broken_Access_Control/");
            this.references.add("https://cwe.mitre.org/data/definitions/352.html");
            this.references.add("https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html");
        }
        // Default references
        else {
            this.cweId = "";
            this.owaspCategory = "A05:2021 - Security Misconfiguration";
            this.references.add("https://owasp.org/Top10/");
        }
    }
    
    /**
     * Convert to JSON
     */
    public JSONObject toJSON() {
        JSONObject json = new JSONObject();
        json.put("type", type);
        json.put("severity", severity);
        json.put("confidence", confidence);
        json.put("description", description);
        json.put("evidence", evidence);
        json.put("exploitation", exploitation);
        json.put("remediation", remediation);
        json.put("isFalsePositive", isFalsePositive);
        json.put("affectedUrl", affectedUrl != null ? affectedUrl : "");

        // NEW: Enhanced fields
        json.put("cvssScore", cvssScore);
        json.put("cvssVector", getCvssVector());
        json.put("priority", priority);
        json.put("cweId", cweId != null ? cweId : "");
        json.put("owaspCategory", owaspCategory != null ? owaspCategory : "");
        json.put("owaspApiCategory", getOwaspApiCategory());
        String wstg = getWstgId();
        if (!wstg.isEmpty()) json.put("wstg", wstg);

        if (references != null && !references.isEmpty()) {
            JSONArray refsArray = new JSONArray();
            for (String ref : references) {
                refsArray.put(ref);
            }
            json.put("references", refsArray);
        }

        return json;
    }
    
    /**
     * Create from JSON
     */
    public static Finding fromJSON(JSONObject json) {
        Finding finding = new Finding(
            json.getString("type"),
            json.getString("severity"),
            json.getDouble("confidence"),
            json.optString("description", ""),
            json.optString("evidence", ""),
            json.optString("exploitation", ""),
            json.optString("remediation", "")
        );
        finding.setFalsePositive(json.optBoolean("isFalsePositive", false));
        return finding;
    }
    
    // Getters and Setters
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    // ===== Effective (reported) severity — never exceeds what confidence/evidence prove =====
    // Faz 0: false-positive -> Info; confidence<0.50 -> Low; <0.70 -> Medium.
    // (Faz 1 extends getEffectiveSeverity(): high severity without deterministic evidence is also capped.)
    private static int severityRank(String s) {
        if (s == null) return 0;
        switch (s.trim().toLowerCase()) {
            case "critical": return 4;
            case "high":     return 3;
            case "medium":   return 2;
            case "low":      return 1;
            default:         return 0; // info / unknown
        }
    }

    private static String severityName(int rank) {
        switch (rank) {
            case 4:  return "Critical";
            case 3:  return "High";
            case 2:  return "Medium";
            case 1:  return "Low";
            default: return "Info";
        }
    }

    /** Severity actually shown in Burp issues, the Findings panel and reports — capped by confidence/FP. */
    public String getEffectiveSeverity() {
        int claim = severityRank(severity);
        int cap = claim;
        if (isFalsePositive)        cap = 0;                 // suppressed claim reads as Info
        else if (confidence < 0.50) cap = Math.min(cap, 1); // Low
        else if (confidence < 0.70) cap = Math.min(cap, 2); // Medium
        // Faz 1 iron rule: a refuted claim reads as Info; a high claim explicitly judged inconclusive
        // with no deterministic evidence cannot stand as Critical/High.
        if (oracleVerdict == OracleVerdict.REFUTED) cap = 0;
        else if (oracleVerdict == OracleVerdict.INCONCLUSIVE && cap > 2 && !hasDeterministicEvidence()) cap = 2;
        return severityName(Math.min(claim, cap));
    }

    /** CVSS capped to the effective-severity ceiling (a downgraded finding can't keep a 9.x score). */
    public double getEffectiveCvss() {
        double ceiling;
        switch (severityRank(getEffectiveSeverity())) {
            case 4:  ceiling = 9.0; break;
            case 3:  ceiling = 7.5; break;
            case 2:  ceiling = 5.0; break;
            case 1:  ceiling = 3.0; break;
            default: ceiling = 2.0;
        }
        return Math.min(cvssScore, ceiling);
    }

    /** Priority aligned to the effective severity, so a downgraded High→Medium can't keep a P1. */
    public String getEffectivePriority() {
        int eff = severityRank(getEffectiveSeverity());
        if (eff >= severityRank(severity)) return priority; // not downgraded -> keep type-based priority
        switch (eff) {
            case 4: case 3: return "P1";
            case 2:         return "P2";
            case 1:         return "P3";
            default:        return "P4";
        }
    }

    // ===== Faz 1: evidence accessors + gate + confidence tier =====
    public String getBaselineResponse() { return baselineResponse; }
    public void setBaselineResponse(String s) { this.baselineResponse = s; }

    public OracleVerdict getOracleVerdict() { return oracleVerdict; }
    public void setOracleVerdict(OracleVerdict v) { this.oracleVerdict = (v == null ? OracleVerdict.NONE : v); }

    public boolean needsAiConfirmation() { return needsAiConfirmation; }
    public void setNeedsAiConfirmation(boolean b) { this.needsAiConfirmation = b; }

    public List<String> getVerificationSteps() { return verificationSteps; }
    public void addVerificationStep(String s) {
        if (s != null && !s.trim().isEmpty() && !verificationSteps.contains(s.trim())) verificationSteps.add(s.trim());
    }

    // ===== Reproduction bundle (ordered proof transactions; exportable as Repeater/curl/HAR) =====
    public List<burp.report.ReproStep> getReproSteps() { return reproSteps; }
    public void addReproStep(burp.report.ReproStep s) { if (s != null) reproSteps.add(s); }
    /** True when this finding carries a replayable proof trail (at least the attack step). */
    public boolean hasReproBundle() { return !reproSteps.isEmpty(); }

    /** Iron rule: a reported high-severity finding must carry a deterministic comparison/oracle result. */
    public boolean hasDeterministicEvidence() {
        if (oracleVerdict == OracleVerdict.CONFIRMED) return true;
        return httpResponse != null && !httpResponse.isEmpty()
            && controlResponse != null && !controlResponse.isEmpty();
    }

    /** Symbolic confidence tier (CONFIRMED/FIRM/TENTATIVE) from numeric confidence + oracle verdict. */
    public ConfidenceTier getConfidenceTier() {
        if (oracleVerdict == OracleVerdict.CONFIRMED || confidence >= 0.9) return ConfidenceTier.CONFIRMED;
        if (confidence >= 0.7) return ConfidenceTier.FIRM;
        return ConfidenceTier.TENTATIVE;
    }
    
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }
    
    public String getExploitation() { return exploitation; }
    public void setExploitation(String exploitation) { this.exploitation = exploitation; }
    
    public String getRemediation() { return remediation; }
    public void setRemediation(String remediation) { this.remediation = remediation; }

    public String getAffectedUrl() { return affectedUrl; }
    public void setAffectedUrl(String affectedUrl) { this.affectedUrl = affectedUrl; }

    public boolean isFalsePositive() { return isFalsePositive; }
    public void setFalsePositive(boolean falsePositive) { isFalsePositive = falsePositive; }

    public String getHttpRequest() { return httpRequest; }
    public void setHttpRequest(String httpRequest) { this.httpRequest = httpRequest; }

    public String getHttpResponse() { return httpResponse; }
    public void setHttpResponse(String httpResponse) { this.httpResponse = httpResponse; }

    public String getControlResponse() { return controlResponse; }
    public void setControlResponse(String controlResponse) { this.controlResponse = controlResponse; }

    public int getDbId() { return dbId; }
    public void setDbId(int dbId) { this.dbId = dbId; }

    public RetestStatus getRetestStatus() { return retestStatus; }
    public void setRetestStatus(RetestStatus s) { this.retestStatus = (s == null ? RetestStatus.NOT_TESTED : s); }
    public String getRetestDetail() { return retestDetail == null ? "" : retestDetail; }
    public void setRetestDetail(String d) { this.retestDetail = (d == null ? "" : d); }
    public long getRetestAtMs() { return retestAtMs; }
    public void setRetestAtMs(long ms) { this.retestAtMs = ms; }

    // Alias methods for compatibility
    public String getVulnType() { return type; }
    public String getUrl() { return affectedUrl; }

    // NEW: Enhanced getters and setters
    public double getCvssScore() { return cvssScore; }
    public void setCvssScore(double cvssScore) { this.cvssScore = cvssScore; }

    public String getPriority() { return priority; }
    public void setPriority(String priority) { this.priority = priority; }

    public List<String> getReferences() { return references != null ? references : new ArrayList<>(); }
    public void setReferences(List<String> references) { this.references = references; }
    public void addReference(String reference) {
        if (this.references == null) this.references = new ArrayList<>();
        this.references.add(reference);
    }

    public String getCweId() { return cweId != null ? cweId : ""; }
    public void setCweId(String cweId) { this.cweId = cweId; }

    public String getOwaspCategory() { return owaspCategory != null ? owaspCategory : ""; }
    public void setOwaspCategory(String owaspCategory) { this.owaspCategory = owaspCategory; }

    // ===== Industry-standard tags (deterministically derived from the finding class) =====
    /** CVSS 3.1 base vector for this finding's class (the numeric score is {@link #getCvssScore()}). */
    public String getCvssVector() { return burp.report.Standards.cvssVector(this); }
    /** OWASP API Security Top-10 (2023) category, or "" when the class is not API-access-shaped. */
    public String getOwaspApiCategory() { return burp.report.Standards.owaspApi(this); }
    /** OWASP WSTG test id, or "" when the class has no confident mapping. */
    public String getWstgId() { return burp.report.Standards.wstg(this); }

    /**
     * Get formatted references as string
     */
    public String getReferencesFormatted() {
        if (references == null || references.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (String ref : references) {
            sb.append("• ").append(ref).append("\n");
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return type + " (" + severity + ", CVSS: " + cvssScore + ", " + priority + ")";
    }

    /**
     * Normalize a raw vulnerability type string into a human-readable, specific name.
     * Moved here from ResponseAnalyzer so every scan engine benefits automatically.
     */
    public static String normalizeType(String type, String description, String evidence) {
        if (type == null || type.isEmpty()) return type;
        String lowerType = type.toLowerCase();
        String lowerDesc = description != null ? description.toLowerCase() : "";
        String lowerEvidence = evidence != null ? evidence.toLowerCase() : "";

        if (lowerType.contains("csp") || lowerDesc.contains("content-security-policy") ||
                lowerDesc.contains("content security policy") || lowerEvidence.contains("content-security-policy"))
            return "Missing or Weak Content-Security-Policy (CSP) Header";
        if (lowerType.contains("frame") || lowerType.contains("clickjack") ||
                lowerDesc.contains("x-frame-options") || lowerEvidence.contains("x-frame-options"))
            return "Missing X-Frame-Options Header (Clickjacking Risk)";
        if (lowerType.contains("hsts") || lowerDesc.contains("strict-transport-security") ||
                lowerEvidence.contains("strict-transport-security"))
            return "Missing HTTP Strict-Transport-Security (HSTS) Header";
        if ((lowerType.contains("content-type") && lowerType.contains("nosniff")) ||
                lowerDesc.contains("x-content-type-options") || lowerEvidence.contains("x-content-type-options"))
            return "Missing X-Content-Type-Options Header";
        if (lowerType.contains("referrer") || lowerDesc.contains("referrer-policy") ||
                lowerEvidence.contains("referrer-policy"))
            return "Missing or Weak Referrer-Policy Header";
        if (lowerType.contains("permissions-policy") || lowerType.contains("feature-policy") ||
                lowerDesc.contains("permissions-policy") || lowerDesc.contains("feature-policy"))
            return "Missing Permissions-Policy Header";
        if (lowerType.contains("security header") || lowerType.contains("missing header")) {
            if (lowerDesc.contains("csp") || lowerEvidence.contains("csp"))
                return "Missing or Weak Content-Security-Policy (CSP) Header";
            if (lowerDesc.contains("hsts")) return "Missing HTTP Strict-Transport-Security (HSTS) Header";
            if (lowerDesc.contains("frame")) return "Missing X-Frame-Options Header (Clickjacking Risk)";
            return "Missing Security Headers";
        }
        if (lowerType.contains("xss")) {
            if (lowerDesc.contains("reflected")) return "Reflected Cross-Site Scripting (XSS)";
            if (lowerDesc.contains("stored") || lowerDesc.contains("persistent")) return "Stored Cross-Site Scripting (XSS)";
            if (lowerDesc.contains("dom")) return "DOM-Based Cross-Site Scripting (XSS)";
            return "Cross-Site Scripting (XSS)";
        }
        if (lowerType.contains("sql")) {
            if (lowerDesc.contains("blind")) return "Blind SQL Injection";
            if (lowerDesc.contains("time") || lowerDesc.contains("delay")) return "Time-Based SQL Injection";
            if (lowerDesc.contains("boolean")) return "Boolean-Based SQL Injection";
            if (lowerDesc.contains("union")) return "UNION-Based SQL Injection";
            return "SQL Injection";
        }
        return type;
    }
}

package burp;

import burp.i18n.I18n;
import java.util.*;

/**
 * Prompt Builder - Constructs optimized prompts for Qwen AI
 * 
 * @author Zahid Eroglu
 */
public class PromptBuilder {
    
    private static final String SYSTEM_PROMPT =
        "You are a WORLD-CLASS penetration testing expert and security researcher. " +
        "Your analysis must be EXHAUSTIVE, PRECISE, and ACTIONABLE.\n\n" +

        "═══════════════════════════════════════════════════════════\n" +
        "PROVE-IT DISCIPLINE (overrides everything below):\n" +
        "═══════════════════════════════════════════════════════════\n" +
        "• Report a finding ONLY if the request/response at hand contains DIRECT evidence of it.\n" +
        "• Never assert a vulnerability you cannot point to a concrete snippet for.\n" +
        "• If something is plausible but NOT proven by the evidence: set confidence < 0.5, set severity\n" +
        "  no higher than \"Low\", and put the concrete next test in next_verification_steps.\n" +
        "• Severity follows PROVEN impact, not category. A missing header is Low/Info, not High.\n" +
        "• Confidence calibration: CONFIRMED(>=0.9) only with a deterministic signal (error string present,\n" +
        "  payload reflected unencoded, foreign-owner data returned); FIRM(0.7-0.9) strong-indirect;\n" +
        "  TENTATIVE(<0.7) speculative. Fewer PROVEN findings beat many speculative ones.\n\n" +

        "═══════════════════════════════════════════════════════════\n" +
        "MANDATORY ANALYSIS CHECKLIST - CHECK EVERY SINGLE ITEM:\n" +
        "═══════════════════════════════════════════════════════════\n\n" +

        "🚨 CRITICAL SECURITY ISSUES (CHECK FIRST!):\n\n" +

        "1. WILDCARD CORS (High - CVSS 7.5, P1):\n" +
        "   ✓ Look for: Access-Control-Allow-Origin: *\n" +
        "   ✓ Look for: Access-Control-Allow-Credentials: true with wildcard origin\n" +
        "   ✓ Overly permissive CORS policies\n" +
        "   Evidence: Copy the EXACT CORS headers from response\n\n" +

        "2. TOKEN/SESSION IN URL (High - CVSS 8.1, P1):\n" +
        "   ✓ Look for tokens/keys in URL query parameters: ?token=, ?api_key=, ?auth=, ?session=\n" +
        "   ✓ JWT tokens in URL\n" +
        "   ✓ Bearer tokens in URL\n" +
        "   ✓ Any sensitive data in URL parameters\n" +
        "   Evidence: Show the exact parameter and partial token value\n\n" +

        "📋 SECURITY HEADERS (ALWAYS CHECK - HIGH PRIORITY):\n" +
        "   ✓ Strict-Transport-Security (HSTS) - Missing = Low\n" +
        "   ✓ X-Frame-Options - Missing = Low (Clickjacking risk)\n" +
        "   ✓ Content-Security-Policy (CSP) - Missing/Weak = Low/Medium (judge by actual impact)\n" +
        "   ✓ X-Content-Type-Options - Missing = Low\n" +
        "   ✓ Referrer-Policy - Missing/Weak = Info/Low\n" +
        "   ✓ Permissions-Policy - Missing = Info\n" +
        "   IMPORTANT: List ALL present headers AND identify which are MISSING!\n\n" +

        "🔍 INFORMATION DISCLOSURE (Medium - CVSS 5.3, P2):\n" +
        "   ✓ Server header with version (nginx/1.25.4, Apache/2.4.41) = Report it!\n" +
        "   ✓ X-Powered-By header (PHP version, ASP.NET version)\n" +
        "   ✓ Stack traces in response body\n" +
        "   ✓ Debug information\n" +
        "   ✓ Internal IP addresses (10.x.x.x, 192.168.x.x, 172.16-31.x.x)\n" +
        "   ✓ Internal paths (/var/www/, C:\\Users\\, /home/)\n" +
        "   ✓ Database error messages\n" +
        "   ✓ Technology stack disclosure\n\n" +

        "👤 USER ENUMERATION (Medium - CVSS 5.3, P2):\n" +
        "   ✓ Different error messages for existing vs non-existing users\n" +
        "   ✓ 'User not found' vs 'Invalid password' messages\n" +
        "   ✓ Response time differences\n" +
        "   ✓ User IDs in responses\n" +
        "   ✓ Username hints in password reset\n\n" +

        "🔐 JWT/TOKEN ISSUES (Medium - CVSS 4.3, P3):\n" +
        "   ✓ Weak JWT configuration (alg: none, HS256 with weak secret)\n" +
        "   ✓ No expiration on tokens\n" +
        "   ✓ Sensitive data in JWT payload (unencrypted)\n" +
        "   ✓ JWT without signature verification\n" +
        "   ✓ Predictable token patterns\n\n" +

        "🤖 CAPTCHA/RATE LIMITING (Low - CVSS 3.7, P4):\n" +
        "   ✓ CAPTCHA keys exposed in response\n" +
        "   ✓ Missing rate limiting\n" +
        "   ✓ Weak CAPTCHA implementation\n" +
        "   ✓ Bypassable verification\n\n" +

        "🔒 AUTHENTICATION & SESSION:\n" +
        "   ✓ Session cookies without HttpOnly flag\n" +
        "   ✓ Session cookies without Secure flag\n" +
        "   ✓ Missing SameSite attribute\n" +
        "   ✓ Weak session ID entropy\n" +
        "   ✓ Session fixation indicators\n\n" +

        "═══════════════════════════════════════════════════════════\n" +
        "OUTPUT FORMAT - MUST FOLLOW EXACTLY:\n" +
        "═══════════════════════════════════════════════════════════\n" +
        "Return ONLY valid JSON - NO markdown, NO code blocks, NO explanation\n\n" +

        "{\n" +
        "  \"is_vulnerable\": true,\n" +
        "  \"vulnerabilities\": [\n" +
        "    {\n" +
        "      \"type\": \"Exact vulnerability name\",\n" +
        "      \"severity\": \"Critical|High|Medium|Low|Info\",\n" +
        "      \"confidence\": 0.95,\n" +
        "      \"description\": \"Detailed technical description of the vulnerability. Include what it is, why it's dangerous, and the specific context found.\",\n" +
        "      \"evidence\": \"COPY THE EXACT TEXT from response that proves this vulnerability exists\",\n" +
        "      \"exploitation\": \"Step-by-step exploitation scenario with specific commands or techniques\",\n" +
        "      \"remediation\": \"Specific fix with code examples, configuration changes, or commands\",\n" +
        "      \"next_verification_steps\": [\"Concrete next test(s) to confirm — REQUIRED when confidence < 0.7\"]\n" +
        "    }\n" +
        "  ],\n" +
        "  \"summary\": \"Overall security assessment with risk level\"\n" +
        "}\n\n" +

        "═══════════════════════════════════════════════════════════\n" +
        "EXAMPLES OF CORRECT FINDINGS:\n" +
        "═══════════════════════════════════════════════════════════\n\n" +

        "EXAMPLE 1 - Wildcard CORS:\n" +
        "{\n" +
        "  \"type\": \"Wildcard CORS Configuration\",\n" +
        "  \"severity\": \"High\",\n" +
        "  \"confidence\": 0.98,\n" +
        "  \"description\": \"The server returns Access-Control-Allow-Origin: * which allows any website to make cross-origin requests. Combined with sensitive data in responses, this can lead to data theft.\",\n" +
        "  \"evidence\": \"Access-Control-Allow-Origin: *\\nAccess-Control-Allow-Methods: GET, POST, PUT\",\n" +
        "  \"exploitation\": \"1. Create malicious website\\n2. Use fetch() to request sensitive endpoints\\n3. Exfiltrate user data due to permissive CORS\",\n" +
        "  \"remediation\": \"Replace wildcard with specific allowed origins. Example: Access-Control-Allow-Origin: https://trusted-domain.com\"\n" +
        "}\n\n" +

        "EXAMPLE 2 - Token in URL:\n" +
        "{\n" +
        "  \"type\": \"Authentication Token in URL\",\n" +
        "  \"severity\": \"High\",\n" +
        "  \"confidence\": 0.98,\n" +
        "  \"description\": \"Authentication token is transmitted via URL query parameter. This exposes the token in browser history, server logs, referrer headers, and proxy logs, enabling session hijacking.\",\n" +
        "  \"evidence\": \"?token=eyJhbGciOiJIUzI1NiIs... (JWT token in URL parameter)\",\n" +
        "  \"exploitation\": \"1. Token is logged in web server access logs\\n2. Token leaks via Referer header to third-party sites\\n3. Token visible in browser history\\n4. Attacker can hijack session with stolen token\",\n" +
        "  \"remediation\": \"1. Send tokens in Authorization header instead\\n2. Use HttpOnly cookies for session management\\n3. Implement token rotation\\n4. Add short expiration times\"\n" +
        "}\n\n" +

        "EXAMPLE 3 - Missing HSTS:\n" +
        "{\n" +
        "  \"type\": \"Missing HTTP Strict-Transport-Security (HSTS) Header\",\n" +
        "  \"severity\": \"Low\",\n" +
        "  \"confidence\": 0.95,\n" +
        "  \"description\": \"The response does not include Strict-Transport-Security header. This allows man-in-the-middle attacks through SSL stripping, where attacker can downgrade HTTPS to HTTP.\",\n" +
        "  \"evidence\": \"Response headers present: Server, Content-Type, Date. HSTS header is ABSENT.\",\n" +
        "  \"exploitation\": \"1. Attacker performs MITM attack on network\\n2. Intercepts initial HTTP request\\n3. Strips HTTPS and serves HTTP version\\n4. Captures credentials and sensitive data\",\n" +
        "  \"remediation\": \"Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\"\n" +
        "}\n\n" +

        "EXAMPLE 4 - Server Version Disclosure:\n" +
        "{\n" +
        "  \"type\": \"Server Version Information Disclosure\",\n" +
        "  \"severity\": \"Low\",\n" +
        "  \"confidence\": 0.98,\n" +
        "  \"description\": \"The server reveals its exact version in the Server header. Attackers can search for known CVEs and exploits specific to this version.\",\n" +
        "  \"evidence\": \"Server: nginx/1.25.4\",\n" +
        "  \"exploitation\": \"1. Search CVE databases for nginx 1.25.4 vulnerabilities\\n2. Use specific exploits for this version\\n3. Target known weaknesses\",\n" +
        "  \"remediation\": \"Hide version: Add 'server_tokens off;' to nginx.conf. For Apache: ServerTokens Prod and ServerSignature Off\"\n" +
        "}\n\n" +

        "REMEMBER:\n" +
        "1. Check the categories, but report ONLY what the evidence proves.\n" +
        "2. Every finding MUST cite a concrete snippet from the response as evidence.\n" +
        "3. Include SPECIFIC remediation for each finding.\n" +
        "4. Calibrate confidence to evidence; speculative -> confidence < 0.5 + severity <= Low + next_verification_steps.\n" +
        "5. Severity follows PROVEN impact. Fewer correct findings beat many inflated ones.";

    /**
     * System prompt + a runtime OUTPUT-LANGUAGE directive so AI findings follow the UI language
     * (Turkish by default). The reasoning instructions stay in English on purpose — only the
     * human-readable result fields are localised; "type"/"severity" stay canonical English.
     */
    private static String systemPrompt() {
        String lang = I18n.isTr()
            ? "Write the human-readable result fields — \"description\", \"evidence\", \"exploitation\", " +
              "\"remediation\", \"summary\" and \"next_verification_steps\" — in TURKISH (professional, " +
              "technical Turkish). Keep all JSON keys in English; keep the \"type\" value a canonical ENGLISH " +
              "vulnerability name (e.g. \"SQL Injection\", \"CORS Misconfiguration\"); keep \"severity\" as the " +
              "English enum (Critical|High|Medium|Low|Info). Preserve technical tokens verbatim (HTTP, header " +
              "names, payloads, URLs, code, numbers)."
            : "Write all human-readable result fields in clear, professional ENGLISH.";
        return SYSTEM_PROMPT +
            "\n\n═══════════════════════════════════════════════════════════\n" +
            "OUTPUT LANGUAGE:\n" +
            "═══════════════════════════════════════════════════════════\n" + lang;
    }

    /**
     * Prompt templates
     */
    public enum Template {
        QUICK_SCAN("Comprehensive Security Scan",
            "Perform a THOROUGH security analysis checking ALL of the following:\n\n" +
            "1. SECURITY HEADERS (CHECK EVERY ONE):\n" +
            "   - Content-Security-Policy (CSP)\n" +
            "   - X-Frame-Options\n" +
            "   - Strict-Transport-Security (HSTS)\n" +
            "   - X-Content-Type-Options\n" +
            "   - X-XSS-Protection\n" +
            "   - Referrer-Policy\n" +
            "   - Permissions-Policy\n\n" +
            "2. VERSION DISCLOSURE:\n" +
            "   - Server header (nginx, Apache, IIS versions)\n" +
            "   - X-Powered-By (PHP, ASP.NET versions)\n" +
            "   - X-AspNet-Version\n" +
            "   - Any technology stack information\n" +
            "   - FLAG OLD VERSIONS as HIGH severity (PHP <7.4, nginx <1.20)\n\n" +
            "3. INJECTION VULNERABILITIES (only with evidence):\n" +
            "   - Command Injection (shell errors)\n" +
            "   - LDAP/XML/NoSQL Injection\n" +
            "   - Template Injection\n\n" +
            "4. INFORMATION DISCLOSURE:\n" +
            "   - Directory listings\n" +
            "   - Source code exposure\n" +
            "   - Internal paths\n" +
            "   - Database errors\n" +
            "   - Stack traces\n" +
            "   - API keys, tokens\n\n" +
            "5. OTHER VULNERABILITIES:\n" +
            "   - SSRF (with evidence)\n" +
            "   - IDOR\n" +
            "   - Authentication issues\n" +
            "   - Session management flaws\n" +
            "   - CORS misconfigurations\n\n" +
            "IMPORTANT: Report ALL findings with concrete evidence. " +
            "Priority: Headers and version disclosure (easy to confirm, always accurate)."),

        AUTH_CHECK("Authentication Analysis",
            "Analyze authentication and authorization:\n" +
            "1. Authentication bypass techniques\n" +
            "2. Session management issues\n" +
            "3. Password reset flaws\n" +
            "4. JWT vulnerabilities\n" +
            "5. OAuth flow issues\n" +
            "6. Weak credentials\n" +
            "7. Missing authentication"),
        
        API_SECURITY("API Security Test",
            "API security assessment:\n" +
            "1. Excessive data exposure\n" +
            "2. Rate limiting issues\n" +
            "3. Broken authentication\n" +
            "4. Security misconfiguration\n" +
            "5. Mass assignment\n" +
            "6. Improper assets management\n" +
            "7. Injection flaws"),
        
        BUSINESS_LOGIC("Business Logic Flaws",
            "Identify business logic vulnerabilities:\n" +
            "1. Price manipulation\n" +
            "2. Quantity bypass\n" +
            "3. Workflow violations\n" +
            "4. Privilege escalation\n" +
            "5. Race conditions\n" +
            "6. Parameter tampering"),
        
        IDOR_ACCESS("IDOR & Access Control",
            "Check for Insecure Direct Object References:\n" +
            "1. Horizontal privilege escalation\n" +
            "2. Vertical privilege escalation\n" +
            "3. Forced browsing\n" +
            "4. Missing function level access control\n" +
            "5. Predictable resource IDs\n" +
            "6. Account-ownership validation (Hesap Aitlik Kontrolü) — for EVERY client-supplied\n" +
            "   account/customer identifier (CustomerId, AccountNumber, SenderAccountNumber,\n" +
            "   ReceiverAccountNumber, AccountSuffix, SenderAccountSuffix, Iban, SenderIban,\n" +
            "   ReceiverIban, PersonId), swap it to another owner's value with your own session and\n" +
            "   flag if the backend serves/acts on it without an ownership (IsOwnAccount) check. Skip none."),
        
        ALL_INJECTION("All Injection Types",
            "Comprehensive injection testing:\n" +
            "1. SQL Injection\n" +
            "2. NoSQL Injection\n" +
            "3. LDAP Injection\n" +
            "4. XPath Injection\n" +
            "5. OS Command Injection\n" +
            "6. XML Injection\n" +
            "7. SSI Injection\n" +
            "8. Template Injection"),
        
        DATA_LEAK("Sensitive Data Leak",
            "Find sensitive data leakage:\n" +
            "1. Credentials in responses\n" +
            "2. API keys exposure\n" +
            "3. Session tokens\n" +
            "4. PII (Personal Identifiable Information)\n" +
            "5. Internal paths\n" +
            "6. Stack traces\n" +
            "7. Version disclosure\n" +
            "8. Database errors"),
        
        HEADER_SSL("Header & SSL Check",
            "Security headers and SSL/TLS analysis:\n" +
            "1. Missing security headers (CSP, HSTS, X-Frame-Options)\n" +
            "2. Insecure cookie flags\n" +
            "3. CORS misconfiguration\n" +
            "4. Server version disclosure\n" +
            "5. Weak cipher suites\n" +
            "6. SSL certificate issues"),

        SSRF_FINDER("SSRF Detection",
            "Server-Side Request Forgery analysis:\n" +
            "1. Internal network access\n" +
            "2. Cloud metadata endpoints\n" +
            "3. URL parameter manipulation\n" +
            "4. DNS rebinding\n" +
            "5. Blind SSRF indicators\n" +
            "6. Protocol smuggling"),

        FILE_UPLOAD("File Upload Vulnerabilities",
            "File upload security testing:\n" +
            "1. Unrestricted file upload\n" +
            "2. File type bypass\n" +
            "3. Path traversal in filenames\n" +
            "4. XXE via file upload\n" +
            "5. Malicious file execution\n" +
            "6. File size limits\n" +
            "7. Metadata exploitation"),

        CSRF_TEST("CSRF Analysis",
            "Cross-Site Request Forgery testing:\n" +
            "1. Missing CSRF tokens\n" +
            "2. Weak token generation\n" +
            "3. Token reuse\n" +
            "4. GET-based state changes\n" +
            "5. JSON CSRF\n" +
            "6. SameSite cookie bypass"),

        XXE_DETECTION("XXE (XML External Entity)",
            "XML External Entity vulnerability testing:\n" +
            "1. Classic XXE\n" +
            "2. Blind XXE\n" +
            "3. XXE via file upload\n" +
            "4. SSRF via XXE\n" +
            "5. Denial of Service\n" +
            "6. Parameter entities"),

        DESERIALIZATION("Deserialization Flaws",
            "Insecure deserialization testing:\n" +
            "1. Java deserialization\n" +
            "2. PHP object injection\n" +
            "3. Python pickle\n" +
            "4. .NET deserialization\n" +
            "5. Magic bytes detection\n" +
            "6. Gadget chain indicators"),

        RATE_LIMIT("Rate Limiting & DoS",
            "Rate limiting and abuse testing:\n" +
            "1. Missing rate limits\n" +
            "2. Brute force protection\n" +
            "3. Account enumeration\n" +
            "4. Resource exhaustion\n" +
            "5. Excessive data retrieval\n" +
            "6. Email/SMS bombing"),

        WEBSOCKET_SEC("WebSocket Security",
            "WebSocket vulnerability testing:\n" +
            "1. Missing origin validation\n" +
            "2. CSRF in WebSocket\n" +
            "3. Message injection\n" +
            "4. Insecure upgrades\n" +
            "5. Protocol confusion\n" +
            "6. Token exposure"),

        MOBILE_API("Mobile API Testing",
            "Mobile application API security:\n" +
            "1. Hardcoded secrets\n" +
            "2. Certificate pinning bypass\n" +
            "3. Deep link vulnerabilities\n" +
            "4. Insecure data storage\n" +
            "5. Weak encryption\n" +
            "6. API key exposure"),

        CRYPTO_WEAK("Cryptographic Weaknesses",
            "Cryptography vulnerability analysis:\n" +
            "1. Weak hashing algorithms (MD5, SHA1)\n" +
            "2. ECB mode usage\n" +
            "3. Hardcoded keys/IVs\n" +
            "4. Padding oracle\n" +
            "5. Weak random generation\n" +
            "6. Key reuse"),

        REGEX_DOS("ReDoS (Regex DoS)",
            "Regular Expression Denial of Service:\n" +
            "1. Evil regex patterns\n" +
            "2. Catastrophic backtracking\n" +
            "3. Input validation bypass\n" +
            "4. Performance degradation\n" +
            "5. Nested quantifiers");

        private final String name;
        private final String description;
        
        Template(String name, String description) {
            this.name = name;
            this.description = description;
        }
        
        public String getName() { return name; }
        public String getDescription() { return description; }
    }
    
    /**
     * Build conversation prompt with context
     */
    public static List<QwenAPIClient.Message> buildConversationPrompt(
            List<Conversation> history,
            String userPrompt,
            String httpRequest,
            String httpResponse) {
        
        List<QwenAPIClient.Message> messages = new ArrayList<>();
        
        // System prompt
        messages.add(new QwenAPIClient.Message("system", systemPrompt()));
        
        // Add conversation history (last 5 messages)
        int startIdx = Math.max(0, history.size() - 5);
        for (int i = startIdx; i < history.size(); i++) {
            Conversation conv = history.get(i);
            String role = conv.getSender().equals("user") ? "user" : "assistant";
            messages.add(new QwenAPIClient.Message(role, conv.getMessage()));
        }
        
        // Add current request with prompt
        String userMessage = userPrompt + "\n\nHTTP Request:\n" + 
                           truncate(httpRequest, 3000) + 
                           "\n\nHTTP Response:\n" + 
                           truncate(httpResponse, 3000);
        
        messages.add(new QwenAPIClient.Message("user", userMessage));
        
        return messages;
    }
    
    /**
     * Build prompt from template
     */
    public static List<QwenAPIClient.Message> buildTemplatePrompt(
            Template template,
            String httpRequest,
            String httpResponse) {
        
        List<QwenAPIClient.Message> messages = new ArrayList<>();

        messages.add(new QwenAPIClient.Message("system", systemPrompt()));

        String userMessage = template.getDescription() +
                           "\n\nHTTP Request:\n" + 
                           truncate(httpRequest, 3000) + 
                           "\n\nHTTP Response:\n" + 
                           truncate(httpResponse, 3000);
        
        messages.add(new QwenAPIClient.Message("user", userMessage));
        
        return messages;
    }
    
    /**
     * Build simple scan prompt
     */
    public static List<QwenAPIClient.Message> buildSimplePrompt(
            String httpRequest,
            String httpResponse) {
        
        return buildTemplatePrompt(Template.QUICK_SCAN, httpRequest, httpResponse);
    }
    
    /**
     * Truncate string to max length
     */
    private static String truncate(String str, int maxLength) {
        if (str == null) return "";
        if (str.length() <= maxLength) return str;
        return str.substring(0, maxLength) + "\n... (truncated)";
    }
    
    /**
     * Get all template names
     */
    public static List<String> getTemplateNames() {
        List<String> names = new ArrayList<>();
        for (Template template : Template.values()) {
            names.add(template.getName());
        }
        return names;
    }
    
    /**
     * Get template by name
     */
    public static Template getTemplateByName(String name) {
        for (Template template : Template.values()) {
            if (template.getName().equals(name)) {
                return template;
            }
        }
        return Template.QUICK_SCAN;
    }
}

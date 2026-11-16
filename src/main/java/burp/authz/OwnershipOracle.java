package burp.authz;

import burp.IExtensionHelpers;
import burp.IRequestInfo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ownership-aware IDOR/BOLA decision logic. Pure CPU — no network I/O; callers
 * supply the reference response bodies and this class turns them into a deterministic
 * verdict that separates a REAL cross-owner access from the two dominant false positives:
 *
 *  (a) FP_PUBLIC  — a PUBLIC / shared resource everyone legitimately sees (a shop product,
 *      a public page). Proven when an ANONYMOUS (auth-stripped) fetch of the SAME object
 *      returns an equivalent body: if the server hands the same content to a caller with no
 *      session, the object is not owned by anyone and reaching it is not a violation.
 *      (The user's "değişiklik herkesin göreceği alışveriş üzerindeki üründen olacaksa olmasın".)
 *
 *  (b) FP_OWN_DATA — the attacker's OWN data returned again, because the endpoint ignores the
 *      identifier or scopes it to the caller's session. Proven when the manipulated body equals
 *      the caller's own object of that type, or the invalid-id negative control.
 *      (The user's "yine kendi verisine ulaşıyorsa bu bir FP".)
 *
 *  CONFIRMED_IDOR — the manipulated body matches the legitimate OWNER's own view of THIS object
 *      (ground-truth path), proving the attacker reached exactly the data the owner sees. The
 *      single-session path can't supply an owner view, so it relies on {@link #carriesForeignOwnerData}
 *      (foreign identity tokens present in the manipulated body but absent from every reference).
 *
 *  AMBIGUOUS — distinct data that is provably neither public nor the caller's own, but without an
 *      owner view to confirm it. Caller escalates to the AI ("cevabın net olmadığı alanlar için
 *      yapay zekaya sorulsun") or, on the single-session path, defers it to the ground-truth pass.
 *
 * @author Zahid Eroglu
 */
public final class OwnershipOracle {

    private OwnershipOracle() {}

    // The two scan paths (IdorModule single-session, ScenarioAccessTester ground-truth) compose these
    // primitives into their own decision flow — each must run the public-resource and foreign-owner-token
    // checks in the order that fits its available references, so the matrix is expressed at the call site
    // rather than baked into one fixed-order method here.

    // ---- account-ownership parameter recognition ----------------------------
    // Single source of truth for the "Hesap Aitlik Kontrolü" (account-ownership validation) spec
    // (OWASP A01:2021 – Broken Access Control / IDOR). The spec flags backend endpoints that accept a
    // client-supplied account/customer identifier WITHOUT an IsOwnAccount()-style ownership check, letting
    // an attacker view or move another customer's money. Every IDOR/BOLA touchpoint (IdorModule,
    // AccessModelBuilder, PassiveTriage, PlaybookRouter) routes its id-parameter gate through
    // {@link #isAccountOwnershipParam} so NONE of these fields is ever skipped.
    //
    // The spec's exact fields are: CustomerId, AccountNumber, SenderAccountNumber, ReceiverAccountNumber,
    // AccountSuffix, SenderAccountSuffix, Iban, SenderIban, ReceiverIban, PersonId. Matching is by STEM
    // (substring of the separator-stripped, lower-cased name) so role-prefixed PascalCase compounds —
    // SenderAccountNumber, ReceiverIban, SenderAccountSuffix, OrderingCustomerId, … — are all caught,
    // not just the bare names.
    private static final String[] OWNERSHIP_STEMS = {
            "accountnumber", "accountno", "accountsuffix", "iban",
            "customerid", "customerno", "personid", "msisdn",
            "cardno", "cardnumber", "subscriberno"
    };

    /**
     * True when a request parameter name carries an account/customer ownership identifier per the
     * "Hesap Aitlik Kontrolü" spec — so the IDOR/BOLA engines test EVERY such field. Stem-matched
     * (separators stripped) so SenderAccountNumber / ReceiverIban / SenderAccountSuffix / PersonId and
     * other role-prefixed variants are recognised, not only the bare CustomerId / Iban names. Stems are
     * deliberately specific (no bare "account"/"customer") so non-identifier siblings like accountType
     * or customerName are not mistaken for object ids.
     */
    public static boolean isAccountOwnershipParam(String rawName) {
        if (rawName == null) return false;
        String n = rawName.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        if (n.isEmpty()) return false;
        for (String stem : OWNERSHIP_STEMS) {
            if (n.contains(stem)) return true;
        }
        return false;
    }

    // ---- body comparison ----------------------------------------------------

    /**
     * True when two response bodies represent the SAME content, tolerant of volatile fields
     * (timestamps, CSRF tokens, pagination nonces) that make benign re-fetches differ slightly.
     * Digit-preserving on purpose: for financial / PII objects the distinguishing data (account
     * no, IBAN, balance, the id itself) is numeric — stripping it would make a real cross-owner
     * body look identical to the caller's own object.
     */
    public static boolean bodiesEquivalent(String a, String b) {
        if (a == null || b == null) return false;
        String na = norm(a), nb = norm(b);
        if (na.equals(nb)) return true;
        int max = Math.max(na.length(), nb.length());
        if (max == 0) return true;
        // Very different lengths → different objects.
        if (Math.abs(na.length() - nb.length()) / (double) max > 0.20) return false;
        Set<String> ta = tokens(a), tb = tokens(b);
        if (ta.isEmpty() && tb.isEmpty()) return true;
        Set<String> inter = new HashSet<>(ta); inter.retainAll(tb);
        Set<String> uni = new HashSet<>(ta); uni.addAll(tb);
        return !uni.isEmpty() && (inter.size() / (double) uni.size()) >= 0.85;
    }

    private static String norm(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT).replaceAll("\\s+", "");
    }

    /** Lower-cased alphanumeric tokens (digits KEPT) of length >= 2. */
    private static Set<String> tokens(String s) {
        Set<String> out = new HashSet<>();
        if (s == null) return out;
        for (String t : s.toLowerCase(Locale.ROOT).split("[^a-z0-9]+")) {
            if (t.length() >= 2) out.add(t);
        }
        return out;
    }

    // ---- owner-identity tokens ---------------------------------------------

    private static final Pattern EMAIL = Pattern.compile(
            "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
    private static final Pattern IBAN = Pattern.compile(
            "\\b[A-Za-z]{2}[0-9]{2}[A-Za-z0-9]{10,30}\\b");
    /** JSON/field identity markers: "email":"..", "customerNo":"..", "iban":"..", etc. The VALUE (group 2)
     *  is the per-owner token. We deliberately do NOT match bare digit runs — a 13-digit epoch-millisecond
     *  timestamp would differ between requests and masquerade as another owner's id (a false positive). An
     *  account/card/msisdn number that actually identifies an owner is virtually always in a labelled field. */
    private static final Pattern IDFIELD = Pattern.compile(
            "\"(email|e-?mail|mail|user_?name|full_?name|first_?name|last_?name|"
            + "tckn|tc_?kimlik|national_?id|customer_?id|customer_?no|account_?no|account_?id|iban|msisdn|"
            + "phone|gsm|mobile|card_?no|pan|user_?id|owner|owner_?id|email_?address)\"\\s*:\\s*\"?"
            + "([^\"\\,\\}\\]\\s]{2,})", Pattern.CASE_INSENSITIVE);

    /** "Hesap Aitlik Kontrolü" account-ownership identity markers, matched even when the JSON key carries
     *  a role prefix/suffix ("SenderAccountNumber", "receiverIban", "AccountSuffix", "PersonId", …). The
     *  VALUE (group 1) is the per-owner token: a foreign account no / IBAN / customer-or-person id appearing
     *  in a swapped response (but in none of our references) is positive cross-owner evidence — exactly the
     *  leak the spec's IsOwnAccount() check is meant to prevent. Complements {@link #IDFIELD}, which only
     *  matches bare (un-prefixed) field names. */
    private static final Pattern OWNERSHIP_FIELD = Pattern.compile(
            "\"[a-z0-9_]*(?:account_?number|account_?no|account_?suffix|iban|customer_?id|customer_?no|"
            + "person_?id|msisdn|card_?no|card_?number|subscriber_?no)[a-z0-9_]*\"\\s*:\\s*\"?"
            + "([^\"\\,\\}\\]\\s]{2,})", Pattern.CASE_INSENSITIVE);

    /** Identity-bearing tokens: emails, IBANs, and the VALUES of named identity fields (customer/account/
     *  user/owner/msisdn/card/phone/name…). These are what prove a body belongs to a specific principal. */
    public static Set<String> ownerTokens(String body) {
        Set<String> out = new HashSet<>();
        if (body == null || body.isEmpty()) return out;
        addMatches(out, EMAIL, body);
        addMatches(out, IBAN, body);
        Matcher m = IDFIELD.matcher(body);
        while (m.find()) addLabelledValue(out, m.group(2));
        // Account-ownership fields (incl. role-prefixed SenderAccountNumber / ReceiverIban / PersonId …).
        Matcher mo = OWNERSHIP_FIELD.matcher(body);
        while (mo.find()) addLabelledValue(out, mo.group(1));
        return out;
    }

    /** Add a labelled field's value as an owner token, skipping short / boring placeholders. */
    private static void addLabelledValue(Set<String> out, String v) {
        if (v == null) return;
        String lv = v.toLowerCase(Locale.ROOT);
        if (lv.length() >= 2 && !isBoringValue(lv)) out.add(lv);
    }

    private static void addMatches(Set<String> out, Pattern p, String body) {
        Matcher m = p.matcher(body);
        while (m.find()) out.add(m.group().toLowerCase(Locale.ROOT));
    }

    private static boolean isBoringValue(String v) {
        return v.equals("null") || v.equals("true") || v.equals("false") || v.equals("none")
                || v.equals("string") || v.equals("0") || v.equals("-") || v.equals("undefined")
                || v.equals("n/a") || v.equals("na") || v.equals("{}") || v.equals("[]");
    }

    /** Owner tokens present in {@code manipulated} but in NONE of the reference bodies. */
    public static Set<String> foreignOwnerTokens(String manipulated, String... references) {
        Set<String> t = ownerTokens(manipulated);
        if (t.isEmpty()) return t;
        if (references != null) {
            for (String ref : references) {
                if (ref != null && !ref.isEmpty()) t.removeAll(ownerTokens(ref));
            }
        }
        return t;
    }

    /** True when the manipulated body carries identity data found in none of the references —
     *  strong evidence that ANOTHER principal's object was returned (the single-session positive signal). */
    public static boolean carriesForeignOwnerData(String manipulated, String... references) {
        return !foreignOwnerTokens(manipulated, references).isEmpty();
    }

    // ---- owner-identity tokens carried in RESPONSE HEADERS (not the body) ----
    // Some APIs echo the owning principal in a response header (X-User-Id, X-Account-Id, …) rather than in
    // the body. A swapped-id response whose ownership header carries a value ABSENT from our own baseline
    // headers is positive cross-owner evidence the body-only check misses. The whitelist is deliberately
    // ownership-SEMANTIC only: request/trace/correlation ids (which legitimately change every request) are
    // EXCLUDED so they can never masquerade as a foreign owner.
    private static final Set<String> OWNER_HEADER_NAMES = new HashSet<>(Arrays.asList(
            "x-user-id", "x-userid", "x-account-id", "x-accountid", "x-customer-id", "x-customerid",
            "x-owner-id", "x-ownerid", "x-tenant-id", "x-tenantid", "x-org-id", "x-orgid",
            "x-subscriber-id", "x-subscriberid", "x-person-id", "x-personid"));

    /** Owner-identity token VALUES carried in ownership-semantic response headers (X-User-Id, X-Account-Id,
     *  X-Owner-Id, X-Tenant-Id, …). Joined ("\n"-separated) header blob in, lower-cased values out. */
    public static Set<String> ownerHeaderTokens(String joinedHeaders) {
        Set<String> out = new HashSet<>();
        if (joinedHeaders == null || joinedHeaders.isEmpty()) return out;
        for (String line : joinedHeaders.split("\n")) {
            int c = line.indexOf(':');
            if (c <= 0) continue;
            String name = line.substring(0, c).trim().toLowerCase(Locale.ROOT);
            if (!OWNER_HEADER_NAMES.contains(name)) continue;
            String v = line.substring(c + 1).trim().toLowerCase(Locale.ROOT);
            if (v.length() >= 1 && !isBoringValue(v)) out.add(v);
        }
        return out;
    }

    /** Owner header tokens present in {@code manipulatedHeaders} but in none of the reference header blobs. */
    public static Set<String> foreignOwnerHeaderTokens(String manipulatedHeaders, String... referenceHeaders) {
        Set<String> t = ownerHeaderTokens(manipulatedHeaders);
        if (t.isEmpty()) return t;
        if (referenceHeaders != null) {
            for (String ref : referenceHeaders) {
                if (ref != null && !ref.isEmpty()) t.removeAll(ownerHeaderTokens(ref));
            }
        }
        return t;
    }

    // ---- request helpers ----------------------------------------------------

    /**
     * Clone a request with every session/authentication credential removed — the anonymous
     * "public" probe. Keeps the method, path, body and (browser) User-Agent so an upstream WAF
     * does not 403 the clone; only drops the credentials that prove who the caller is. Strips BOTH
     * header credentials (Cookie/Authorization/X-*-Token) AND well-known session tokens carried in the
     * URL query string (?token=, ?sid=, jsessionid=, …) — otherwise a query-token session would survive
     * and the "anonymous" body would equal the authenticated one, falsely suppressing a real IDOR.
     */
    public static byte[] stripAuthHeaders(IExtensionHelpers helpers, byte[] request) {
        if (helpers == null || request == null) return null;
        try {
            IRequestInfo ri = helpers.analyzeRequest(request);
            List<String> headers = ri.getHeaders();
            List<String> out = new ArrayList<>();
            for (int i = 0; i < headers.size(); i++) {
                String h = headers.get(i);
                if (i == 0) { out.add(stripQueryTokens(h)); continue; } // request line: strip URL session tokens
                if (isAuthHeader(h)) continue;
                out.add(h);
            }
            byte[] body = Arrays.copyOfRange(request, ri.getBodyOffset(), request.length);
            return helpers.buildHttpMessage(out, body);
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isAuthHeader(String h) {
        if (h == null) return false;
        String l = h.toLowerCase(Locale.ROOT);
        return l.startsWith("cookie:") || l.startsWith("authorization:") || l.startsWith("authentication:")
                || l.startsWith("x-auth-token:") || l.startsWith("x-api-key:") || l.startsWith("x-access-token:")
                || l.startsWith("x-xsrf-token:") || l.startsWith("x-csrf-token:") || l.startsWith("x-session-token:")
                || l.startsWith("x-auth:") || l.startsWith("proxy-authorization:");
    }

    /** Session/auth token names that some apps pass in the URL query string instead of a cookie/header. */
    private static final Set<String> URL_TOKEN_PARAMS = new HashSet<>(Arrays.asList(
            "token", "access_token", "accesstoken", "auth_token", "authtoken", "id_token", "idtoken",
            "session", "sessionid", "session_id", "sid", "jsessionid", "phpsessid", "aspsessionid",
            "auth", "apikey", "api_key", "key", "jwt", "bearer", "sig", "signature", "ticket", "st",
            "sso", "ssotoken", "oauth_token", "code"));

    /**
     * Strip well-known session/auth tokens from the query string of a request line
     * ("GET /path?token=..&amp;id=5 HTTP/1.1"), leaving the path and all other params intact.
     */
    private static String stripQueryTokens(String requestLine) {
        if (requestLine == null) return null;
        try {
            String[] parts = requestLine.split(" ");
            if (parts.length < 2) return requestLine;
            String target = parts[1];
            int q = target.indexOf('?');
            if (q < 0 || q == target.length() - 1) return requestLine; // no query
            String path = target.substring(0, q);
            String query = target.substring(q + 1);
            StringBuilder kept = new StringBuilder();
            for (String pair : query.split("&")) {
                if (pair.isEmpty()) continue;
                int eq = pair.indexOf('=');
                String name = (eq >= 0 ? pair.substring(0, eq) : pair).toLowerCase(Locale.ROOT);
                if (URL_TOKEN_PARAMS.contains(name)) continue; // drop the session token
                if (kept.length() > 0) kept.append('&');
                kept.append(pair);
            }
            parts[1] = kept.length() > 0 ? path + "?" + kept : path;
            return String.join(" ", parts);
        } catch (Exception e) {
            return requestLine;
        }
    }
}

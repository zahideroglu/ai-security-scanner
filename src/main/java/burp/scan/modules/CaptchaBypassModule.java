package burp.scan.modules;

import burp.Finding;
import burp.IParameter;
import burp.Settings;
import burp.i18n.I18n;
import burp.scan.Baseline;
import burp.scan.Probe;
import burp.scan.ProbeResult;
import burp.scan.ScanModule;
import burp.scan.Signals;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * A07 Identification &amp; Authentication Failures — CAPTCHA / human-verification BYPASS.
 *
 * <p>Many login / one-time-action endpoints put a CAPTCHA in front of credential
 * checking but fail to ENFORCE it server-side: the CAPTCHA token is validated on the
 * client, never re-checked, accepted empty, or not invalidated after the first use.
 * On a request that carries a CAPTCHA parameter we re-submit it three ways —
 * <b>omitted</b>, <b>empty</b>, and with a <b>garbage</b> value — and decide whether the
 * server still processed the request (it reached credential validation / succeeded /
 * advanced to the next step) instead of demanding a valid CAPTCHA.</p>
 *
 * <p>The oracle is deliberately conservative to avoid the false positives that plagued
 * the rest of the scanner: a response that asks for / rejects the CAPTCHA proves the
 * control IS enforced (no finding); a response that reaches a CREDENTIAL error / success /
 * OTP step (or is indistinguishable from the with-CAPTCHA baseline) proves it was
 * BYPASSED. Anything ambiguous is emitted at lower confidence for the AI adjudicator,
 * which receives the actual bypass response + the baseline as evidence.</p>
 *
 * @author Zahid Eroglu
 */
public class CaptchaBypassModule implements ScanModule {

    /** Parameter names that carry a CAPTCHA / human-verification token. */
    private static final Pattern CAPTCHA_PARAM = Pattern.compile(
            "captcha|recaptcha|hcaptcha|g-recaptcha-response|h-captcha-response", Pattern.CASE_INSENSITIVE);

    /** Response wording meaning the CAPTCHA WAS required/checked (control enforced → secure). */
    private static final Pattern CAPTCHA_ENFORCED = Pattern.compile(
            "captcha|recaptcha|hcaptcha|you are (a )?robot|are you (a )?human|i'?m not a robot|"
            + "robot de[gğ]il|g[uü]venlik kodu|resimdeki|do[gğ]rulama kodunu gir|"
            + "verify you are human|human verification|please complete the (captcha|verification)|"
            + "g[uü]venlik do[gğ]rulamas[iı]|captcha (required|invalid|expired|gerekli|hatal[iı]|bo[sş])",
            Pattern.CASE_INSENSITIVE);

    /** Response wording meaning the server PROCESSED the request past the CAPTCHA (bypassed). */
    private static final Pattern PROCEEDED = Pattern.compile(
            "kullan[iı]c[iı] ad[iı] veya (parola|[sş]ifre)|hatal[iı] (kullan[iı]c[iı]|parola|[sş]ifre)|"
            + "(parola|[sş]ifre)niz hatal[iı]|ge[cç]ersiz (kullan[iı]c[iı]|kimlik)|kullan[iı]c[iı] bulunamad[iı]|"
            + "invalid (username|password|user name|credentials)|incorrect (password|username)|wrong password|"
            + "bad credentials|authentication failed|login failed|"
            + "\"access_?token\"|\"id_?token\"|isauthenticated|\"success\"\\s*:\\s*true|"
            + "tek kullan[iı]ml[iı]k|otp|sms (kodu|do[gğ]rulama)|do[gğ]rulama kodu g[oö]nder",
            Pattern.CASE_INSENSITIVE);

    /** Lockout / rate-limit wording: the server BLOCKED the request — the control is ACTIVE, not bypassed. */
    private static final Pattern LOCKOUT = Pattern.compile(
            "hesab[iı]n[iı]z (kilit|bloke)|account (is )?(locked|blocked)|too many (attempts|requests|tries)|"
            + "[cç]ok fazla deneme|rate limit|429|ge[cç]ici olarak engellendi|try again later",
            Pattern.CASE_INSENSITIVE);

    /** Identity/secret parameter names — replaced with benign dummies so we NEVER submit real credentials. */
    private static final Pattern CRED_PARAM = Pattern.compile(
            "user(name)?|email|e-?posta|login|kullan[iı]c[iı]|m[uü][sş]teri|customer|"
            + "pass(word)?|parola|[sş]ifre|pwd", Pattern.CASE_INSENSITIVE);

    public String id() { return "captchabypass"; }
    public String displayName() { return "CAPTCHA / Auth-step Bypass"; }
    public boolean isEnabled(Settings s) { return s.isModuleCaptchaBypassEnabled(); }

    public boolean appliesTo(Baseline b) {
        // A captcha-bearing, state-changing request (login / one-time action). Need a baseline to compare.
        if (b.statusCode <= 0) return false;
        if (!("POST".equalsIgnoreCase(b.method) || "PUT".equalsIgnoreCase(b.method))) return false;
        return captchaParam(b) != null;
    }

    private static final String DUMMY_ID = "zzcaptchatest9q7z";
    private static final String DUMMY_SECRET = "Zz9q7zCaptcha.Test";

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> probes = new ArrayList<>();
        IParameter cap = captchaParam(b);
        if (cap == null || b.base == null) return probes;
        byte[] orig = b.base.getRequest();
        if (orig == null) return probes;

        // SAFETY: never replay the user's real credentials (could lock THEIR account). Swap any
        // username/password-like fields to benign non-existent dummies first, so failed attempts (and any
        // lockout) hit a fake account, and a "invalid credentials" reply still proves the CAPTCHA was skipped.
        byte[] neutral = neutralizeCreds(b, orig);
        // Re-resolve the captcha parameter on the neutralised request (offsets shifted).
        IParameter cap2 = captchaParamOf(b, neutral);
        if (cap2 == null) cap2 = cap;

        // 1) Omit the CAPTCHA parameter entirely (is it enforced server-side at all?).
        addRaw(probes, safeRemove(b, neutral, cap2), "Omit CAPTCHA (" + cap.getName() + ")", "omit");
        // 2) Empty CAPTCHA value (does an empty token pass?).
        addRaw(probes, safeUpdate(b, neutral, cap2, ""), "Empty CAPTCHA (" + cap.getName() + ")", "empty");
        // 3) Garbage CAPTCHA value (is the token actually validated?).
        addRaw(probes, safeUpdate(b, neutral, cap2, "0000"), "Garbage CAPTCHA (" + cap.getName() + ")", "garbage");

        return probes;
    }

    /** Replace identity/secret parameters with benign dummies (no real-credential replay). */
    private byte[] neutralizeCreds(Baseline b, byte[] req) {
        byte[] out = req;
        try {
            for (IParameter p : b.parameters) {
                byte t = p.getType();
                if (t != IParameter.PARAM_URL && t != IParameter.PARAM_BODY && t != IParameter.PARAM_JSON
                        && t != IParameter.PARAM_MULTIPART_ATTR) continue;
                if (CAPTCHA_PARAM.matcher(p.getName()).find()) continue; // leave the captcha field for the probes
                if (!CRED_PARAM.matcher(p.getName()).find()) continue;
                boolean secret = p.getName().toLowerCase().matches(".*(pass|parola|sifre|şifre|pwd).*");
                String dummy = secret ? DUMMY_SECRET : DUMMY_ID;
                out = b.helpers.updateParameter(out, b.helpers.buildParameter(p.getName(), dummy, p.getType()));
            }
        } catch (Exception ignore) {
        }
        return out;
    }

    private IParameter captchaParamOf(Baseline b, byte[] req) {
        try {
            for (IParameter p : b.helpers.analyzeRequest(req).getParameters()) {
                if (CAPTCHA_PARAM.matcher(p.getName()).find()) return p;
            }
        } catch (Exception ignore) {
        }
        return null;
    }

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> findings = new ArrayList<>();
        ProbeResult bestBypass = null;
        String bestScenario = null;
        ProbeResult ambiguous = null;
        String ambiguousScenario = null;

        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok() || !"CAPTCHA Bypass".equals(r.probe.attackType)) continue;
            String scenario = String.valueOf(r.probe.tag);
            String body = r.bodySnippet == null ? "" : r.bodySnippet;
            // Never reason about a WAF/block page or a binary blob.
            if (Signals.looksLikeBlockPage(body)) continue;
            if (Signals.isBinaryOrImageType(Signals.contentTypeOf(r.responseHeaders))) continue;
            // 1xx/5xx server errors aren't a clean "processed" signal.
            if (r.statusCode < 200 || r.statusCode >= 500) continue;

            // CAPTCHA was demanded/rejected, OR the server locked/rate-limited us → the control is ACTIVE
            // (not a bypass). Treating lockout as "proceeded" would mislabel a working defense.
            if (CAPTCHA_ENFORCED.matcher(body).find() || LOCKOUT.matcher(body).find()) continue;

            // A bypass needs POSITIVE proof the request reached credential/next-step handling. We do NOT use
            // "same size as the baseline" — the baseline re-fires the original request whose single-use CAPTCHA
            // token is already consumed, so the baseline is itself a rejection and matching it proves nothing.
            if (PROCEEDED.matcher(body).find()) {
                if (bestBypass == null) { bestBypass = r; bestScenario = scenario; }
            } else if (ambiguous == null) {
                ambiguous = r; ambiguousScenario = scenario;
            }
        }

        if (bestBypass != null) {
            findings.add(buildFinding(b, bestBypass, bestScenario, true));
        } else if (ambiguous != null) {
            // Couldn't prove it deterministically — hand the AI a real candidate (with the evidence
            // response + baseline) rather than dropping a possible bypass silently.
            Finding f = buildFinding(b, ambiguous, ambiguousScenario, false);
            f.setSeverity("Medium");
            f.setConfidence(0.4);
            f.setOracleVerdict(burp.Finding.OracleVerdict.INCONCLUSIVE);
            findings.add(f);
        }
        return findings;
    }

    private Finding buildFinding(Baseline b, ProbeResult r, String scenario, boolean strong) {
        String how = "omit".equals(scenario) ? I18n.t("f.cap.how.omit")
                : "empty".equals(scenario) ? I18n.t("f.cap.how.empty")
                : I18n.t("f.cap.how.garbage");
        String evSuffix = strong ? I18n.t("f.cap.bypass.ev.strong") : I18n.t("f.cap.bypass.ev.weak");
        Finding f = new Finding("CAPTCHA Bypass", "High", strong ? 0.75 : 0.55,
                I18n.t("f.cap.bypass.desc", how, r.statusCode),
                "", I18n.t("f.cap.bypass.ev", r.probe.description, r.statusCode, r.responseLength, b.responseLength, evSuffix),
                I18n.t("f.cap.bypass.exp", how),
                I18n.t("f.cap.bypass.rem"));
        f.setHttpResponse(r.bodySnippet);
        f.setControlResponse(b.bodySnippet); // the with-CAPTCHA baseline = control for the AI comparison
        f.setOracleVerdict(burp.Finding.OracleVerdict.INCONCLUSIVE); // AI adjudicates with both bodies
        return f;
    }

    private void addRaw(List<Probe> probes, byte[] raw, String desc, String scenarioTag) {
        if (raw == null) return;
        Probe p = new Probe(id(), desc, "raw", scenarioTag, "", "CAPTCHA Bypass", "High");
        p.rawRequest = raw;
        p.tag = scenarioTag;
        probes.add(p);
    }

    private byte[] safeRemove(Baseline b, byte[] req, IParameter p) {
        try { return b.helpers.removeParameter(req, p); } catch (Exception e) { return null; }
    }

    private byte[] safeUpdate(Baseline b, byte[] req, IParameter p, String value) {
        try {
            return b.helpers.updateParameter(req, b.helpers.buildParameter(p.getName(), value, p.getType()));
        } catch (Exception e) { return null; }
    }

    private IParameter captchaParam(Baseline b) {
        for (IParameter p : b.parameters) {
            byte t = p.getType();
            if (t != IParameter.PARAM_URL && t != IParameter.PARAM_BODY && t != IParameter.PARAM_JSON
                    && t != IParameter.PARAM_COOKIE && t != IParameter.PARAM_MULTIPART_ATTR) continue;
            if (CAPTCHA_PARAM.matcher(p.getName()).find()) return p;
        }
        return null;
    }
}

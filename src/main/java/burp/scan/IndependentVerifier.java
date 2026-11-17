package burp.scan;

import burp.Finding;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IResponseInfo;
import burp.authz.OwnershipOracle;
import burp.engine.SharedRateLimiter;
import burp.report.ReproStep;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

/**
 * A SECOND, context-decoupled verification pass over a finding that already passed the first gate.
 *
 * <p>The first {@code aiJudge} runs in the finder's context (it sees the candidate's evidence text).
 * This pass is independent: it re-sends the finding's own {@link ReproStep reproduction bundle} LIVE
 * (it does NOT trust the cached responses), re-applies the deterministic ownership oracle to the fresh
 * bodies, and — when AI is available — asks a clean-context judge that sees ONLY the raw transactions
 * (own / attack / control bodies), never the finder's "I found IDOR" narrative.
 *
 * <p>Outcome:
 * <ul>
 *   <li>{@link Outcome#REPRODUCED} — the cross-owner leak recurs on an independent sample → keep CONFIRMED;</li>
 *   <li>{@link Outcome#NOT_REPRODUCED} — it did not recur (transient / flaky / disagreement) → caller flags
 *       NEEDS-REVIEW instead of silently confirming OR silently dropping;</li>
 *   <li>{@link Outcome#UNAVAILABLE} — could not re-send (host blocked, no bundle) → first-pass result stands.</li>
 * </ul>
 *
 * Only re-runs the SAME authorised verification more rigorously — no new attack class, no exploitation.
 *
 * @author Zahid Eroglu
 */
public class IndependentVerifier {

    public enum Outcome { REPRODUCED, NOT_REPRODUCED, UNAVAILABLE }

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final burp.AiApiClient aiClient;   // may be null → skip the clean-context AI vote
    private final SharedRateLimiter limiter;
    private final PrintWriter stdout;
    private final PrintWriter stderr;

    public IndependentVerifier(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                               burp.AiApiClient aiClient, SharedRateLimiter limiter,
                               PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.aiClient = aiClient;
        this.limiter = limiter;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    public Outcome verify(Finding f) {
        try {
            if (f == null) return Outcome.UNAVAILABLE;
            List<ReproStep> steps = f.getReproSteps();
            if (steps == null || steps.isEmpty()) return Outcome.UNAVAILABLE;

            ReproStep own = find(steps, ReproStep.Role.OWN);
            ReproStep attack = find(steps, ReproStep.Role.ATTACK);
            ReproStep control = find(steps, ReproStep.Role.CONTROL);
            if (attack == null || !attack.hasRequest()) return Outcome.UNAVAILABLE;

            String host = attack.getHost();
            if (host == null || host.isEmpty()) return Outcome.UNAVAILABLE;
            if (limiter != null && limiter.isHostBlocked(host)) return Outcome.UNAVAILABLE;

            IHttpService svc = service(host, attack.getPort(), attack.isHttps());

            byte[] freshAttackResp = resend(svc, attack.getRequest());
            if (freshAttackResp == null) return Outcome.UNAVAILABLE;
            byte[] freshControlResp = (control != null && control.hasRequest())
                    ? resend(svc, control.getRequest()) : null;

            // Fresh status must be a real 200 object — a 401/403/5xx on the replay is NOT a reproduced leak.
            int freshStatus = statusOf(freshAttackResp);
            if (freshStatus != 200) {
                note(f, "indep.notReproduced.status", freshStatus);
                return Outcome.NOT_REPRODUCED;
            }

            String ownBody = own != null ? bodyText(own.getResponse()) : "";
            String freshAttackBody = bodyText(freshAttackResp);
            String freshControlBody = freshControlResp != null ? bodyText(freshControlResp) : "";

            // Deterministic re-check: foreign owner-identity tokens in the FRESH attack body, absent from our
            // own object and the fresh control (the same oracle the first pass trusted — just on a new sample).
            Set<String> foreign = OwnershipOracle.foreignOwnerTokens(freshAttackBody, ownBody, freshControlBody);
            String injected = injectedId(attack.getDetail());
            if (injected != null) foreign.remove(injected.toLowerCase());
            boolean deterministicRepro = !foreign.isEmpty();

            // Clean-context AI judge: sees ONLY the raw bodies, with a neutral manipulation label — never the
            // finder's narrative. Used solely to DOWNGRADE a deterministic reproduction on active disagreement.
            Boolean aiValid = cleanContextJudge(f.getType(), ownBody, freshAttackBody, freshControlBody);

            if (deterministicRepro && (aiValid == null || aiValid)) {
                if (stdout != null) stdout.println("[IndependentVerifier] REPRODUCED " + f.getType() + " @ " + host);
                return Outcome.REPRODUCED;
            }
            note(f, deterministicRepro ? "indep.notReproduced.aiSplit" : "indep.notReproduced.det");
            return Outcome.NOT_REPRODUCED;
        } catch (Exception e) {
            if (stderr != null) stderr.println("[IndependentVerifier] " + e.getMessage());
            return Outcome.UNAVAILABLE;
        }
    }

    // ---- clean-context AI (optional) ----------------------------------------------------------------

    /** null = AI unavailable/unused; TRUE/FALSE = clean-context verdict on the raw bodies. */
    private Boolean cleanContextJudge(String type, String ownBody, String attackBody, String controlBody) {
        if (aiClient == null) return null;
        try {
            burp.ai.AIFalsePositiveFilter filter = new burp.ai.AIFalsePositiveFilter(
                    aiClient, helpers, stdout, stderr);
            burp.ai.AIFalsePositiveFilter.ValidationResult r = filter.judgeAccessControlConsensus(
                    type, "independent replay (no finder context)", ownBody, attackBody, controlBody, null);
            if (r == null || r.verificationUnavailable) return null;
            return r.isValidVulnerability;
        } catch (Exception e) {
            return null; // fail-open: AI absence never blocks the deterministic decision
        }
    }

    // ---- helpers ------------------------------------------------------------------------------------

    private static ReproStep find(List<ReproStep> steps, ReproStep.Role role) {
        for (ReproStep s : steps) if (s.getRole() == role) return s;
        return null;
    }

    private byte[] resend(IHttpService svc, byte[] request) {
        try {
            if (limiter != null) limiter.acquire();
            IHttpRequestResponse rr = callbacks.makeHttpRequest(svc, request);
            return rr == null ? null : rr.getResponse();
        } catch (Exception e) {
            return null;
        }
    }

    private int statusOf(byte[] resp) {
        try { return helpers.analyzeResponse(resp).getStatusCode(); }
        catch (Exception e) { return 0; }
    }

    private String bodyText(byte[] resp) {
        if (resp == null) return "";
        try {
            IResponseInfo ri = helpers.analyzeResponse(resp);
            int off = ri.getBodyOffset();
            if (off <= 0 || off > resp.length) return "";
            int end = Math.min(resp.length, off + 8192);
            return new String(resp, off, end - off, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    /** The value after the "→" in an attack-step detail ("param → 42") — the id WE injected, never evidence. */
    private String injectedId(String detail) {
        if (detail == null) return null;
        int arrow = detail.lastIndexOf('→');
        if (arrow < 0) return null;
        String v = detail.substring(arrow + 1).trim();
        return v.isEmpty() ? null : v;
    }

    private IHttpService service(String host, int port, boolean https) {
        final String h = host;
        final int p = port > 0 ? port : (https ? 443 : 80);
        final String proto = https ? "https" : "http";
        return new IHttpService() {
            public String getHost() { return h; }
            public int getPort() { return p; }
            public String getProtocol() { return proto; }
        };
    }

    private void note(Finding f, String key, Object... args) {
        try { f.addVerificationStep(burp.i18n.I18n.t(key, args)); } catch (Exception ignore) {}
    }
}

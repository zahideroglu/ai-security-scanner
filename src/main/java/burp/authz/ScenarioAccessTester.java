package burp.authz;

import burp.Finding;
import burp.i18n.I18n;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.MultiSessionTester;
import burp.MultiSessionTester.UserSession;
import burp.QwenAPIClient;
import burp.ai.AIFalsePositiveFilter;
import burp.scan.Signals;
import burp.engine.DetectionStage;
import burp.engine.SharedRateLimiter;
import burp.engine.StageListener;
import burp.spec.SyntheticHttpRequestResponse;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Ground-truth BOLA tester: for each attacker identity A and each object provably
 * owned by another identity B, replays B's request to that object AS A. If A gets
 * HTTP 200, AI compares A's response (B's object) vs a baseline + a negative control
 * (same endpoint, invalid id) to confirm a real cross-owner access. The ground truth
 * ("this object belongs to B") makes the finding provable, not a guess.
 *
 * @author Zahid Eroglu
 */
public class ScenarioAccessTester {

    private static final String INVALID_ID = "2147483646";
    private static final int MAX_TESTS = 80;

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final MultiSessionTester mtester;
    private final QwenAPIClient qwen;
    private final SharedRateLimiter limiter;
    private final PrintWriter stdout, stderr;
    private final AccessOracle oracle;

    public ScenarioAccessTester(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                                MultiSessionTester mtester, QwenAPIClient qwen, SharedRateLimiter limiter,
                                PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.mtester = mtester;
        this.qwen = qwen;
        this.limiter = limiter;
        this.stdout = stdout;
        this.stderr = stderr;
        this.oracle = new AccessOracle(helpers);
    }

    public List<Finding> run(AccessModel model, List<UserSession> roleSessions, boolean includeMutating,
                             StageListener l) {
        List<Finding> findings = new ArrayList<>();
        Map<String, UserSession> byName = new HashMap<>();
        for (UserSession s : roleSessions) byName.put(s.roleName, s);
        AIFalsePositiveFilter ai = (qwen != null)
                ? new AIFalsePositiveFilter(qwen, helpers, stdout, stderr) : null;

        int tests = 0;
        for (String attacker : model.roles) {
            UserSession aSess = byName.get(attacker);
            if (aSess == null) continue;
            for (AccessModel.OwnedObject victim : model.objectsNotOwnedBy(attacker)) {
                if (tests >= MAX_TESTS) {
                    if (l != null) l.onStageProgress(DetectionStage.EXECUTE,
                            "BOLA testi sınırı (" + MAX_TESTS + ") — kalanlar atlandı");
                    return findings;
                }
                if (!includeMutating && !isGet(victim.request)) continue; // never replay mutating cross-owner unless allowed
                // Skip pre-auth / public / benign endpoints (login, captcha, token, register, reset, health,
                // logout, .well-known, language) — reaching them is not cross-owner access.
                if (oracle.isBenignPath(pathOf(victim.request))) continue;
                tests++;

                // Manipulated: A requests B's object (B's id, A's session).
                if (limiter != null) limiter.acquire();
                IHttpRequestResponse manip = safeReplay(victim.request, aSess);
                // Use the oracle verdict (folds in 401/403=DENIED, 3xx-redirect=DENIED, 200-login-page=DENIED)
                // instead of a bare 200, so a silently-expired attacker session redirected to /login is not a hit.
                if (manip == null || oracle.verdict(manip.getResponse()) != AuthMatrix.Verdict.GRANTED) continue;
                String manipBody = bodyOf(manip);
                // A binary/image payload or a WAF/block page is never cross-owner object data.
                String manipCt = manip.getResponse() == null ? "" : Signals.contentTypeOf(
                        String.join("\n", helpers.analyzeResponse(manip.getResponse()).getHeaders()));
                // Only skip IMAGE/MEDIA (charts/avatars) — a PDF/ZIP/octet-stream export CAN be sensitive
                // cross-owner data, so it must stay in scope for the BOLA check.
                if (Signals.isImageOrMediaType(manipCt) || Signals.looksLikeBlockPage(manipBody)) continue;

                // ── WRITE-IDOR / mutating BOLA ──────────────────────────────────────────────────────
                // For a mutating request the response body is a confirmation, not the object, so the read
                // body-comparison oracle below does not apply. Use a STATUS oracle: the attacker was GRANTED
                // (2xx) replaying the VICTIM's own request (idempotent — victim's own body, so no data is
                // actually changed); confirm the id MATTERS by checking the SAME request with an INVALID id is
                // DENIED. GRANTED-on-foreign + DENIED-on-invalid = the attacker can WRITE another owner's
                // object. (Only idempotent PUT/PATCH — DELETE/POST are excluded as destructive / object-creating.)
                String method = methodOf(victim.request);
                if ("PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) {
                    boolean idMatters = true;
                    byte[] invW = withInvalidId(victim);
                    if (invW != null) {
                        if (limiter != null) limiter.acquire();
                        IHttpRequestResponse negW = safeReplay(
                                new SyntheticHttpRequestResponse(invW, victim.request.getHttpService()), aSess);
                        idMatters = (negW == null) || oracle.verdict(negW.getResponse()) != AuthMatrix.Verdict.GRANTED;
                    }
                    if (!idMatters) {
                        if (l != null) l.onStageProgress(DetectionStage.EXECUTE,
                                "Write-IDOR atlandı (uç id'yi yok sayıyor): " + method + " " + victim.type + ":" + victim.id);
                        continue;
                    }
                    Finding wf = new Finding("Write-IDOR / BOLA (" + method + ")", "Critical", 0.9,
                            I18n.t("f.sat.writeidor.desc", attacker, method, victim.type + ":" + victim.id, victim.role),
                            "", I18n.t("f.sat.writeidor.ev", attacker, victim.role, method, victim.type + ":" + victim.id, reqLine(victim.request)),
                            I18n.t("f.sat.writeidor.exp"),
                            I18n.t("f.sat.writeidor.rem"));
                    wf.setHttpRequest(reqLine(victim.request));
                    try { wf.setAffectedUrl(helpers.analyzeRequest(victim.request).getUrl().toString()); } catch (Exception ignore) {}
                    wf.setHttpResponse(manipBody);
                    wf.setOracleVerdict(burp.Finding.OracleVerdict.CONFIRMED);
                    note(wf, I18n.t("f.sat.writeidor.note"));
                    findings.add(wf);
                    if (l != null) l.onStageProgress(DetectionStage.EXECUTE,
                            "⚠ Write-IDOR: " + attacker + " → " + victim.role + " nesnesini " + method + " edebiliyor ("
                                    + victim.type + ":" + victim.id + ")");
                    continue; // handled as write-IDOR; skip the read body-comparison path below
                }
                // ────────────────────────────────────────────────────────────────────────────────────

                // Public/shared-resource discriminator: fetch the SAME victim object with NO session at all
                // (every credential stripped). If an anonymous caller ALSO gets a real GRANTED 200 with an
                // equivalent body, the object is public/shared (a shop product, a public page) — the ownership
                // model only recorded it as "owned by B" because B happened to view it. Reaching it
                // cross-session is NOT a violation. Only probe safe (GET) reads.
                if (isGet(victim.request)) {
                    byte[] anonReq = OwnershipOracle.stripAuthHeaders(helpers, victim.request.getRequest());
                    if (anonReq != null) {
                        if (limiter != null) limiter.acquire();
                        IHttpRequestResponse anon = safeSend(anonReq, victim.request.getHttpService());
                        if (anon != null && oracle.verdict(anon.getResponse()) == AuthMatrix.Verdict.GRANTED
                                && OwnershipOracle.bodiesEquivalent(manipBody, bodyOf(anon))) {
                            if (l != null) l.onStageProgress(DetectionStage.EXECUTE,
                                    "BOLA atlandı (genel/paylaşılan kaynak): " + victim.type + ":" + victim.id);
                            continue; // public/shared resource → not cross-owner access
                        }
                    }
                }

                // Negative control: same endpoint AS A but with a definitely-invalid id.
                String negBody = "";
                byte[] inv = withInvalidId(victim);
                if (inv != null) {
                    if (limiter != null) limiter.acquire();
                    IHttpRequestResponse neg = safeReplay(
                            new SyntheticHttpRequestResponse(inv, victim.request.getHttpService()), aSess);
                    negBody = bodyOf(neg);
                }

                // Baseline: A's own object of the same type (reference shape), if any.
                String baseBody = "";
                AccessModel.OwnedObject own = model.ownObjectOfType(attacker, victim.type);
                if (own != null && own.request.getResponse() != null) baseBody = bodyBytes(own.request.getResponse());

                // Deterministic cross-owner proof FIRST (ground truth, not a guess): the attacker got a
                // GRANTED response (line above) to the VICTIM's object, and that body is real AND distinct
                // from the invalid-id negative control AND from the attacker's own object of that type.
                // id-ignoring endpoints (same body for any id) and "returns my own data" are NOT vulns → skip.
                if (manipBody.trim().isEmpty()
                        || norm(manipBody).equals(norm(negBody))
                        || norm(manipBody).equals(norm(baseBody))) {
                    continue; // indistinguishable from control / own data → not a cross-owner hit
                }

                // Positive cross-owner proof: the attacker's body is equivalent to the OWNER's OWN recorded
                // view of this exact object, yet differs from the attacker's own object — the attacker is
                // seeing precisely B's data, not a coincidentally-distinct object. Strengthens the verdict.
                String ownerBody = (victim.request.getResponse() != null)
                        ? bodyBytes(victim.request.getResponse()) : "";
                boolean ownerMatch = !ownerBody.trim().isEmpty()
                        && OwnershipOracle.bodiesEquivalent(manipBody, ownerBody)
                        && !OwnershipOracle.bodiesEquivalent(manipBody, baseBody);

                Finding f = new Finding("BOLA (Ground-Truth)", "High", 0.9,
                        I18n.t("f.sat.bola.desc", attacker, victim.type + ":" + victim.id, victim.role),
                        "", I18n.t("f.sat.bola.ev", attacker, victim.role, victim.type + ":" + victim.id, reqLine(victim.request)),
                        I18n.t("f.sat.bola.exp"),
                        I18n.t("f.sat.bola.rem"));
                f.setHttpRequest(reqLine(victim.request));
                try { f.setAffectedUrl(helpers.analyzeRequest(victim.request).getUrl().toString()); } catch (Exception ignore) {}
                f.setHttpResponse(manipBody);
                if (!negBody.isEmpty()) f.setControlResponse(negBody);
                // PROVEN by ground truth → mark it DIRECTLY as CONFIRMED. The AI below is only a refinement:
                // it may DOWNGRADE on an active refutation, but an unavailable / timed-out AI never weakens
                // a deterministically-proven cross-owner hit (this was the "AI yanıt vermedi → Low" gap).
                f.setOracleVerdict(burp.Finding.OracleVerdict.CONFIRMED);
                if (ownerMatch) {
                    f.setConfidence(Math.max(f.getConfidence(), 0.95));
                    note(f, I18n.t("f.sat.ownermatch"));
                }

                if (ai != null) {
                    AIFalsePositiveFilter.ValidationResult r = ai.judgeAccessControlConsensus(
                            "BOLA (Ground-Truth)",
                            "attacker '" + attacker + "' replayed victim '" + victim.role + "' object "
                                    + victim.type + ":" + victim.id + " with the attacker's own session",
                            baseBody, manipBody, negBody, null);
                    String why = (r.reasoning == null) ? "" : r.reasoning;
                    if (!r.verificationUnavailable && !r.isValidVulnerability) {
                        f.setFalsePositive(true);
                        f.setOracleVerdict(burp.Finding.OracleVerdict.REFUTED);
                        if (r.confidence > 0) f.setConfidence(Math.min(f.getConfidence(), r.confidence));
                        note(f, "AI: olası FALSE POSITIVE — " + why);
                    } else if (r.verificationUnavailable) {
                        note(f, "AI doğrulanamadı — bulgu ground-truth (çapraz-sahip) deterministik kanıta dayanıyor, doğrudan işaretlendi.");
                    } else {
                        if (r.confidence > 0) f.setConfidence(Math.max(f.getConfidence(), r.confidence));
                        note(f, "AI doğrulaması (ground-truth BOLA): " + why);
                    }
                } else {
                    note(f, "AI yok — ground-truth (çapraz-sahip) deterministik kanıt; doğrudan işaretlendi.");
                }
                findings.add(f);
                if (l != null) l.onStageProgress(DetectionStage.EXECUTE,
                        "BOLA: " + attacker + " → " + victim.role + " " + victim.type + ":" + victim.id
                                + " (" + (f.isFalsePositive() ? "FP" : "HIT") + ")");
            }
        }
        return findings;
    }

    private IHttpRequestResponse safeReplay(IHttpRequestResponse req, UserSession session) {
        try { return mtester.replayAs(req, session); } catch (Exception e) { return null; }
    }

    /** Send a raw request as-is (used for the anonymous public probe — no session at all). */
    private IHttpRequestResponse safeSend(byte[] request, IHttpService service) {
        try { return callbacks.makeHttpRequest(service, request); } catch (Exception e) { return null; }
    }

    /** Build the same request with the object id replaced by a definitely-invalid value. */
    private byte[] withInvalidId(AccessModel.OwnedObject o) {
        try {
            byte[] req = o.request.getRequest();
            IRequestInfo ri = helpers.analyzeRequest(req);
            if ("param".equals(o.location)) {
                for (IParameter p : ri.getParameters()) {
                    if (!p.getName().equals(o.param)) continue;
                    byte pt = p.getType();
                    if (pt == IParameter.PARAM_URL || pt == IParameter.PARAM_BODY || pt == IParameter.PARAM_COOKIE) {
                        return helpers.updateParameter(req, helpers.buildParameter(o.param, INVALID_ID, pt));
                    }
                    // JSON/XML/multipart body ids (e.g. {"customerId":123}): Burp's updateParameter throws
                    // "Action is not supported for this parameter type", so splice INVALID_ID into the value
                    // range instead. Without this, body-id BOLA had NO negative control and a weaker verdict.
                    byte[] spliced = spliceValue(req, p, INVALID_ID);
                    if (spliced != null) return spliced;
                }
                return null;
            }
            // path
            List<String> headers = ri.getHeaders();
            if (headers.isEmpty()) return null;
            String[] parts = headers.get(0).split(" ");
            if (parts.length < 2) return null;
            String path = parts[1];
            String replaced = path.replaceFirst("/" + Pattern.quote(o.id) + "(/|$|\\?)", "/" + INVALID_ID + "$1");
            if (replaced.equals(path)) return null;
            parts[1] = replaced;
            headers.set(0, String.join(" ", parts));
            byte[] body = Arrays.copyOfRange(req, ri.getBodyOffset(), req.length);
            return helpers.buildHttpMessage(headers, body);
        } catch (Exception e) {
            return null;
        }
    }

    /** Splice a replacement value into a parameter's value range (for JSON/XML/multipart body ids that
     *  Burp's updateParameter rejects). Rebuilds via buildHttpMessage so Content-Length stays correct. */
    private byte[] spliceValue(byte[] req, IParameter p, String value) {
        try {
            int s = p.getValueStart(), e = p.getValueEnd();
            if (s < 0 || e < s || e > req.length) return null;
            byte[] pay = value.getBytes("UTF-8");
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            bos.write(req, 0, s);
            bos.write(pay, 0, pay.length);
            bos.write(req, e, req.length - e);
            byte[] spliced = bos.toByteArray();
            IRequestInfo si = helpers.analyzeRequest(spliced);
            byte[] body = Arrays.copyOfRange(spliced, si.getBodyOffset(), spliced.length);
            return helpers.buildHttpMessage(si.getHeaders(), body);
        } catch (Exception e) {
            return null;
        }
    }

    /** Path of a request, or "" — for benign/pre-auth skipping. */
    private String pathOf(IHttpRequestResponse h) {
        try { return helpers.analyzeRequest(h).getUrl().getPath(); } catch (Exception e) { return ""; }
    }

    /** Normalize a body for comparison: lower-case + strip whitespace only. We KEEP digits — for financial
     *  / PII objects the distinguishing data (account no, IBAN, balance, the id itself) is numeric, and
     *  stripping it would make a real cross-owner body look identical to the attacker's own object. */
    private String norm(String s) {
        return s == null ? "" : s.toLowerCase().replaceAll("\\s+", "");
    }

    private void note(Finding f, String n) {
        String ex = (f.getExploitation() == null || f.getExploitation().isEmpty()) ? "" : f.getExploitation() + "\n";
        f.setExploitation(ex + n);
    }

    private boolean isGet(IHttpRequestResponse h) {
        try { return "GET".equalsIgnoreCase(helpers.analyzeRequest(h).getMethod()); }
        catch (Exception e) { return false; }
    }

    private String methodOf(IHttpRequestResponse h) {
        try { return helpers.analyzeRequest(h).getMethod(); } catch (Exception e) { return ""; }
    }

    private String reqLine(IHttpRequestResponse h) {
        try {
            IRequestInfo ri = helpers.analyzeRequest(h);
            return ri.getMethod() + " " + ri.getUrl().getPath();
        } catch (Exception e) { return "?"; }
    }

    private int statusOf(IHttpRequestResponse m) {
        try { return (m == null || m.getResponse() == null) ? 0 : helpers.analyzeResponse(m.getResponse()).getStatusCode(); }
        catch (Exception e) { return 0; }
    }

    private String bodyOf(IHttpRequestResponse m) {
        return m == null ? "" : bodyBytes(m.getResponse());
    }

    private String bodyBytes(byte[] resp) {
        try {
            if (resp == null) return "";
            int off = helpers.analyzeResponse(resp).getBodyOffset();
            return new String(resp, off, Math.min(2048, Math.max(0, resp.length - off)), "UTF-8");
        } catch (Exception e) {
            return "";
        }
    }
}

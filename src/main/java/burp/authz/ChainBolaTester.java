package burp.authz;

import burp.Finding;
import burp.i18n.I18n;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.MultiSessionTester;
import burp.MultiSessionTester.UserSession;
import burp.AiApiClient;
import burp.ai.AIFalsePositiveFilter;
import burp.scan.EndpointKey;
import burp.scan.JsonIds;
import burp.scan.Signals;
import burp.engine.DetectionStage;
import burp.engine.SharedRateLimiter;
import burp.engine.StageListener;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Multi-step chained BOLA (slice 1: two-step, name-anchored provenance).
 *
 * <p>Single-step {@link ScenarioAccessTester} replays the SAME endpoint that captured an object. Real
 * banking/API leaks often need a CHAIN: a value produced by one endpoint's RESPONSE flows into a
 * DIFFERENT endpoint's REQUEST. Non-sequential ids (CustomerId, AccountNumber, IBAN, GUID) can't be
 * reached by neighbour-walking — but a producer endpoint hands us a REAL valid id, which we then feed
 * to a consumer endpoint as ANOTHER identity to test cross-owner enforcement.
 *
 * <p>Provenance is NAME-ANCHORED: a value emitted under id-name {@code N} in some response is a chain
 * candidate for any request that carries an id parameter/field also named {@code N} at a DIFFERENT
 * endpoint. This avoids spurious "a random number equals another random number" matches.
 *
 * <p>Per chain: inject the producer value into the consumer request, replay as attacker B, and judge
 * with the same ground-truth machinery as {@link ScenarioAccessTester} — a negative control (invalid
 * id) proves the id is honoured, and {@link OwnershipOracle} + the AI adjudicator require FOREIGN owner
 * data (absent from B's own view and the control). Read-only by default; a non-GET consumer runs only
 * when {@code includeMutating} (test-environment affirmed), mirroring the single-step tester.
 *
 * @author Zahid Eroglu
 */
public class ChainBolaTester {

    private static final String INVALID_ID = "2147483646";
    private static final int MAX_CHAINS = 16;          // bound total chain executions (volume/throttle; gateway IP-ban)
    private static final int MAX_ATTACKERS = 2;        // attacker identities tried per chain
    private static final int MAX_VALUES_PER_NAME = 2;  // producer values tried per id-name
    private static final int MAX_LIVE_PRODUCERS = 8;   // bound LIVE producer executions (slice 2)

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final MultiSessionTester mtester;
    private final AiApiClient aiClient;
    private final SharedRateLimiter limiter;
    private final PrintWriter stdout, stderr;
    private final AccessOracle oracle;

    public ChainBolaTester(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                           MultiSessionTester mtester, AiApiClient aiClient, SharedRateLimiter limiter,
                           PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.mtester = mtester;
        this.aiClient = aiClient;
        this.limiter = limiter;
        this.stdout = stdout;
        this.stderr = stderr;
        this.oracle = new AccessOracle(helpers);
    }

    /** A real id value emitted under {@code name} by endpoint {@code producerEpKey}. {@code ownerRole} is
     *  non-null when the value was freshly produced LIVE as that identity (slice 2), so the consumer step
     *  must NOT run as that same identity — otherwise it is the caller's own data, not cross-owner. */
    private static final class Produced {
        final String name, value, producerEpKey, ownerRole;
        Produced(String name, String value, String producerEpKey, String ownerRole) {
            this.name = name; this.value = value; this.producerEpKey = producerEpKey; this.ownerRole = ownerRole;
        }
    }

    /** An id-injection point in a consumer request. */
    private static final class Inject {
        final IHttpRequestResponse req;
        final String epKey, name, location; // location: "param" | "json"
        final IParameter param;             // for "param"
        final int jsonStart, jsonEnd;       // byte range for "json"
        final String currentValue;
        Inject(IHttpRequestResponse req, String epKey, String name, String location,
               IParameter param, int jsonStart, int jsonEnd, String currentValue) {
            this.req = req; this.epKey = epKey; this.name = name; this.location = location;
            this.param = param; this.jsonStart = jsonStart; this.jsonEnd = jsonEnd; this.currentValue = currentValue;
        }
    }

    public List<Finding> run(List<IHttpRequestResponse> candidateEndpoints, List<UserSession> attackerSessions,
                             String host, boolean includeMutating, StageListener l) {
        List<Finding> findings = new ArrayList<>();
        if (candidateEndpoints == null || candidateEndpoints.isEmpty()
                || attackerSessions == null || attackerSessions.isEmpty() || host == null) return findings;

        // 1) Consumers: every id-named injection point in the candidate requests.
        List<Inject> consumers = indexConsumers(candidateEndpoints);
        if (consumers.isEmpty()) return findings;
        Set<String> names = new LinkedHashSet<>();
        for (Inject c : consumers) names.add(c.name);

        AIFalsePositiveFilter ai = (aiClient != null)
                ? new AIFalsePositiveFilter(aiClient, helpers, stdout, stderr) : null;
        List<UserSession> attackers = attackerSessions.size() > MAX_ATTACKERS
                ? attackerSessions.subList(0, MAX_ATTACKERS) : attackerSessions;

        // 2) Producer values for those names: (a) STATIC — real ids the app already emitted in history;
        //    (b) LIVE (slice 2) — run a producer endpoint as identity A NOW to get a FRESH id owned by A
        //    (handles stale/expiring ids; the genuine executed chain). Live values are prerequisite-gated:
        //    the producer must return 2xx AND actually yield the value.
        Map<String, List<Produced>> produced = mineProducerValues(host, names);
        addLiveProducerValues(produced, candidateEndpoints, host, names, attackers, includeMutating, l);
        if (produced.isEmpty()) {
            if (l != null) l.onStageProgress(DetectionStage.EXECUTE,
                    "Zincir-BOLA: id-üreten uç bulunamadı — atlandı");
            return findings;
        }

        Set<String> chainSeen = new LinkedHashSet<>();
        int chains = 0;
        for (Inject c : consumers) {
            if (chains >= MAX_CHAINS) {
                if (l != null) l.onStageProgress(DetectionStage.EXECUTE,
                        "Zincir-BOLA sınırı (" + MAX_CHAINS + ") — kalanlar atlandı");
                break;
            }
            if (!includeMutating && !isGet(c.req)) continue;      // read-only unless test-env affirmed
            if (oracle.isBenignPath(pathOf(c.req))) continue;     // login/captcha/token/health… not a target
            List<Produced> vals = produced.get(c.name);
            if (vals == null) continue;                            // no producer for this consumer's id-name
            int tried = 0;
            for (Produced p : vals) {
                if (tried >= MAX_VALUES_PER_NAME || chains >= MAX_CHAINS) break;
                if (p.producerEpKey.equals(c.epKey)) continue;    // same endpoint = single-step, not a chain
                if (p.value.equals(c.currentValue)) continue;     // injecting the current value proves nothing
                if (!chainSeen.add(p.producerEpKey + "»" + c.epKey + "|" + c.name)) continue; // dedup template
                tried++;
                chains++;                                          // count the attempt (bound a dead app)
                Finding f = testOneChain(c, p, attackers, includeMutating, ai, l);
                if (f != null) findings.add(f);
            }
        }
        if (l != null) l.onStageProgress(DetectionStage.EXECUTE,
                "Zincir-BOLA: " + chains + " zincir denendi · " + findings.size() + " bulgu");
        return findings;
    }

    /** Execute one producer→consumer chain against each attacker until one confirms (or all fail). */
    private Finding testOneChain(Inject c, Produced p, List<UserSession> attackers, boolean includeMutating,
                                 AIFalsePositiveFilter ai, StageListener l) {
        byte[] injected = injectValue(c, p.value);
        if (injected == null) return null;
        byte[] invalid = injectValue(c, INVALID_ID);

        for (UserSession b : attackers) {
            // A LIVE-produced value is owned by its producer identity — consuming it as that same identity is
            // the caller's own data, not cross-owner. Skip it (static/history values have ownerRole=null and
            // are allowed for any attacker; the foreign-token judge decides ownership there).
            if (p.ownerRole != null && p.ownerRole.equalsIgnoreCase(b.roleName)) continue;
            // Manipulated: consumer endpoint carrying the PRODUCER's id, sent as attacker B.
            IHttpRequestResponse manip = send(injected, c.req, b);
            if (manip == null || oracle.verdict(manip.getResponse()) != AuthMatrix.Verdict.GRANTED) continue;
            String manipBody = bodyOf(manip);
            String manipCt = ctOf(manip);
            if (Signals.isImageOrMediaType(manipCt) || Signals.looksLikeBlockPage(manipBody)) continue;

            // Baseline: same consumer as B, UNCHANGED (B's own view of this endpoint).
            IHttpRequestResponse baseResp = send(c.req.getRequest(), c.req, b);
            String baseBody = bodyOf(baseResp);
            // Negative control: consumer with a definitely-invalid id, as B (proves the id is honoured).
            IHttpRequestResponse negResp = (invalid == null) ? null : send(invalid, c.req, b);
            String negBody = bodyOf(negResp);

            if (norm(manipBody).isEmpty()) continue;
            if (norm(manipBody).equals(norm(negBody)) || norm(manipBody).equals(norm(baseBody))) continue;

            // Positive cross-owner proof: owner-identity tokens in the manipulated body absent from B's own
            // view AND the control. The injected id itself is our value — never evidence — so drop it. Header
            // owner-ids (X-User-Id/X-Account-Id…) in the manipulated response absent from B's own also count.
            Set<String> foreign = OwnershipOracle.foreignOwnerTokens(manipBody, baseBody, negBody);
            foreign.remove(p.value.toLowerCase(Locale.ROOT));
            foreign.addAll(OwnershipOracle.foreignOwnerHeaderTokens(hdrsOf(manip), hdrsOf(baseResp)));
            if (foreign.isEmpty()) continue;

            String producerEp = p.producerEpKey, consumerEp = c.epKey;
            Finding f = new Finding("BOLA (Chain)", "High", 0.9,
                    I18n.t("f.sat.bola.desc", b.roleName, c.name + "=" + p.value, "producer:" + producerEp),
                    "", I18n.t("f.sat.bola.ev", b.roleName, "producer:" + producerEp,
                            c.name + "=" + p.value, reqLine(c.req)),
                    I18n.t("f.sat.bola.exp"), I18n.t("f.sat.bola.rem"));
            f.setHttpResponse(manipBody);
            if (!negBody.isEmpty()) f.setControlResponse(negBody);
            f.setOracleVerdict(Finding.OracleVerdict.CONFIRMED);
            note(f, "Zincir: '" + producerEp + "' ucundan üretilen " + c.name + "=" + p.value
                    + " değeri, '" + consumerEp + "' ucuna '" + b.roleName
                    + "' kimliğiyle enjekte edildi; başka sahibin verisi döndü (" + sample(foreign) + ").");

            if (ai != null) {
                String manipulation = "chain: produced " + c.name + "=" + p.value + " at " + producerEp
                        + " → injected into " + consumerEp + " as '" + b.roleName + "'";
                AIFalsePositiveFilter.ValidationResult r = ai.judgeAccessControlConsensus(
                        "BOLA (Chain)", manipulation, baseBody, manipBody, negBody, null);
                String why = (r.reasoning == null) ? "" : r.reasoning;
                if (!r.verificationUnavailable && !r.isValidVulnerability) {
                    f.setFalsePositive(true);
                    f.setOracleVerdict(Finding.OracleVerdict.REFUTED);
                    if (r.confidence > 0) f.setConfidence(Math.min(f.getConfidence(), r.confidence));
                    note(f, "AI: olası FALSE POSITIVE — " + why);
                } else if (r.verificationUnavailable) {
                    note(f, "AI doğrulanamadı — zincir deterministik (çapraz-sahip) kanıta dayanıyor, işaretlendi.");
                } else {
                    if (r.confidence > 0) f.setConfidence(Math.max(f.getConfidence(), r.confidence));
                    note(f, "AI doğrulaması (zincir BOLA): " + why);
                }
            }
            if (l != null) l.onStageProgress(DetectionStage.EXECUTE,
                    "Zincir BOLA: " + producerEp + " → " + consumerEp + " (" + c.name + ") as " + b.roleName
                            + " (" + (f.isFalsePositive() ? "FP" : "HIT") + ")");
            return f;
        }
        return null;
    }

    // ---- producer mining (proxy-history responses) --------------------------------------------------

    /** Mine real id values the app emitted (from the host's proxy-history JSON responses) under id-names
     *  that a consumer actually carries ({@code names}). Static values → {@code ownerRole=null}. */
    private Map<String, List<Produced>> mineProducerValues(String host, Set<String> names) {
        Map<String, List<Produced>> out = new LinkedHashMap<>();
        IHttpRequestResponse[] hist = callbacks.getProxyHistory();
        if (hist == null) return out;
        for (IHttpRequestResponse h : hist) {
            try {
                if (h == null || h.getResponse() == null) continue;
                IRequestInfo ri = helpers.analyzeRequest(h);
                if (!host.equalsIgnoreCase(ri.getUrl().getHost())) continue;
                if (helpers.analyzeResponse(h.getResponse()).getStatusCode() / 100 != 2) continue;
                String epKey = EndpointKey.of(ri.getMethod(), ri.getUrl().getPath());
                String body = bodyBytes(h.getResponse());
                if (body.isEmpty() || (body.indexOf('{') < 0 && body.indexOf('[') < 0)) continue;
                for (JsonIds.Hit hit : JsonIds.extract(body)) {
                    if (hit.name == null || hit.value == null) continue;
                    String name = hit.name.toLowerCase(Locale.ROOT);
                    if (!names.contains(name)) continue;          // only names a consumer carries
                    String v = hit.value.trim();
                    if (v.length() < 2 || isBoring(v)) continue;
                    List<Produced> l = out.get(name);
                    if (l == null) { l = new ArrayList<>(); out.put(name, l); }
                    if (l.size() < 8 && !containsValue(l, v)) l.add(new Produced(name, v, epKey, null));
                }
            } catch (Exception ignore) {
                // best-effort per history item
            }
        }
        return out;
    }

    private boolean containsValue(List<Produced> l, String v) {
        for (Produced p : l) if (p.value.equals(v)) return true;
        return false;
    }

    // ---- LIVE producer execution (slice 2) ----------------------------------------------------------

    /** Producer ENDPOINTS whose response emits an id under one of {@code names} (candidate requests +
     *  proxy history for the host), deduped by name+endpoint-template, capped per name. */
    private Map<String, List<IHttpRequestResponse>> indexProducerEndpoints(
            List<IHttpRequestResponse> endpoints, String host, Set<String> names) {
        Map<String, List<IHttpRequestResponse>> out = new LinkedHashMap<>();
        Set<String> epSeen = new LinkedHashSet<>();
        List<IHttpRequestResponse> pool = new ArrayList<>(endpoints);
        IHttpRequestResponse[] hist = callbacks.getProxyHistory();
        if (hist != null) pool.addAll(Arrays.asList(hist));
        for (IHttpRequestResponse h : pool) {
            try {
                if (h == null || h.getRequest() == null || h.getResponse() == null) continue;
                IRequestInfo ri = helpers.analyzeRequest(h);
                if (!host.equalsIgnoreCase(ri.getUrl().getHost())) continue;
                String epKey = EndpointKey.of(ri.getMethod(), ri.getUrl().getPath());
                String body = bodyBytes(h.getResponse());
                if (body.isEmpty()) continue;
                for (JsonIds.Hit hit : JsonIds.extract(body)) {
                    String n = hit.name == null ? "" : hit.name.toLowerCase(Locale.ROOT);
                    if (!names.contains(n)) continue;
                    if (!epSeen.add(n + "|" + epKey)) continue;
                    List<IHttpRequestResponse> l = out.get(n);
                    if (l == null) { l = new ArrayList<>(); out.put(n, l); }
                    if (l.size() < 3) l.add(h);
                }
            } catch (Exception ignore) {
                // best-effort per item
            }
        }
        return out;
    }

    /** Run producer endpoints LIVE as the first attacker to obtain FRESH ids owned by that identity, and add
     *  them to {@code produced} (ownerRole set). Prerequisite-gated (2xx + value present); mutating (non-GET)
     *  producers run only when {@code includeMutating}. Bounded by {@link #MAX_LIVE_PRODUCERS}. Needs ≥2
     *  attackers so the consumer can run as a DIFFERENT identity than the producer. */
    private void addLiveProducerValues(Map<String, List<Produced>> produced,
                                       List<IHttpRequestResponse> candidateEndpoints, String host,
                                       Set<String> names, List<UserSession> attackers,
                                       boolean includeMutating, StageListener l) {
        if (attackers.size() < 2) return;
        UserSession a = attackers.get(0);
        Map<String, List<IHttpRequestResponse>> producerEps = indexProducerEndpoints(candidateEndpoints, host, names);
        int ran = 0;
        for (Map.Entry<String, List<IHttpRequestResponse>> e : producerEps.entrySet()) {
            String name = e.getKey();
            for (IHttpRequestResponse p : e.getValue()) {
                if (ran >= MAX_LIVE_PRODUCERS) return;
                if (!includeMutating && !isGet(p)) continue;      // a create/POST producer is state-changing
                if (oracle.isBenignPath(pathOf(p))) continue;
                ran++;
                String v = runProducerLive(p, a, name);           // prerequisite-gated fresh value
                if (v == null) continue;
                String epKey = reqEpKey(p);
                List<Produced> list = produced.get(name);
                if (list == null) { list = new ArrayList<>(); produced.put(name, list); }
                if (!containsValue(list, v)) list.add(new Produced(name, v, epKey, a.roleName));
                if (l != null) l.onStageProgress(DetectionStage.EXECUTE,
                        "Zincir producer (canlı): " + epKey + " → " + name + "=" + v + " (" + a.roleName + ")");
            }
        }
    }

    /** Run a producer endpoint as {@code a}; return the FRESH value of {@code name} from its 2xx response,
     *  or null when the prerequisite fails (not 2xx, or the value is absent). */
    private String runProducerLive(IHttpRequestResponse producer, UserSession a, String name) {
        IHttpRequestResponse resp = send(producer.getRequest(), producer, a);
        if (resp == null || resp.getResponse() == null) return null;
        try {
            if (helpers.analyzeResponse(resp.getResponse()).getStatusCode() / 100 != 2) return null;
        } catch (Exception e) { return null; }
        for (JsonIds.Hit hit : JsonIds.extract(bodyOf(resp))) {
            if (hit.name != null && hit.name.equalsIgnoreCase(name) && hit.value != null) {
                String v = hit.value.trim();
                if (v.length() >= 2 && !isBoring(v)) return v;
            }
        }
        return null;
    }

    private String reqEpKey(IHttpRequestResponse h) {
        try {
            IRequestInfo ri = helpers.analyzeRequest(h);
            return EndpointKey.of(ri.getMethod(), ri.getUrl().getPath());
        } catch (Exception e) { return "?"; }
    }

    // ---- consumer indexing --------------------------------------------------------------------------

    /** Injection points (named id params + JSON id fields) in candidate requests. */
    private List<Inject> indexConsumers(List<IHttpRequestResponse> endpoints) {
        List<Inject> out = new ArrayList<>();
        Set<String> epNameSeen = new LinkedHashSet<>();
        for (IHttpRequestResponse ep : endpoints) {
            if (ep == null || ep.getRequest() == null) continue;
            try {
                IRequestInfo ri = helpers.analyzeRequest(ep);
                String epKey = EndpointKey.of(ri.getMethod(), ri.getUrl().getPath());
                // URL / BODY id params.
                for (IParameter p : ri.getParameters()) {
                    byte t = p.getType();
                    if (t != IParameter.PARAM_URL && t != IParameter.PARAM_BODY) continue;
                    String n = p.getName().toLowerCase(Locale.ROOT);
                    if (!isIdName(p.getName())) continue;
                    if (epNameSeen.add(epKey + "|param|" + n))
                        out.add(new Inject(ep, epKey, n, "param", p, -1, -1, p.getValue()));
                }
                // JSON body id fields (Burp's flat IParameter model misses nested/array ids).
                String ct = contentTypeOfReq(ri);
                if (ct.contains("json")) {
                    int bodyOff = ri.getBodyOffset();
                    byte[] req = ep.getRequest();
                    String body = new String(req, bodyOff, req.length - bodyOff, "UTF-8");
                    for (JsonIds.Hit hit : JsonIds.extract(body)) {
                        String n = hit.name.toLowerCase(Locale.ROOT);
                        if (!isIdName(hit.name)) continue;
                        int start = bodyOff + body.substring(0, hit.valueStart).getBytes("UTF-8").length;
                        int end = bodyOff + body.substring(0, hit.valueEnd).getBytes("UTF-8").length;
                        if (epNameSeen.add(epKey + "|json|" + n + "@" + hit.valueStart))
                            out.add(new Inject(ep, epKey, n, "json", null, start, end, hit.value));
                    }
                }
            } catch (Exception ignore) {
                // best-effort per endpoint
            }
        }
        return out;
    }

    // ---- request building / sending -----------------------------------------------------------------

    /** Build the consumer request with {@code value} injected at the injection point. */
    private byte[] injectValue(Inject c, String value) {
        try {
            byte[] req = c.req.getRequest();
            if ("param".equals(c.location)) {
                return helpers.updateParameter(req, helpers.buildParameter(c.param.getName(), value, c.param.getType()));
            }
            return spliceBytes(req, c.jsonStart, c.jsonEnd, value); // json id value range
        } catch (Exception e) {
            return null;
        }
    }

    /** Splice {@code value} over [start,end) of {@code req}, rebuilding so Content-Length stays correct. */
    private byte[] spliceBytes(byte[] req, int start, int end, String value) {
        try {
            if (start < 0 || end < start || end > req.length) return null;
            byte[] pay = value.getBytes("UTF-8");
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            bos.write(req, 0, start);
            bos.write(pay, 0, pay.length);
            bos.write(req, end, req.length - end);
            byte[] spliced = bos.toByteArray();
            IRequestInfo si = helpers.analyzeRequest(spliced);
            byte[] body = Arrays.copyOfRange(spliced, si.getBodyOffset(), spliced.length);
            return helpers.buildHttpMessage(si.getHeaders(), body);
        } catch (Exception e) {
            return null;
        }
    }

    /** Apply attacker session {@code b} to {@code request} and send it (rate-limited). */
    private IHttpRequestResponse send(byte[] request, IHttpRequestResponse template, UserSession b) {
        try {
            if (request == null) return null;
            byte[] applied = mtester.applySession(request, b);
            if (applied == null) applied = request;
            if (limiter != null) limiter.acquire();
            return callbacks.makeHttpRequest(template.getHttpService(), applied);
        } catch (Exception e) {
            return null;
        }
    }

    // ---- helpers ------------------------------------------------------------------------------------

    private static final Set<String> EXTRA_ID_NAMES = new LinkedHashSet<>(Arrays.asList(
            "id", "uid", "userid", "user_id", "accountid", "account_id", "accountno", "account_no",
            "customerid", "customer_id", "customerno", "orderid", "order_id", "invoiceid", "cardid",
            "personid", "subscriberid", "iban", "msisdn", "recordid", "objectid", "ref", "reference"));

    /** True when a field/param NAME looks like an object identifier (mirrors IdorModule.isIdName). */
    private boolean isIdName(String name) {
        if (name == null) return false;
        String n = name.toLowerCase(Locale.ROOT);
        return EXTRA_ID_NAMES.contains(n) || n.endsWith("id") || n.endsWith("_id")
                || OwnershipOracle.isAccountOwnershipParam(n);
    }

    private boolean isBoring(String v) {
        String lv = v.toLowerCase(Locale.ROOT);
        return lv.equals("null") || lv.equals("true") || lv.equals("false") || lv.equals("0")
                || lv.equals("-1") || lv.equals("undefined") || lv.equals("string") || lv.equals("n/a");
    }

    private String sample(Set<String> tokens) {
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (String t : tokens) {
            if (n++ >= 3) { sb.append("…"); break; }
            if (sb.length() > 0) sb.append(", ");
            sb.append(t.length() > 40 ? t.substring(0, 40) + "…" : t);
        }
        return sb.toString();
    }

    private String contentTypeOfReq(IRequestInfo ri) {
        for (String h : ri.getHeaders()) {
            String l = h.toLowerCase(Locale.ROOT);
            if (l.startsWith("content-type:")) return l.substring(13).trim();
        }
        return "";
    }

    private String ctOf(IHttpRequestResponse m) {
        try {
            return m == null || m.getResponse() == null ? "" : Signals.contentTypeOf(hdrsOf(m));
        } catch (Exception e) { return ""; }
    }

    private String hdrsOf(IHttpRequestResponse m) {
        try {
            return m == null || m.getResponse() == null ? ""
                    : String.join("\n", helpers.analyzeResponse(m.getResponse()).getHeaders());
        } catch (Exception e) { return ""; }
    }

    private boolean isGet(IHttpRequestResponse h) {
        try { return "GET".equalsIgnoreCase(helpers.analyzeRequest(h).getMethod()); }
        catch (Exception e) { return false; }
    }

    private String pathOf(IHttpRequestResponse h) {
        try { return helpers.analyzeRequest(h).getUrl().getPath(); } catch (Exception e) { return ""; }
    }

    private String reqLine(IHttpRequestResponse h) {
        try {
            IRequestInfo ri = helpers.analyzeRequest(h);
            return ri.getMethod() + " " + ri.getUrl().getPath();
        } catch (Exception e) { return "?"; }
    }

    private String norm(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT).replaceAll("\\s+", "");
    }

    private void note(Finding f, String n) {
        String ex = (f.getExploitation() == null || f.getExploitation().isEmpty()) ? "" : f.getExploitation() + "\n";
        f.setExploitation(ex + n);
    }

    private String bodyOf(IHttpRequestResponse m) {
        return m == null ? "" : bodyBytes(m.getResponse());
    }

    private String bodyBytes(byte[] resp) {
        try {
            if (resp == null) return "";
            int off = helpers.analyzeResponse(resp).getBodyOffset();
            return new String(resp, off, Math.min(4096, Math.max(0, resp.length - off)), "UTF-8");
        } catch (Exception e) {
            return "";
        }
    }
}

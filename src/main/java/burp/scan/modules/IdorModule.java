package burp.scan.modules;

import burp.Finding;
import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IRequestInfo;
import burp.Settings;
import burp.authz.OwnershipOracle;
import burp.i18n.I18n;
import burp.scan.Baseline;
import burp.scan.Probe;
import burp.scan.ProbeResult;
import burp.scan.ScanModule;
import burp.scan.Signals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A01 Broken Access Control - IDOR (single-session). Swaps numeric IDs in the URL
 * path and in id-like parameters, then decides with {@link OwnershipOracle} instead
 * of the old "differs from the invalid-id control ⇒ High" rule, which over-reported.
 *
 * Per swapped id it also sends an ANONYMOUS (auth-stripped) clone of the SAME request
 * — the "public probe". The oracle then:
 *   • drops it as FP_PUBLIC when the anonymous caller sees the same body (a shop product /
 *     public page everyone legitimately sees);
 *   • drops it as FP_OWN_DATA when the body equals the caller's own object or the invalid-id
 *     control (the endpoint ignores the id / scopes it to the session — "still my own data");
 *   • emits a finding ONLY when the swapped body carries FOREIGN owner-identity tokens (an
 *     email / IBAN / account-no / user field) absent from every reference — positive evidence
 *     that another principal's object was returned. The AI then confirms/refutes it.
 *
 * A single session can never PROVE cross-owner access (it has no second user), so genuinely
 * ambiguous "distinct but no foreign tokens" cases are deferred to the ground-truth BOLA pass
 * ({@link burp.authz.ScenarioAccessTester}) rather than reported as a guess.
 *
 * @author Zahid Eroglu
 */
public class IdorModule implements ScanModule {

    private static final Pattern NUM = Pattern.compile("^\\d{1,12}$");
    private static final Set<String> ID_NAMES = new HashSet<>(Arrays.asList(
            "id", "user", "userid", "user_id", "uid", "account", "accountid", "account_id",
            "order", "orderid", "order_id", "doc", "docid", "file", "fileid", "pid",
            "customer", "customerid", "customer_id", "customerno", "accountno", "account_no",
            "invoice", "invoiceid", "number", "record", "recordid", "objectid", "object_id",
            // broadened object-id names (request body identifiers, not just URL): resources + banking/PII
            "uuid", "guid", "ref", "refid", "reference", "slug", "key", "cart", "cartid", "product",
            "productid", "item", "itemid", "ticket", "ticketid", "project", "projectid", "group",
            "groupid", "message", "messageid", "contract", "contractid", "subscription", "subscriptionid",
            "transaction", "transactionid", "txn", "payment", "paymentid", "payee", "beneficiary",
            "card", "cardid", "cardno", "iban", "msisdn", "subscriber", "subscriberid"));

    private static final String INVALID_ID = "2147483646"; // negative control: a definitely-invalid id

    public String id() { return "idor"; }
    public String displayName() { return "IDOR / Object Access"; }
    public boolean isEnabled(Settings s) { return s.isModuleIdorEnabled(); }

    // Endpoints that serve PUBLIC, non-owned content keyed by an id (charts/graphics/images/market
    // data, thumbnails, avatars, banners). A different id returning a different-sized body is EXPECTED
    // there (a different chart/image), not unauthorized object access. Skip them — this was the
    // "/api/Generic/Graphic?FECBid=1..25 -> different sizes" IDOR false positive (public FX charts).
    private static final Pattern PUBLIC_OBJECT_PATH = Pattern.compile(
            "(graphic|chart|image|img|thumb|avatar|banner|photo|picture|icon|logo|map|tile|render|"
            + "captcha|qr|barcode|sprite)", Pattern.CASE_INSENSITIVE);

    public boolean appliesTo(Baseline b) {
        if (b.statusCode != 200) return false; // need a valid baseline object
        if (b.path != null && PUBLIC_OBJECT_PATH.matcher(b.path).find()) return false; // public graphic/media, not an owned object
        if (b.responseIsImageMedia()) return false;                                     // image/media (chart/avatar) = public, not an owned object
        if (!numericPathSegments(b.path).isEmpty()) return true;
        for (IParameter p : b.parameters) {
            if (isIdParam(p)) return true;
        }
        if (jsonHasId(b)) return true; // nested/array JSON ids Burp's flat IParameter model misses
        return false;
    }

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> probes = new ArrayList<>();
        Set<String> negDone = new HashSet<>();
        for (String seg : numericPathSegments(b.path)) {
            long v = parseLong(seg);
            String rep = String.valueOf(v + 1);            // representative neighbour id
            addPath(probes, b, seg, rep);
            addPath(probes, b, seg, String.valueOf(Math.max(0, v - 1)));
            addPath(probes, b, seg, "1");
            if (negDone.add("path|" + seg)) {
                addNegPath(probes, b, seg);                // negative control
                addPublicProbe(probes, b, "path", seg, null, rep); // anonymous public probe
            }
        }
        for (IParameter p : b.parameters) {
            if (p.getType() == IParameter.PARAM_JSON) continue; // nested/array JSON ids handled by addJsonIdProbes
            if (!isIdParam(p)) continue;
            String val = p.getValue();
            String rep;
            if (val != null && NUM.matcher(val).matches() && !looksLikeEpoch(val)) {
                long v = parseLong(val);
                rep = String.valueOf(v + 1);
                addParam(probes, p.getName(), rep);
                addParam(probes, p.getName(), "1");
            } else {
                rep = "1";
                addParam(probes, p.getName(), "1");
            }
            if (negDone.add("param|" + p.getName())) {
                addNegParam(probes, p.getName());          // negative control
                addPublicProbe(probes, b, "param", p.getName(), p, rep); // anonymous public probe
            }
        }
        addJsonIdProbes(probes, b, negDone);               // nested + array JSON ids (Burp's flat model misses)
        return probes;
    }

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> findings = new ArrayList<>();
        // Index results: negative controls (invalid id) by location|param, and live + public probes by
        // location|param|payload so each swapped id can be matched to its anonymous public twin.
        Map<String, String> negCtrl = new HashMap<>();
        Map<String, ProbeResult> live = new HashMap<>();
        Map<String, ProbeResult> pub = new HashMap<>();
        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok()) continue;
            String lp = r.probe.location + "|" + r.probe.targetParameter;
            String full = lp + "|" + r.probe.payload;
            if ("IDOR-NEG".equals(r.probe.attackType)) negCtrl.put(lp, r.bodySnippet);
            else if ("IDOR".equals(r.probe.attackType)) live.put(full, r);
            else if ("IDOR-PUB".equals(r.probe.attackType)) pub.put(full, r);
        }

        // A location is PUBLIC when an anonymous (auth-stripped) caller gets an equivalent 200 body for the
        // same id the authenticated caller did — the server serves it to everyone (a shop product, a public
        // page). Every swap on such a location is a public asset, not an owned object → suppress them all.
        // Block/login/error 200s (WAF pages, SPA shells) are NOT proof of publicness — skip those.
        Set<String> publicLocParam = new HashSet<>();
        for (Map.Entry<String, ProbeResult> e : pub.entrySet()) {
            ProbeResult pr = e.getValue();
            ProbeResult lr = live.get(e.getKey());
            if (lr == null || pr.statusCode != 200 || lr.statusCode != 200) continue;
            if (Signals.isImageOrMediaType(Signals.contentTypeOf(pr.responseHeaders))) continue;
            if (Signals.looksLikeBlockPage(pr.bodySnippet) || Signals.looksLikeBlockPage(lr.bodySnippet)) continue;
            if (OwnershipOracle.bodiesEquivalent(lr.bodySnippet, pr.bodySnippet)) {
                publicLocParam.add(pr.probe.location + "|" + pr.probe.targetParameter);
            }
        }

        // The caller's OWN object (the baseline id), taken from the same ~8KB-capped snippet window as the
        // probe response snippets so the length-ratio comparison in bodiesEquivalent stays apples-to-apples.
        String selfBaseline = (b.bodySnippet != null) ? b.bodySnippet : "";

        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok() || !"IDOR".equals(r.probe.attackType)) continue;
            if (r.statusCode != 200 || Signals.hasSqlError(r.bodySnippet)) continue;
            // Public image/media payload (chart/graphic/avatar) → different id = different public asset, not
            // IDOR. (A private PDF/binary keyed by id stays in scope — it can be a real object exposure.)
            if (Signals.isImageOrMediaType(Signals.contentTypeOf(r.responseHeaders))) continue;
            String lp = r.probe.location + "|" + r.probe.targetParameter;
            // Public/shared resource: anonymous caller sees the same content → not an owned object.
            if (publicLocParam.contains(lp)) continue;
            String ctrl = negCtrl.get(lp);
            // A negative control is REQUIRED: without proof the id is honoured a lone 200 is not evidence.
            if (ctrl == null) continue;

            // Per-result public check: this exact id served to an anonymous caller with an equivalent body.
            ProbeResult pr = pub.get(lp + "|" + r.probe.payload);
            String publicBody = null;
            if (pr != null && pr.statusCode == 200
                    && !Signals.isImageOrMediaType(Signals.contentTypeOf(pr.responseHeaders))
                    && !Signals.looksLikeBlockPage(pr.bodySnippet)) {
                publicBody = pr.bodySnippet;
                if (OwnershipOracle.bodiesEquivalent(r.bodySnippet, publicBody)) continue; // public/shared
            }

            // Positive cross-owner signal FIRST (it must win over a fuzzy own-data match): foreign owner
            // identity tokens (email / IBAN / labelled account-customer-user field) present in the swapped
            // body but ABSENT from our own object, the invalid-id control AND the public probe. The injected
            // id itself is echoed back by many endpoints — it is the value WE supplied, never evidence — so
            // it is removed before the decision.
            Set<String> foreign = OwnershipOracle.foreignOwnerTokens(
                    r.bodySnippet, selfBaseline, ctrl, publicBody);
            foreign.remove(r.probe.payload == null ? "" : r.probe.payload.toLowerCase());
            // Also treat an ownership-semantic RESPONSE HEADER (X-User-Id / X-Account-Id / X-Owner-Id /
            // X-Tenant-Id …) whose value is ABSENT from our own baseline headers as foreign-owner evidence —
            // some APIs return the owning principal in a header, not the body. The strict header-name
            // whitelist (no request/trace/correlation ids) is the FP guard; the injected id is removed so an
            // endpoint that merely echoes our swapped id in a header is not mistaken for a leak.
            String baseHdrs = (b.responseHeaders == null) ? "" : String.join("\n", b.responseHeaders);
            Set<String> foreignHdr = OwnershipOracle.foreignOwnerHeaderTokens(r.responseHeaders, baseHdrs);
            foreignHdr.remove(r.probe.payload == null ? "" : r.probe.payload.toLowerCase());
            foreign.addAll(foreignHdr);
            // No foreign owner data → it is our own data, an id-ignoring endpoint, or an unprovable distinct
            // object. A single session cannot prove cross-owner access, so we DON'T guess: drop it (the
            // ground-truth two-user BOLA pass is the place that can prove these).
            if (foreign.isEmpty()) continue; // suppress-unless-confirmed

            Finding f = new Finding("IDOR", "High", 0.55,
                    I18n.t("f.idor.idor.desc", r.probe.location, r.probe.targetParameter, r.probe.payload),
                    "", I18n.t("f.idor.idor.ev", r.probe.payload, r.responseLength, b.responseLength),
                    I18n.t("f.idor.idor.exp"),
                    I18n.t("f.idor.idor.rem"));
            f.setHttpResponse(r.bodySnippet);
            f.setControlResponse(ctrl);
            f.setExploitation(I18n.t("f.idor.foreign", sample(foreign)) + "\n" + f.getExploitation());
            // "Hesap Aitlik Kontrolü" framing: when the swapped field is an account/customer ownership
            // identifier, lead with the missing-ownership-check explanation so the report maps onto the spec.
            if ("param".equals(r.probe.location)
                    && OwnershipOracle.isAccountOwnershipParam(r.probe.targetParameter)) {
                f.setExploitation(I18n.t("f.idor.ownership", r.probe.targetParameter) + "\n" + f.getExploitation());
            }
            // Foreign owner tokens present, but a single session cannot PROVE ownership — defer the final
            // CONFIRM to the AI body comparison. If the AI is unavailable / does not confirm, this candidate
            // is suppressed downstream (suppress-unless-confirmed) rather than shown as a guess.
            f.setOracleVerdict(burp.Finding.OracleVerdict.INCONCLUSIVE);
            f.setNeedsAiConfirmation(true);
            findings.add(f);
        }
        return findings;
    }

    /** A short, readable sample (max 3) of the foreign owner tokens that triggered the finding. */
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

    /**
     * Live path-IDOR probe. Built as a {@code rawRequest} via {@link #replacePathSeg} (boundary-anchored,
     * first segment only) instead of the engine's default global {@code String.replace}, which corrupts a
     * path when the numeric id repeats or is a substring of another number (e.g. {@code /v2/orders/2} →
     * {@code /v3/orders/3}). This keeps the live request, the negative control and the public probe targeting
     * the SAME resource, which is what makes the public-resource comparison valid.
     */
    private void addPath(List<Probe> probes, Baseline b, String seg, String payload) {
        if (seg.equals(payload)) return;
        byte[] variant = pathVariant(b, seg, payload);
        // Skip entirely if we can't build the SAFE boundary-anchored request — do NOT fall back to the
        // engine's global String.replace, which corrupts repeated/substring ids (/v2/orders/2 → /v3/orders/3)
        // and would also leave the live probe inconsistent with the (always-anchored) public probe.
        if (variant == null) return;
        Probe p = new Probe(id(), "IDOR path " + seg + "→" + payload, "path", seg, payload, "IDOR", "High");
        p.rawRequest = variant;
        probes.add(p);
    }

    private void addParam(List<Probe> probes, String name, String payload) {
        probes.add(new Probe(id(), "IDOR param " + name + "→" + payload, "param", name, payload, "IDOR", "High"));
    }

    private void addNegPath(List<Probe> probes, Baseline b, String seg) {
        if (seg.equals(INVALID_ID)) return;
        byte[] variant = pathVariant(b, seg, INVALID_ID); // same boundary-anchored replacement as the live probe
        if (variant == null) return;                      // keep live/neg/public path probes consistent
        Probe p = new Probe(id(), "IDOR negctrl path " + seg + "→" + INVALID_ID, "path", seg, INVALID_ID, "IDOR-NEG", "Info");
        p.rawRequest = variant;
        probes.add(p);
    }

    private void addNegParam(List<Probe> probes, String name) {
        probes.add(new Probe(id(), "IDOR negctrl param " + name + "→" + INVALID_ID, "param", name, INVALID_ID, "IDOR-NEG", "Info"));
    }

    /**
     * Plan an ANONYMOUS clone of the swapped-id request (the "public probe"): the EXACT same swapped-id
     * request, but with every session credential stripped (and a browser User-Agent kept so the WAF does not
     * 403 it). If the server still returns the same body, the object is public/shared and must not be flagged
     * as IDOR. The swap is done first (so id offsets are valid), then the auth headers are stripped — this
     * also lets it cover JSON/XML body ids that {@code updateParameter} cannot. Sent via {@code rawRequest}.
     */
    private void addPublicProbe(List<Probe> probes, Baseline b, String location, String target,
                                IParameter param, String payload) {
        try {
            IExtensionHelpers helpers = b.helpers;
            byte[] base = (b.base != null) ? b.base.getRequest() : null;
            if (helpers == null || base == null) return;
            byte[] tampered = "param".equals(location)
                    ? spliceParamValue(helpers, base, param, payload)
                    : pathVariant(b, target, payload);
            if (tampered == null) return;
            byte[] anon = OwnershipOracle.stripAuthHeaders(helpers, tampered);
            if (anon == null) return;
            Probe pub = new Probe(id(), "IDOR pub " + location + " " + target + "→" + payload,
                    location, target, payload, "IDOR-PUB", "Info");
            pub.rawRequest = anon;
            probes.add(pub);
        } catch (Exception ignore) {
            // best-effort: no public probe for this location
        }
    }

    /** Build the request with the {@code seg} path segment replaced by {@code payload} (auth kept), or null. */
    private byte[] pathVariant(Baseline b, String seg, String payload) {
        if (b == null || b.helpers == null || b.base == null || b.base.getRequest() == null) return null;
        return replacePathSeg(b.helpers, b.base.getRequest(), seg, payload);
    }

    /** Replace the first {@code /seg} path segment with {@code payload}, keeping headers + body intact. */
    private byte[] replacePathSeg(IExtensionHelpers helpers, byte[] req, String seg, String payload) {
        try {
            IRequestInfo ri = helpers.analyzeRequest(req);
            List<String> headers = new ArrayList<>(ri.getHeaders());
            if (headers.isEmpty()) return null;
            String[] parts = headers.get(0).split(" ");
            if (parts.length < 2) return null;
            String path = parts[1];
            // quoteReplacement so a non-numeric payload containing $ or \ is treated literally (the live id
            // payloads are numeric today, but a future caller could pass an arbitrary value).
            String replaced = path.replaceFirst("/" + Pattern.quote(seg) + "(/|$|\\?)",
                    java.util.regex.Matcher.quoteReplacement("/" + payload) + "$1");
            if (replaced.equals(path)) return null;
            parts[1] = replaced;
            headers.set(0, String.join(" ", parts));
            byte[] body = Arrays.copyOfRange(req, ri.getBodyOffset(), req.length);
            return helpers.buildHttpMessage(headers, body);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Replace a parameter's value in-place by splicing over its value range — works for URL, BODY and
     * JSON/XML/multipart ids alike (unlike {@code updateParameter}, which throws on JSON/XML). Rebuilds via
     * {@code buildHttpMessage} so Content-Length stays correct.
     */
    private byte[] spliceParamValue(IExtensionHelpers helpers, byte[] req, IParameter p, String value) {
        return (p == null) ? null : spliceAt(helpers, req, p.getValueStart(), p.getValueEnd(), value);
    }

    /** Splice {@code value} over the byte range [start,end) of {@code req}, rebuilding so Content-Length
     *  stays correct. Works for URL/body params AND nested/array JSON id value ranges. */
    private byte[] spliceAt(IExtensionHelpers helpers, byte[] req, int start, int end, String value) {
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
        } catch (Exception ex) {
            return null;
        }
    }

    // ----- nested / array JSON id probes (Burp's flat IParameter model misses these) ----------------

    private boolean isJsonBody(Baseline b) {
        String ct = b == null || b.requestContentType == null ? "" : b.requestContentType.toLowerCase();
        return ct.contains("json") && b.requestBody != null && !b.requestBody.isEmpty();
    }

    /** True when the request has a JSON body carrying an id-like field at any depth. */
    private boolean jsonHasId(Baseline b) {
        if (!isJsonBody(b)) return false;
        for (burp.scan.JsonIds.Hit h : burp.scan.JsonIds.extract(b.requestBody)) {
            if (isIdName(h.name)) return true;
        }
        return false;
    }

    /**
     * Plan IDOR probes for id-like fields anywhere in the JSON body — nested objects ({@code account.id})
     * and array elements ({@code items[].orderId}). Mirrors the path/param probe set (live swap + negative
     * control + anonymous public probe) so the existing {@link #judge} ownership oracle handles them as-is.
     */
    private void addJsonIdProbes(List<Probe> probes, Baseline b, Set<String> negDone) {
        if (!isJsonBody(b) || b.helpers == null || b.base == null || b.base.getRequest() == null) return;
        IExtensionHelpers helpers = b.helpers;
        byte[] req = b.base.getRequest();
        int bodyOff;
        String body;
        try {
            bodyOff = helpers.analyzeRequest(req).getBodyOffset();
            body = new String(req, bodyOff, req.length - bodyOff, "UTF-8");
        } catch (Exception e) { return; }
        int planned = 0;
        for (burp.scan.JsonIds.Hit hit : burp.scan.JsonIds.extract(body)) {
            if (planned >= 6) break;                       // cap nested-id probes per request
            if (!isIdName(hit.name)) continue;
            int start, end;
            try {                                          // char offset → byte offset (multi-byte safe)
                start = bodyOff + body.substring(0, hit.valueStart).getBytes("UTF-8").length;
                end = bodyOff + body.substring(0, hit.valueEnd).getBytes("UTF-8").length;
            } catch (Exception e) { continue; }
            String val = hit.value;
            String rep = NUM.matcher(val).matches() ? String.valueOf(parseLong(val) + 1) : "1";
            String target = "json:" + hit.name + "@" + hit.valueStart; // disambiguate same-named fields
            planned++;
            addJson(probes, helpers, req, start, end, target, rep, "IDOR", "High", false);
            if (negDone.add("json|" + target)) {
                addJson(probes, helpers, req, start, end, target, INVALID_ID, "IDOR-NEG", "Info", false);
                addJson(probes, helpers, req, start, end, target, rep, "IDOR-PUB", "Info", true); // anon twin of the live swap
            }
        }
    }

    /** Build a JSON-id probe by splicing the value range; {@code anon}=true also strips auth (public probe). */
    private void addJson(List<Probe> probes, IExtensionHelpers helpers, byte[] req, int start, int end,
                         String target, String payload, String attackType, String sev, boolean anon) {
        byte[] variant = spliceAt(helpers, req, start, end, payload);
        if (variant == null) return;
        if (anon) {
            variant = OwnershipOracle.stripAuthHeaders(helpers, variant);
            if (variant == null) return;
        }
        Probe p = new Probe(id(), attackType + " " + target + "→" + payload, "json", target, payload, attackType, sev);
        p.rawRequest = variant;
        probes.add(p);
    }

    private boolean isIdParam(IParameter p) {
        byte t = p.getType();
        if (t != IParameter.PARAM_URL && t != IParameter.PARAM_BODY && t != IParameter.PARAM_JSON) return false;
        return isIdName(p.getName());
    }

    /** True if a field/parameter NAME looks like an object identifier. ID_NAMES / *id suffix cover the
     *  generic ids; isAccountOwnershipParam adds the banking ownership fields (AccountNumber, Iban,
     *  PersonId, …) that have no *id suffix. ROOT locale: tr_TR lower-cases 'I'→dotless 'ı', which would
     *  break endsWith("id") and the stem match. */
    static boolean isIdName(String name) {
        if (name == null) return false;
        String n = name.toLowerCase(Locale.ROOT);
        return ID_NAMES.contains(n) || n.endsWith("id") || n.endsWith("_id")
                || OwnershipOracle.isAccountOwnershipParam(n);
    }

    private List<String> numericPathSegments(String path) {
        List<String> out = new ArrayList<>();
        if (path == null) return out;
        for (String seg : path.split("/")) {
            if (NUM.matcher(seg).matches() && !looksLikeEpoch(seg)) out.add(seg); // skip epoch-timestamp segments
        }
        return out;
    }

    /** True for a purely-numeric value that is almost certainly a UNIX timestamp (epoch seconds, ~2001–2033),
     *  not a sequential object id. Walking a timestamp's neighbours wastes requests and never finds an IDOR,
     *  so we don't range-walk it ("min istek – maks bulgu"). 13-digit epoch-millis are already excluded by the
     *  {@code ^\d{1,12}$} id bound; this catches the 10-digit epoch-seconds case that slips through. */
    private static boolean looksLikeEpoch(String s) {
        if (s == null || s.length() != 10) return false;
        try {
            long v = Long.parseLong(s);
            return v >= 1_000_000_000L && v <= 2_000_000_000L;
        } catch (Exception e) {
            return false;
        }
    }

    private long parseLong(String s) {
        try { return Long.parseLong(s); } catch (Exception e) { return 0L; }
    }
}

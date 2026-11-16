package burp.ambient;

import burp.DatabaseManager;
import burp.Finding;
import burp.FilterEngine;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.Settings;
import burp.authz.OwnershipOracle;
import burp.scan.Signals;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The LLM-free passive scorer. For each proxy response it runs cheap heuristics
 * ({@link FilterEngine#shouldScan}, {@link Signals} header checks, request-shape
 * signals copied from {@code PlaybookRouter}) to compute an "interestingness"
 * score (0..100) and suspected vulnerability-class tags, then enqueues the
 * endpoint if it clears the threshold. NO network, NO model calls — safe to run
 * on every response from a single worker thread.
 *
 * @author Zahid Eroglu
 */
public final class PassiveTriage {

    // Canonical class tags (also used by the hunter to pick deterministic vs agentic).
    public static final String C_IDOR = "IDOR/BOLA";
    public static final String C_AUTH = "Auth/JWT";
    public static final String C_LOGIC = "BusinessLogic";
    public static final String C_MASSASSIGN = "MassAssignment";
    public static final String C_MISCONFIG = "Misconfig";

    /** Queue threshold; overridable from Settings in Phase 8 via {@link #setMinScore}. */
    private volatile int minScore = 35;

    private static final Set<String> ID_NAMES = new HashSet<String>(Arrays.asList(
            "id", "user", "userid", "user_id", "uid", "account", "accountid", "account_id",
            "customer", "customerid", "customer_id", "customerno", "accountno", "order", "orderid", "order_id",
            "invoice", "doc", "docid", "file", "fileid", "pid", "objectid", "object_id",
            // body identifiers beyond the URL (resources + banking/PII)
            "ref", "refid", "reference", "ticket", "ticketid", "product", "productid", "item", "itemid",
            "contract", "contractid", "subscription", "subscriptionid", "transaction", "transactionid",
            "payment", "paymentid", "payee", "beneficiary", "card", "cardid", "iban", "msisdn", "subscriber"));

    private static final Set<String> ECON_NAMES = new HashSet<String>(Arrays.asList(
            "price", "amount", "qty", "quantity", "total", "cost", "discount", "coupon",
            "voucher", "balance", "credit", "role", "isadmin", "admin", "status", "state",
            "approved", "verified", "isverified", "permission", "scope"));

    private final IExtensionHelpers helpers;
    private final FilterEngine filter;
    private final Settings settings;
    private final TargetModel model;
    private final OpportunityQueue queue;
    private final DatabaseManager db;
    private final PrintWriter stdout;
    private final PrintWriter stderr;

    private volatile long lastLearnRefresh = 0L;
    private static final long LEARN_INTERVAL_MS = 60_000L;

    public PassiveTriage(IExtensionHelpers helpers, FilterEngine filter, Settings settings,
                         TargetModel model, OpportunityQueue queue, DatabaseManager db,
                         PrintWriter stdout, PrintWriter stderr) {
        this.helpers = helpers;
        this.filter = filter;
        this.settings = settings;
        this.model = model;
        this.queue = queue;
        this.db = db;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    public void setMinScore(int v) {
        if (v > 0) this.minScore = v;
    }

    /** The unit of work, run on the triage worker thread. Never throws. */
    public void consider(IHttpRequestResponse msg) {
        try {
            if (msg == null || msg.getRequest() == null) return;
            if (!filter.shouldScan(msg)) return;

            IRequestInfo ri = helpers.analyzeRequest(msg);
            byte[] response = msg.getResponse();
            if (isStaticAsset(ri, response)) return;

            String host = ri.getUrl().getHost();
            boolean firstHost = model.peek(host) == null;

            Sig sig = extractSignals(ri, msg, response);
            recordModel(ri, host, sig);
            refreshLearningIfDue();

            Score sc = scoreOf(sig, firstHost);
            int score = applyLearning(host, sc.classes, sc.score); // host history nudges the score
            if (score < minScore) return;

            Opportunity op = new Opportunity(host, ri.getMethod(), ri.getUrl().getPath(),
                    ri.getUrl().toString(), msg.getRequest(), msg.getHttpService());
            op.score = score;
            op.addClasses(sc.classes);
            op.rationale = sc.rationale;
            queue.offerOrMerge(op);

            if (stdout != null) {
                stdout.println("[ambient] queued: " + ri.getMethod() + " " + ri.getUrl().getPath()
                        + " score=" + score + " " + sc.classes);
            }
        } catch (Exception e) {
            if (stderr != null) stderr.println("[ambient] triage error: " + e.getMessage());
        }
    }

    // ----- model update ----------------------------------------------------

    private void recordModel(IRequestInfo ri, String host, Sig sig) {
        TargetModel.HostInfo h = model.host(host);
        for (IParameter p : ri.getParameters()) {
            byte t = p.getType();
            if (t == IParameter.PARAM_URL || t == IParameter.PARAM_BODY || t == IParameter.PARAM_JSON) {
                if (p.getName() != null) h.paramNames.add(p.getName());
            }
        }
        if (sig.authScheme != null) h.authScheme = sig.authScheme;
    }

    // ----- signal extraction (LLM-free) ------------------------------------

    /** Request/response signals, mirroring PlaybookRouter.signals + Signals header checks. */
    Sig extractSignals(IRequestInfo ri, IHttpRequestResponse msg, byte[] response) {
        Sig s = new Sig();
        try {
            String method = ri.getMethod();
            String path = ri.getUrl().getPath() == null ? "" : ri.getUrl().getPath().toLowerCase();
            boolean nonRead = !"GET".equalsIgnoreCase(method) && !"HEAD".equalsIgnoreCase(method);

            String auth = header(ri, "authorization");
            String cookie = header(ri, "cookie");
            String apiKey = header(ri, "x-api-key");
            if (auth != null) s.authScheme = auth.toLowerCase().startsWith("bearer") ? "Bearer" : "Authorization";
            else if (apiKey != null) s.authScheme = "ApiKey";
            else if (cookie != null) s.authScheme = "Cookie";
            s.hasAuth = auth != null || cookie != null || apiKey != null
                    || header(ri, "x-auth-token") != null;
            s.jwt = looksLikeJwt(auth);

            for (String seg : path.split("/")) {
                if (seg.matches("\\d{1,}") || seg.matches("[0-9a-f]{8}-[0-9a-f-]{12,}")) { s.idLike = true; break; }
            }

            for (IParameter p : ri.getParameters()) {
                byte t = p.getType();
                String name = p.getName() == null ? "" : p.getName().toLowerCase(Locale.ROOT);
                if ((t == IParameter.PARAM_BODY || t == IParameter.PARAM_JSON) && nonRead) s.bodyParams = true;
                if (ID_NAMES.contains(name) || OwnershipOracle.isAccountOwnershipParam(name)) s.idLike = true;
                if (ECON_NAMES.contains(name)) s.econ = true;
            }

            if (response != null) {
                List<String> respHeaders = helpers.analyzeResponse(response).getHeaders();
                s.missingHeaders = !Signals.missingSecurityHeaders(respHeaders).isEmpty();
            }
        } catch (Exception ignore) {
        }
        return s;
    }

    private boolean looksLikeJwt(String authHeader) {
        if (authHeader == null) return false;
        String v = authHeader.trim();
        int sp = v.indexOf(' ');
        if (sp > 0) v = v.substring(sp + 1).trim();
        String[] parts = v.split("\\.");
        return parts.length == 3 && parts[0].length() > 4 && parts[1].length() > 4;
    }

    private String header(IRequestInfo ri, String name) {
        String n = name.toLowerCase() + ":";
        for (String h : ri.getHeaders()) {
            if (h.toLowerCase().startsWith(n)) {
                int c = h.indexOf(':');
                return c >= 0 ? h.substring(c + 1).trim() : "";
            }
        }
        return null;
    }

    // ----- scoring (pure, testable) ----------------------------------------

    /** Additive score (clamped 0..100) + suspected-class tags. Pure function of the signals. */
    static Score scoreOf(Sig s, boolean firstHost) {
        int score = 0;
        Set<String> classes = new LinkedHashSet<String>();
        List<String> why = new ArrayList<String>();

        if (s.idLike) {
            score += 30; classes.add(C_IDOR);
            why.add("sıralı/uuid id → IDOR/BOLA adayı");
        }
        if (s.econ) {
            score += 25; classes.add(C_LOGIC);
            why.add("ekonomik/role parametresi → iş mantığı");
        }
        if (s.bodyParams) {
            score += 20; classes.add(C_LOGIC); classes.add(C_MASSASSIGN);
            why.add("yazma gövdesi → mass-assignment/iş mantığı");
        }
        if (s.jwt) {
            score += 20; classes.add(C_AUTH);
            why.add("JWT tespit edildi → auth/alg bypass");
        } else if (s.hasAuth) {
            score += 15; classes.add(C_AUTH);
            why.add("auth başlığı → yetki/oturum");
        }
        if (s.missingHeaders) {
            score += 10; classes.add(C_MISCONFIG);
            why.add("eksik güvenlik başlıkları");
        }
        if (firstHost) {
            score += 5;
            why.add("bu host ilk kez görüldü");
        }

        if (score > 100) score = 100;
        Score out = new Score();
        out.score = score;
        out.classes = new ArrayList<String>(classes);
        out.rationale = String.join("; ", why);
        return out;
    }

    // ----- learning loop (per-host class stats from the findings DB) --------

    /** Periodically reload per-host (class → confirmed/fp) counts from the findings table. */
    private void refreshLearningIfDue() {
        long now = System.currentTimeMillis();
        if (db == null || now - lastLearnRefresh < LEARN_INTERVAL_MS) return;
        lastLearnRefresh = now;
        try {
            Map<String, int[]> agg = new HashMap<String, int[]>();
            for (Finding f : db.getRecentFindings(200)) accumulate(agg, f, false);
            for (Finding f : db.getRecentFalsePositives(100)) accumulate(agg, f, true);
            for (Map.Entry<String, int[]> en : agg.entrySet()) {
                int sep = en.getKey().indexOf('|');
                if (sep <= 0) continue;
                String host = en.getKey().substring(0, sep);
                String cls = en.getKey().substring(sep + 1);
                model.host(host).classStats.put(cls, en.getValue());
            }
        } catch (Exception ignore) {
        }
    }

    private void accumulate(Map<String, int[]> agg, Finding f, boolean fp) {
        if (f == null) return;
        String host = hostOf(f.getAffectedUrl());
        String cls = classify(f.getType());
        if (host == null || cls == null) return;
        String key = host + "|" + cls;
        int[] s = agg.get(key);
        if (s == null) { s = new int[2]; agg.put(key, s); }
        if (fp) s[1]++; else s[0]++;
    }

    private String hostOf(String url) {
        try { return new java.net.URL(url).getHost(); } catch (Exception e) { return null; }
    }

    /** Map a stored finding type string to a triage class tag (or null if unrecognized). */
    static String classify(String type) {
        if (type == null) return null;
        String t = type.toLowerCase();
        if (t.contains("idor") || t.contains("bola") || t.contains("access control")
                || t.contains("authorization") || t.contains("object reference")) return C_IDOR;
        if (t.contains("mass assignment") || t.contains("mass-assignment")) return C_MASSASSIGN;
        if (t.contains("jwt") || t.contains("auth") || t.contains("session") || t.contains("token")) return C_AUTH;
        if (t.contains("business") || t.contains("logic") || t.contains("price")
                || t.contains("quantity") || t.contains("coupon") || t.contains("race")) return C_LOGIC;
        if (t.contains("misconfig") || t.contains("header") || t.contains("cors")
                || t.contains("disclosure") || t.contains("information")) return C_MISCONFIG;
        return null;
    }

    /** Penalize FP-heavy classes, boost previously-confirmed ones, for THIS host. */
    private int applyLearning(String host, List<String> classes, int score) {
        TargetModel.HostInfo h = model.peek(host);
        if (h == null || classes.isEmpty()) return score;
        double penalty = 0.0;
        int bonus = 0;
        for (String c : classes) {
            double fp = h.fpRatio(c);
            if (fp > 0) penalty = Math.max(penalty, Math.min(20.0, 25.0 * fp));
            if (h.wasConfirmed(c)) bonus = 15;
        }
        int adj = score - (int) Math.round(penalty) + bonus;
        if (adj < 0) adj = 0;
        if (adj > 100) adj = 100;
        return adj;
    }

    // ----- static-asset filter (copied from ScanManager.isStaticAsset) ------

    private boolean isStaticAsset(IRequestInfo ri, byte[] response) {
        String path = ri.getUrl().getPath();
        if (path == null) path = "/";
        if (path.toLowerCase().matches(
                ".*\\.(js|mjs|css|png|jpg|jpeg|gif|bmp|tif|tiff|svg|ico|webp|avif|"
                + "woff|woff2|ttf|otf|eot|map|mp4|mp3|wav|ogg|avi|mov|webm|pdf|zip|gz|rar)$")) {
            return true;
        }
        if (response != null) {
            try {
                String mime = helpers.analyzeResponse(response).getInferredMimeType();
                if (mime != null) {
                    String mm = mime.toLowerCase();
                    if (mm.contains("image") || mm.equals("jpeg") || mm.equals("png") || mm.equals("gif")
                            || mm.equals("css") || mm.equals("script") || mm.equals("font")
                            || mm.equals("video") || mm.equals("sound")) {
                        return true;
                    }
                }
            } catch (Exception ignore) {
            }
        }
        return false;
    }

    // ----- small value types -----------------------------------------------

    static final class Sig {
        boolean hasAuth, jwt, idLike, bodyParams, econ, missingHeaders;
        String authScheme;
    }

    static final class Score {
        int score;
        List<String> classes;
        String rationale;
    }
}

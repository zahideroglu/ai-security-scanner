package burp.authz;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.MultiSessionTester;
import burp.MultiSessionTester.UserSession;
import burp.engine.DetectionStage;
import burp.engine.SharedRateLimiter;
import burp.engine.StageListener;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Pattern;

/**
 * Builds the role × endpoint authorization matrix: for every endpoint, replays the
 * request once per role (plus a synthetic anonymous role) via
 * {@link MultiSessionTester#replayAs}, classifies each response with the
 * {@link AccessOracle}, then derives violations. Bounded parallel + shared rate limit.
 *
 * @author Zahid Eroglu
 */
public class AuthMatrixEngine {

    private static final Pattern NUM_SEG = Pattern.compile("/\\d{1,12}(/|$)");

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final MultiSessionTester mtester;
    private final SharedRateLimiter rateLimiter;
    private final AccessOracle oracle;
    private final int parallelism;
    private final PrintWriter stdout, stderr;
    private burp.session.SessionKeeper sessionKeeper; // optional: keep roles fresh before the matrix run

    public void setSessionKeeper(burp.session.SessionKeeper k) { this.sessionKeeper = k; }

    public AuthMatrixEngine(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                            MultiSessionTester mtester, SharedRateLimiter rateLimiter,
                            int parallelism, PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.mtester = mtester;
        this.rateLimiter = rateLimiter;
        this.oracle = new AccessOracle(helpers);
        this.parallelism = Math.max(1, parallelism);
        this.stdout = stdout;
        this.stderr = stderr;
    }

    public AuthMatrix run(List<IHttpRequestResponse> endpoints, List<UserSession> roles,
                          boolean includeMutating, StageListener listener) {
        AuthMatrix matrix = new AuthMatrix();

        final List<UserSession> ordered = orderRoles(roles);
        for (UserSession r : ordered) matrix.roles.add(r.roleName);

        // Filter endpoints by method safety.
        final List<IHttpRequestResponse> targets = new ArrayList<>();
        for (IHttpRequestResponse e : endpoints) {
            try {
                if (includeMutating || isSafeMethod(helpers.analyzeRequest(e).getMethod())) targets.add(e);
            } catch (Exception ignore) {
            }
        }

        // Faz 2 / #7: keep each authed role fresh before testing. A dead session returns 401/login for
        // everything, which the oracle would read as DENIED ("secure") — a false negative. Auto-relogin
        // from a stored profile when possible, else warn the user to re-login.
        if (sessionKeeper != null && !targets.isEmpty()) {
            IHttpRequestResponse canary = targets.get(0);
            String host = hostOf(canary);
            for (UserSession r : ordered) {
                if (r == null || "anonymous".equals(r.roleName)) continue;
                boolean fresh = sessionKeeper.ensureFresh(r, canary, host);
                if (!fresh && listener != null) {
                    listener.onStageProgress(DetectionStage.EXECUTE,
                            "⚠️ '" + r.roleName + "' oturumu düşmüş ve otomatik yenilenemedi — bu rolün hücreleri "
                            + "güvenilmez; yeniden giriş yapıp tekrar çalıştırın.");
                }
            }
        }

        ExecutorService pool = Executors.newFixedThreadPool(parallelism);
        try {
            List<Future<AuthMatrix.Row>> futures = new ArrayList<>();
            for (IHttpRequestResponse ep : targets) {
                futures.add(pool.submit(() -> buildRow(ep, ordered)));
            }
            int done = 0;
            for (Future<AuthMatrix.Row> f : futures) {
                if (isAborted(listener)) {                       // stop button clicked → cancel the remaining rows
                    for (Future<?> ff : futures) ff.cancel(true);
                    if (listener != null) listener.onStageProgress(DetectionStage.EXECUTE,
                            "⏹ Matris kullanıcı tarafından durduruldu (" + done + "/" + targets.size() + ").");
                    break;
                }
                try {
                    AuthMatrix.Row row = f.get();
                    if (row != null) matrix.rows.add(row);
                } catch (Exception e) {
                    if (stderr != null) stderr.println("[AuthMatrix] row: " + e.getMessage());
                }
                done++;
                if (listener != null) {
                    listener.onStageProgress(DetectionStage.EXECUTE,
                            "Matris: " + done + "/" + targets.size() + " endpoint × " + ordered.size() + " rol");
                }
            }
        } finally {
            pool.shutdownNow();
        }

        matrix.violations.addAll(oracle.detectViolations(matrix));
        return matrix;
    }

    /** True once the user hit the run's Stop button (same pattern the site/agentic engines use). */
    private static boolean isAborted(StageListener l) {
        return (l instanceof burp.DetectionRunView) && ((burp.DetectionRunView) l).isAborted();
    }

    private AuthMatrix.Row buildRow(IHttpRequestResponse ep, List<UserSession> roles) {
        IRequestInfo ri = helpers.analyzeRequest(ep);
        String method = ri.getMethod();
        String url = ri.getUrl().toString();
        String path = ri.getUrl().getPath();
        AuthMatrix.Row row = new AuthMatrix.Row(method, path, url, hasResourceId(ri));
        row.base = ep;
        String host = ri.getUrl().getHost();
        for (UserSession r : roles) {
            // WAF breaker open for this host: skip the replay (it would blackhole) — leave cell at ERROR default.
            if (rateLimiter.isHostBlocked(host)) {
                row.byRole.put(r.roleName, new AuthMatrix.Cell());
                continue;
            }
            rateLimiter.acquire();
            AuthMatrix.Cell cell;
            long t0 = System.nanoTime();
            int st = 0;
            String snip = null;
            try {
                IHttpRequestResponse rr = mtester.replayAs(ep, r);
                byte[] resp = rr != null ? rr.getResponse() : null;
                if (resp == null) {
                    cell = new AuthMatrix.Cell();
                } else {
                    IResponseInfo respInfo = helpers.analyzeResponse(resp);
                    int off = respInfo.getBodyOffset();
                    int len = Math.max(0, resp.length - off);
                    snip = new String(resp, off, Math.min(2048, len),
                            java.nio.charset.StandardCharsets.UTF_8);
                    st = respInfo.getStatusCode();
                    String ct = burp.scan.Signals.contentTypeOf(String.join("\n", respInfo.getHeaders()));
                    if (burp.scan.Signals.isImageOrMediaType(ct) || burp.scan.Signals.looksLikeBlockPage(snip)) {
                        // A world-readable image/media asset or a WAF block under /api/ is not "access
                        // granted" — leave the cell at ERROR default so it never counts as GRANTED. (We do
                        // NOT exclude PDF/ZIP/octet-stream here — those can be sensitive data exports.)
                        cell = new AuthMatrix.Cell();
                    } else {
                        cell = new AuthMatrix.Cell(oracle.verdict(resp), st, len);
                        cell.bodySnippet = snip;
                    }
                }
            } catch (Exception e) {
                cell = new AuthMatrix.Cell();
            }
            // Feed the shared per-host WAF breaker (HTTP 0 / stall / block page / 403-429-503): a trip here
            // halts every engine on this host before the matrix piles up blackholed replays.
            rateLimiter.noteResult(host, st, (System.nanoTime() - t0) / 1_000_000L, snip);
            row.byRole.put(r.roleName, cell);
        }
        return row;
    }

    /** Prepend a synthetic anonymous role, then sort by trust rank ascending. */
    private List<UserSession> orderRoles(List<UserSession> roles) {
        List<UserSession> out = new ArrayList<>();
        UserSession anon = new UserSession();
        anon.roleName = "anonymous";
        anon.authTokens = new HashMap<>();
        out.add(anon);
        if (roles != null) {
            List<UserSession> authed = new ArrayList<>(roles);
            Collections.sort(authed, new Comparator<UserSession>() {
                public int compare(UserSession a, UserSession b) {
                    int ra = AccessOracle.rank(a.roleName), rb = AccessOracle.rank(b.roleName);
                    if (ra != rb) return Integer.compare(ra, rb);
                    return safe(a.roleName).compareToIgnoreCase(safe(b.roleName));
                }
            });
            out.addAll(authed);
        }
        return out;
    }

    private static String safe(String s) { return s == null ? "" : s; }

    private String hostOf(IHttpRequestResponse m) {
        try { return helpers.analyzeRequest(m).getUrl().getHost(); } catch (Exception e) { return null; }
    }

    private boolean isSafeMethod(String m) {
        return "GET".equalsIgnoreCase(m) || "HEAD".equalsIgnoreCase(m) || "OPTIONS".equalsIgnoreCase(m);
    }

    private boolean hasResourceId(IRequestInfo ri) {
        if (NUM_SEG.matcher(ri.getUrl().getPath()).find()) return true;
        for (IParameter p : ri.getParameters()) {
            byte t = p.getType();
            if (t != IParameter.PARAM_URL && t != IParameter.PARAM_BODY && t != IParameter.PARAM_JSON) continue;
            String n = p.getName().toLowerCase(Locale.ROOT);
            if (n.equals("id") || n.endsWith("id") || n.endsWith("_id") || n.contains("user")
                    || n.contains("account") || n.contains("order") || n.contains("doc")) return true;
            // "Hesap Aitlik Kontrolü" fields with no *id suffix / "account" substring — bare Iban,
            // SenderIban, ReceiverIban, Msisdn — must also make the row BOLA-eligible (AccessOracle V3).
            if (OwnershipOracle.isAccountOwnershipParam(p.getName())) return true;
        }
        return false;
    }
}

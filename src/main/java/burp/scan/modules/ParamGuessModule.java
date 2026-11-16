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

/**
 * A01 Broken Access Control (B03): adds undeclared privilege/visibility
 * parameters (internal=1, admin=true, role=admin, ...) that were NOT in the
 * original request and flags when the server honours one (HTTP 200 with changed
 * behaviour) - e.g. exposing internal listings/drafts to anonymous users.
 *
 * @author Zahid Eroglu
 */
public class ParamGuessModule implements ScanModule {

    // High-signal access-control / feature-flag params only. Weak dev-mode guesses (debug, test,
    // preview, unpublished) were dropped to cut requests per endpoint (11 -> 7).
    private static final String[][] GUESS = {
            {"internal", "1"}, {"admin", "true"}, {"isAdmin", "true"}, {"role", "admin"},
            {"draft", "true"}, {"showAll", "true"}, {"is_internal", "1"}
    };

    public String id() { return "paramguess"; }
    public String displayName() { return "Access Control - Parameter Guessing"; }
    public boolean isEnabled(Settings s) { return s.isModuleAccessControlEnabled(); }

    public boolean appliesTo(Baseline b) {
        // Focus on API/JSON GET endpoints (like a listing API) to keep false positives low.
        return b.statusCode == 200 && "GET".equalsIgnoreCase(b.method)
                && (!b.responseIsHtml || (b.path != null && b.path.toLowerCase().contains("/api/")));
    }

    public List<Probe> plan(Baseline b, Settings s) {
        List<Probe> p = new ArrayList<>();
        for (String[] g : GUESS) {
            if (alreadyPresent(b, g[0])) continue;
            p.add(new Probe(id(), "Add param " + g[0] + "=" + g[1], "param",
                    g[0], g[1], "Access Control Param", "Medium"));
        }
        return p;
    }

    public List<Finding> judge(Baseline b, List<ProbeResult> results) {
        List<Finding> f = new ArrayList<>();
        for (ProbeResult r : results) {
            if (r.probe == null || !r.ok() || !"Access Control Param".equals(r.probe.attackType)) continue;
            if (r.statusCode != 200) continue;
            if (Signals.looksLikeBlockPage(r.bodySnippet)) continue; // WAF/block page, not exposed data
            double delta = Signals.lengthDeltaRatio(b.responseLength, r.responseLength);
            if (delta < 0.05 || delta >= 0.95) continue; // unchanged, or an error/redirect page
            f.add(new Finding("Broken Access Control (Parameter)", "Medium", 0.55,
                    I18n.t("f.pg.bac.desc", r.probe.targetParameter, r.probe.payload,
                            b.responseLength, r.responseLength),
                    "", I18n.t("f.pg.bac.ev", r.probe.targetParameter, r.probe.payload,
                            b.responseLength, r.responseLength),
                    I18n.t("f.pg.bac.exp"),
                    I18n.t("f.pg.bac.rem")));
        }
        return f;
    }

    private boolean alreadyPresent(Baseline b, String name) {
        for (IParameter par : b.parameters) {
            if (par.getName().equalsIgnoreCase(name)) return true;
        }
        return false;
    }
}

package burp.scan;

import burp.Finding;
import burp.Settings;
import java.util.List;

/**
 * A deterministic attack module. Pure functions of (Baseline, ProbeResults):
 * {@link #plan} builds probes (NO network), {@link #judge} decides findings
 * (NO AI, NO network). The engine sends probes via the shared TestSink.
 *
 * @author Zahid Eroglu
 */
public interface ScanModule {
    String id();
    String displayName();
    boolean isEnabled(Settings s);
    boolean appliesTo(Baseline b);
    List<Probe> plan(Baseline b, Settings s);
    List<Finding> judge(Baseline b, List<ProbeResult> results);
}

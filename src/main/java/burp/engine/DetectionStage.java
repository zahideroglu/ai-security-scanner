package burp.engine;

/**
 * The ordered stages of the step-by-step vulnerability detection pipeline.
 *
 * RECON      -> understand the target (tech stack, framework, WAF, app type)
 * HYPOTHESIS -> AI ranks the most likely vulnerability classes
 * TEST_PLAN  -> AI builds a concrete plan of requests/payloads to send
 * EXECUTE    -> send the planned requests (and optional attack chains)
 * ANALYZE    -> turn raw results + a comprehensive pass into candidate findings
 * VERIFY     -> AI false-positive filtering / confidence gating
 * REPORT     -> persist, raise Burp issues, push to the Findings panel
 *
 * @author Zahid Eroglu
 */
public enum DetectionStage {
    RECON("Recon"),
    HYPOTHESIS("Hypothesis"),
    TEST_PLAN("Test Plan"),
    EXECUTE("Execute"),
    ANALYZE("Analyze"),
    VERIFY("Verify"),
    REPORT("Report");

    private final String label;

    DetectionStage(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

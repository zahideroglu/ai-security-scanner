package burp.engine;

import java.io.PrintWriter;

/**
 * Simple {@link StageListener} that logs stage activity to stdout and
 * auto-approves every stage. Used for automatic runs that have no UI attached
 * (the default listener wherever a scan path is launched without an interactive
 * {@link burp.DetectionRunView}).
 *
 * @author Zahid Eroglu
 */
public class LoggingStageListener implements StageListener {
    private final PrintWriter out;

    public LoggingStageListener(PrintWriter out) {
        this.out = out;
    }

    public void onStageStart(DetectionStage stage) {
        out.println("[>] " + stage.getLabel() + " ...");
    }

    public void onStageProgress(DetectionStage stage, String message) {
        out.println("    " + stage.getLabel() + ": " + message);
    }

    public void onStageComplete(DetectionStage stage, StageResult result) {
        out.println("[" + (result.ok ? "✓" : "✗") + "] " + stage.getLabel()
                + " (" + result.durationMs + "ms) - " + result.summary);
    }

    public boolean awaitApproval(DetectionStage nextStage, StageResult lastResult) {
        return true;
    }
}

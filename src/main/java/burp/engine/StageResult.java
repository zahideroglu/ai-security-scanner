package burp.engine;

import burp.Finding;
import java.util.ArrayList;
import java.util.List;

/**
 * Result of a single detection stage. Carries a human-readable summary,
 * an ok/failed flag, any findings produced, and a duration for the UI.
 *
 * @author Zahid Eroglu
 */
public class StageResult {

    public final DetectionStage stage;
    public boolean ok = true;
    public boolean skipped = false;
    public String summary = "";
    public long durationMs = 0;
    public List<Finding> findings = new ArrayList<>();

    public StageResult(DetectionStage stage) {
        this.stage = stage;
    }

    public static StageResult ok(DetectionStage stage, String summary) {
        StageResult r = new StageResult(stage);
        r.ok = true;
        r.summary = summary != null ? summary : "";
        return r;
    }

    public static StageResult failed(DetectionStage stage, String summary) {
        StageResult r = new StageResult(stage);
        r.ok = false;
        r.summary = summary != null ? summary : "";
        return r;
    }
}

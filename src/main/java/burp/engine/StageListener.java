package burp.engine;

/**
 * Callback interface the UI implements to observe (and, in guided mode,
 * gate) the detection pipeline.
 *
 * All callbacks are invoked from the pipeline's background worker thread.
 * UI implementations MUST marshal to the EDT (SwingUtilities.invokeLater)
 * themselves. The ONLY method that may block is {@link #awaitApproval},
 * which blocks the worker thread until the user decides - this never
 * touches the EDT and so keeps the UI responsive.
 *
 * @author Zahid Eroglu
 */
public interface StageListener {

    /** A stage is about to run. */
    void onStageStart(DetectionStage stage);

    /** Free-form progress text emitted while a stage runs. */
    void onStageProgress(DetectionStage stage, String message);

    /** A stage finished (successfully or not). */
    void onStageComplete(DetectionStage stage, StageResult result);

    /**
     * Guided-mode gate. Called before each stage when RunMode is GUIDED.
     * Return true to run the stage, false to abort the remaining run.
     * In automatic mode this is never called.
     *
     * @param nextStage  the stage awaiting approval
     * @param lastResult result of the previous stage (null before the first)
     */
    boolean awaitApproval(DetectionStage nextStage, StageResult lastResult);

    /** An individual active test is about to be sent (EXECUTE stage). */
    default void onTestStarted(String description, String location, String target, String payload) {}

    /** The last started active test finished with the given status. */
    default void onTestFinished(String status) {}

    /**
     * Row-id variants for PARALLEL execution: returns a stable id so the
     * matching {@link #onTestFinished2}/{@link #onTestResult} update the correct
     * row even when many probes run concurrently. Default delegates to the
     * single-row methods (returns -1).
     */
    default int onTestStarted2(String description, String location, String target, String payload) {
        onTestStarted(description, location, target, payload);
        return -1;
    }

    default void onTestFinished2(int rowId, String status) {
        onTestFinished(status);
    }

    /** Raw request/response bytes for the finished probe (for UI preview). */
    default void onTestResult(int rowId, byte[] rawRequest, byte[] rawResponse) {}
}

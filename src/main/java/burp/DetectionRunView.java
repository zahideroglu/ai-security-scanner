package burp;

import burp.engine.DetectionStage;
import burp.engine.StageListener;
import burp.engine.StageResult;
import burp.i18n.Glyphs;
import burp.i18n.I18n;
import burp.i18n.I18nUI;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * One detection run rendered as a panel (shown as a sub-tab inside
 * {@link DetectionPanel}). Holds the 7-stage strip, an "Active Tests" table,
 * and a log. Implements {@link StageListener}: the pipeline's worker thread
 * calls in here; Swing mutation is marshalled to the EDT; the only blocking
 * call ({@link #awaitApproval}) blocks the worker thread (never the EDT).
 *
 * @author Zahid Eroglu
 */
public class DetectionRunView extends JPanel implements StageListener {

    // Console (log / request / response) colors follow Burp's theme — resolved per-instance
    // since instances are built at scan time, after ColorScheme.refreshTheme() has run.
    private final Color consoleBg = ColorScheme.CONSOLE_BG;
    private final Color consoleFg = ColorScheme.CONSOLE_FG;

    /** Stage-strip prefix shown for a state; emoji on capable fonts, else color carries the state. */
    private static String statePrefix(String emoji) {
        return Glyphs.emojiOk() ? emoji : "";
    }

    private volatile boolean guided = false;
    private volatile boolean running = false;
    private volatile boolean aborted = false;
    // True when this view hosts MULTIPLE pipeline runs (site scan, or a playbook hunt that runs several
    // playbooks). Each pipeline ends with its own REPORT stage, so REPORT must NOT flip `running` — the
    // run is only finished when the driver calls siteDone(). Otherwise the first endpoint/playbook's
    // REPORT would mark the still-working tab "finished" and "Bitenleri Kapat" would close it mid-scan.
    private volatile boolean multiRun = false;

    private final Map<DetectionStage, JLabel> stageLabels = new EnumMap<>(DetectionStage.class);
    private final JTextArea logArea = new JTextArea();
    private final JButton approveBtn = I18nUI.text(new JButton(), "run.btn.approve");
    private final JButton abortBtn = I18nUI.text(new JButton(), "run.btn.abort");
    private final JLabel targetLabel = I18nUI.text(new JLabel(), "run.notRunYet");
    private final JLabel statusLabel = new JLabel(" ");
    private final JLabel counterLabel = new JLabel(" ");
    private final JProgressBar progressBar = new JProgressBar();
    private int sentCount = 0;
    private int errorCount = 0;

    // Persistent scan logging: every line shown here is also teed to ~/.appsechunter/logs/.
    private volatile String runTag = "";

    /** Short host+tail tag for log lines, e.g. "example.com/postlogin". */
    private static String deriveTag(String target) {
        if (target == null) return "";
        String t = target.replaceFirst("^https?://", "");
        int q = t.indexOf('?');
        if (q >= 0) t = t.substring(0, q);
        if (t.length() > 48) {
            int slash = t.indexOf('/');
            String host = slash > 0 ? t.substring(0, slash) : t;
            String tail = t.substring(Math.max(host.length(), t.length() - 24));
            t = host + "/…" + tail;
        }
        return t;
    }

    /** Localized display name for a pipeline stage (the enum's own label is English-only). */
    private static String stageLabel(DetectionStage stage) {
        switch (stage) {
            case RECON:      return I18n.t("run.stage.recon");
            case HYPOTHESIS: return I18n.t("run.stage.hypothesis");
            case TEST_PLAN:  return I18n.t("run.stage.testPlan");
            case EXECUTE:    return I18n.t("run.stage.execute");
            case ANALYZE:    return I18n.t("run.stage.analyze");
            case VERIFY:     return I18n.t("run.stage.verify");
            case REPORT:     return I18n.t("run.stage.report");
            default:         return stage.getLabel();
        }
    }

    private DefaultTableModel testsModel;
    private JTable testsTable;
    private int lastTestRow = -1;

    // Parallel-safe row tracking + request/response preview
    private final AtomicInteger nextRowId = new AtomicInteger(0);
    private final Map<Integer, Integer> rowIdToModel = new HashMap<>();
    private final Map<Integer, String> rowIdToDesc = new HashMap<>(); // for self-describing log finish lines
    private final Map<Integer, byte[][]> bytesByModelRow = new HashMap<>();
    private JTextArea reqArea;
    private JTextArea respArea;

    private final BlockingQueue<Boolean> gate = new ArrayBlockingQueue<>(1);

    public DetectionRunView() {
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

        // Header
        targetLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        statusLabel.setFont(new Font("Segoe UI", Font.ITALIC, 12));
        statusLabel.setForeground(ColorScheme.isDarkMode() ? new Color(0xFFB74D) : new Color(0xD17B00));
        counterLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        counterLabel.setForeground(ColorScheme.TEXT_SECONDARY);
        progressBar.setVisible(false);
        progressBar.setStringPainted(false);
        JPanel head = new JPanel();
        head.setLayout(new BoxLayout(head, BoxLayout.Y_AXIS));
        head.add(targetLabel);
        head.add(statusLabel);
        head.add(counterLabel);
        head.add(Box.createVerticalStrut(4));
        head.add(progressBar);
        add(head, BorderLayout.NORTH);

        // Stages strip
        JPanel stages = new JPanel(new GridLayout(1, DetectionStage.values().length, 6, 0));
        stages.setBorder(BorderFactory.createEmptyBorder(8, 0, 8, 0));
        for (DetectionStage st : DetectionStage.values()) {
            String pfx = statePrefix("⏳");
            JLabel lbl = new JLabel((pfx.isEmpty() ? "" : pfx + " ") + stageLabel(st), SwingConstants.CENTER);
            lbl.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            lbl.setOpaque(true);
            lbl.setBackground(ColorScheme.STATE_IDLE_BG);
            lbl.setForeground(ColorScheme.STATE_IDLE_FG);
            lbl.setBorder(BorderFactory.createEmptyBorder(6, 4, 6, 4));
            stageLabels.put(st, lbl);
            stages.add(lbl);
        }

        // Active tests table
        testsModel = new DefaultTableModel(
                new Object[]{
                        I18n.t("run.col.num"), I18n.t("run.col.test"), I18n.t("run.col.location"),
                        I18n.t("run.col.target"), I18n.t("run.col.payload"), I18n.t("run.col.result")
                }, 0) {
            public boolean isCellEditable(int r, int c) { return false; }
        };
        testsTable = new JTable(testsModel);
        testsTable.setFillsViewportHeight(true);
        testsTable.setRowHeight(22);
        testsTable.getColumnModel().getColumn(0).setMaxWidth(40);
        testsTable.getColumnModel().getColumn(5).setCellRenderer(new ResultRenderer());
        JScrollPane testsScroll = new JScrollPane(testsTable);
        I18nUI.titled(testsScroll, "run.activeTests");

        // Log
        logArea.setEditable(false);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 11));
        logArea.setBackground(consoleBg);
        logArea.setForeground(consoleFg);
        logArea.setCaretColor(consoleFg);
        JScrollPane logScroll = new JScrollPane(logArea);

        // Request / Response preview (filled when a test row is selected)
        reqArea = newPreviewArea();
        respArea = newPreviewArea();
        JTabbedPane bottomTabs = new JTabbedPane();
        bottomTabs.addTab(I18n.t("run.tab.log"), logScroll);
        bottomTabs.addTab(I18n.t("run.tab.request"), new JScrollPane(reqArea));
        bottomTabs.addTab(I18n.t("run.tab.response"), new JScrollPane(respArea));

        // Row selection -> show that probe's request/response
        testsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        testsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showSelectedRow(bottomTabs);
        });

        JSplitPane lower = new JSplitPane(JSplitPane.VERTICAL_SPLIT, testsScroll, bottomTabs);
        lower.setResizeWeight(0.5);
        lower.setBorder(null);

        JPanel center = new JPanel(new BorderLayout(0, 6));
        center.add(stages, BorderLayout.NORTH);
        center.add(lower, BorderLayout.CENTER);
        add(center, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        approveBtn.setEnabled(false);
        abortBtn.setEnabled(false);
        approveBtn.addActionListener(e -> {
            approveBtn.setEnabled(false);
            gate.offer(Boolean.TRUE);
        });
        abortBtn.addActionListener(e -> {
            approveBtn.setEnabled(false);
            aborted = true;
            gate.offer(Boolean.FALSE);
        });
        buttons.add(approveBtn);
        buttons.add(abortBtn);
        add(buttons, BorderLayout.SOUTH);
    }

    public void startRun(String targetUrl, boolean guided) {
        this.guided = guided;
        this.running = true;
        this.aborted = false;
        this.multiRun = false; // single pipeline → its REPORT marks the run finished
        this.runTag = deriveTag(targetUrl);
        gate.clear();
        targetLabel.setText(I18n.t("run.target", targetUrl));
        statusLabel.setText(guided ? I18n.t("run.mode.guided") : I18n.t("run.mode.auto"));
        logArea.setText("");
        ScanLogger.get().banner(runTag, "RUN START: " + targetUrl + (guided ? " (rehberli)" : " (otomatik)"));
        appendLog(Glyphs.clean("📝 Kayıt: " + ScanLogger.get().currentFilePath()));
        clearTests();
        resetCounters();
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        for (DetectionStage st : DetectionStage.values()) {
            setStage(st, "⏳");
        }
        approveBtn.setVisible(guided);
        approveBtn.setEnabled(false);
        I18nUI.text(abortBtn, "run.btn.abort");
        abortBtn.setEnabled(true);
    }

    private void clearTests() {
        testsModel.setRowCount(0);
        lastTestRow = -1;
        rowIdToModel.clear();
        rowIdToDesc.clear();
        bytesByModelRow.clear();
        nextRowId.set(0);
        if (reqArea != null) reqArea.setText("");
        if (respArea != null) respArea.setText("");
    }

    private JTextArea newPreviewArea() {
        JTextArea a = new JTextArea();
        a.setEditable(false);
        a.setLineWrap(true);
        a.setFont(new Font("Consolas", Font.PLAIN, 11));
        a.setBackground(consoleBg);
        a.setForeground(consoleFg);
        a.setCaretColor(consoleFg);
        return a;
    }

    private void showSelectedRow(JTabbedPane tabs) {
        int viewRow = testsTable.getSelectedRow();
        if (viewRow < 0) return;
        int modelRow = testsTable.convertRowIndexToModel(viewRow);
        byte[][] bytes = bytesByModelRow.get(modelRow);
        if (bytes == null) {
            reqArea.setText(I18n.t("run.preview.notReady"));
            respArea.setText("");
            return;
        }
        reqArea.setText(bytes[0] != null ? new String(bytes[0]) : I18n.t("run.preview.noRequest"));
        reqArea.setCaretPosition(0);
        respArea.setText(bytes[1] != null ? new String(bytes[1]) : I18n.t("run.preview.noResponse"));
        respArea.setCaretPosition(0);
    }

    @Override
    public int onTestStarted2(String description, String location, String target, String payload) {
        final int id = nextRowId.getAndIncrement();
        SwingUtilities.invokeLater(() -> {
            String p = payload == null ? "" : (payload.length() > 60 ? payload.substring(0, 60) + "…" : payload);
            testsModel.addRow(new Object[]{
                    testsModel.getRowCount() + 1, description, location, target, p, I18n.t("run.status.running")
            });
            int modelRow = testsModel.getRowCount() - 1;
            rowIdToModel.put(id, modelRow);
            rowIdToDesc.put(id, description);
            testsTable.scrollRectToVisible(testsTable.getCellRect(modelRow, 0, true));
            sentCount++;
            updateCounter();
        });
        ScanLogger.get().log(runTag, "  ▶ test#" + id + " " + description
                + " @" + location + " → " + target + payloadForLog(payload));
        return id;
    }

    @Override
    public void onTestFinished2(int rowId, String status) {
        SwingUtilities.invokeLater(() -> {
            Integer mr = rowIdToModel.get(rowId);
            if (mr != null && mr < testsModel.getRowCount()) {
                testsModel.setValueAt(status, mr, 5);
            }
            if (status != null && status.toLowerCase().startsWith("error")) {
                errorCount++;
            }
            String desc = rowIdToDesc.get(rowId);
            ScanLogger.get().log(runTag, "  ⇒ test#" + rowId
                    + (desc != null ? " " + desc : "") + "  →  " + status);
            updateCounter();
        });
    }

    @Override
    public void onTestResult(int rowId, byte[] rawRequest, byte[] rawResponse) {
        SwingUtilities.invokeLater(() -> {
            Integer mr = rowIdToModel.get(rowId);
            if (mr != null) {
                bytesByModelRow.put(mr, new byte[][]{rawRequest, rawResponse});
            }
        });
    }

    // ---- Active test events ----

    @Override
    public void onTestStarted(String description, String location, String target, String payload) {
        SwingUtilities.invokeLater(() -> {
            String p = payload == null ? "" : (payload.length() > 60 ? payload.substring(0, 60) + "…" : payload);
            testsModel.addRow(new Object[]{
                    testsModel.getRowCount() + 1, description, location, target, p, I18n.t("run.status.running")
            });
            lastTestRow = testsModel.getRowCount() - 1;
            testsTable.scrollRectToVisible(testsTable.getCellRect(lastTestRow, 0, true));
            sentCount++;
            updateCounter();
        });
        ScanLogger.get().log(runTag, "  ▶ " + description + " @" + location
                + " → " + target + payloadForLog(payload));
    }

    @Override
    public void onTestFinished(String status) {
        SwingUtilities.invokeLater(() -> {
            if (lastTestRow >= 0 && lastTestRow < testsModel.getRowCount()) {
                testsModel.setValueAt(status, lastTestRow, 5);
            }
            if (status != null && status.toLowerCase().startsWith("error")) {
                errorCount++;
            }
            updateCounter();
        });
        ScanLogger.get().log(runTag, "  ⇒ " + status);
    }

    /** Full payload for the log file (capped), unlike the table's 60-char visual truncation. */
    private static String payloadForLog(String payload) {
        if (payload == null || payload.isEmpty()) return "";
        String p = payload.length() > 500 ? payload.substring(0, 500) + "…(" + payload.length() + "b)" : payload;
        return "  payload=" + p.replace("\n", "\\n");
    }

    private void updateCounter() {
        counterLabel.setText(I18n.t("run.counter", sentCount, errorCount));
    }

    private void resetCounters() {
        sentCount = 0;
        errorCount = 0;
        counterLabel.setText(" ");
    }

    // ---- Whole-site scan support ----

    public boolean isAborted() {
        return aborted;
    }

    /** True while this run is still executing (used by DetectionPanel to gate tab close / "Bitenleri Kapat"). */
    public boolean isRunning() {
        return running;
    }

    /** Mark this view as running from the moment its tab is created (for site/agentic drivers that drive
     *  stages directly without startRun). The driver's terminal — siteDone() — clears it. */
    public void markRunning() {
        this.running = true;
        this.aborted = false;
        SwingUtilities.invokeLater(() -> abortBtn.setEnabled(true)); // site/matrix drivers must be stoppable too
    }

    /** Mark this view as hosting multiple pipeline runs so a per-pipeline REPORT does not finish the run;
     *  the driver must call {@link #siteDone} when truly done. (Used by the multi-playbook hunt.) */
    public void setMultiRun(boolean v) {
        this.multiRun = v;
    }

    // Re-run: the launcher stores a closure that re-fires THIS run's scan into a fresh tab.
    private Runnable rerunAction;
    public void setRerunAction(Runnable r) { this.rerunAction = r; }
    public boolean canRerun() { return rerunAction != null; }
    /** Re-fire this run's scan (no-op if not set or still running). */
    public void rerun() {
        Runnable r = rerunAction;
        if (r != null && !running) r.run();
    }

    /** Programmatic abort (e.g. the ambient hunter's kill switch). */
    public void requestAbort() {
        this.aborted = true;
    }

    public void prepareSiteScan(String host, int total) {
        SwingUtilities.invokeLater(() -> {
            this.aborted = false;
            this.running = true;
            this.multiRun = true; // many endpoints, each with its own REPORT → only siteDone() finishes the run
            this.guided = false;
            this.runTag = deriveTag(host);
            targetLabel.setText(I18n.t("run.siteScan", host));
            statusLabel.setText(I18n.t("run.endpointsScanned", 0, total));
            logArea.setText("");
            ScanLogger.get().banner(runTag, "SITE SCAN START: " + host + " (" + total + " uç)");
            appendLog(Glyphs.clean("📝 Kayıt: " + ScanLogger.get().currentFilePath()));
            clearTests();
            resetCounters();
            progressBar.setIndeterminate(true);
            progressBar.setVisible(true);
            for (DetectionStage st : DetectionStage.values()) {
                setStage(st, "—");
            }
            approveBtn.setVisible(false);
            I18nUI.text(abortBtn, "run.btn.abort");
            abortBtn.setEnabled(true);
        });
    }

    public void siteLog(String line) {
        SwingUtilities.invokeLater(() -> appendLog(line));
    }

    public void siteStatus(String s) {
        SwingUtilities.invokeLater(() -> statusLabel.setText(s));
    }

    public void siteDone(int findings, boolean abortedEarly) {
        SwingUtilities.invokeLater(() -> {
            this.running = false;
            progressBar.setIndeterminate(false);
            progressBar.setVisible(false);
            appendLog("");
            appendLog("════════════ SONUÇ ════════════");
            appendLog((abortedEarly ? "Durduruldu. " : "Tamamlandı. ")
                    + findings + " bulgu raporlandı ('Findings' sekmesi + Burp Issues).");
            statusLabel.setText(abortedEarly
                    ? I18n.t("run.site.stopped", findings)
                    : I18n.t("run.site.completed", findings));
            abortBtn.setEnabled(false);
        });
    }

    private void appendLog(String line) {
        logArea.append(line + "\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
        ScanLogger.get().log(runTag, line); // persist to ~/.appsechunter/logs/ for later review
    }

    private void setStage(DetectionStage stage, String prefix) {
        JLabel lbl = stageLabels.get(stage);
        if (lbl != null) {
            // `prefix` is a semantic state key (emoji literal from the caller). It still drives the
            // colors; the *displayed* glyph is dropped on fonts without emoji (color carries state).
            String disp = statePrefix(prefix);
            lbl.setText((disp.isEmpty() ? "" : disp + " ") + stageLabel(stage));
            Color bg, fg;
            if ("✓".equals(prefix)) {
                bg = ColorScheme.STATE_DONE_BG;    fg = ColorScheme.STATE_DONE_FG;
            } else if ("✗".equals(prefix)) {
                bg = ColorScheme.STATE_FAIL_BG;    fg = ColorScheme.STATE_FAIL_FG;
            } else if ("▶".equals(prefix) || "⏸".equals(prefix)) {
                bg = ColorScheme.STATE_RUNNING_BG; fg = ColorScheme.STATE_RUNNING_FG;
            } else {
                bg = ColorScheme.STATE_IDLE_BG;    fg = ColorScheme.STATE_IDLE_FG;
            }
            lbl.setBackground(bg);
            lbl.setForeground(fg);
        }
    }

    // ---- StageListener ----

    @Override
    public boolean awaitApproval(DetectionStage nextStage, StageResult lastResult) {
        if (!guided) {
            return true;
        }
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(I18n.t("run.awaitingApproval", stageLabel(nextStage)));
            setStage(nextStage, "⏸");
            approveBtn.setEnabled(true);
            abortBtn.setEnabled(true);
        });
        try {
            Boolean go = gate.take();
            return go != null && go;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    @Override
    public void onStageStart(DetectionStage stage) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(I18n.t("run.running", stageLabel(stage)));
            setStage(stage, "▶");
            appendLog("[>] " + stage.getLabel() + " ...");
        });
    }

    @Override
    public void onStageProgress(DetectionStage stage, String message) {
        SwingUtilities.invokeLater(() -> appendLog("    " + message));
    }

    @Override
    public void onStageComplete(DetectionStage stage, StageResult result) {
        SwingUtilities.invokeLater(() -> {
            setStage(stage, result.ok ? "✓" : "✗");
            appendLog("[" + (result.ok ? Glyphs.ok() : Glyphs.fail()) + "] " + stage.getLabel()
                    + " (" + result.durationMs + "ms) - " + result.summary);
            if (stage == DetectionStage.REPORT && !multiRun) {
                running = false;
                progressBar.setIndeterminate(false);
                progressBar.setVisible(false);
                int n = result.findings != null ? result.findings.size() : 0;
                appendLog("");
                appendLog("════════════ SONUÇ ════════════");
                if (n == 0) {
                    appendLog("Doğrulanmış zafiyet bulunamadı.");
                    statusLabel.setText(I18n.t("run.site.completed", n));
                } else {
                    appendLog(n + " bulgu raporlandı (ayrıca 'Findings' sekmesi + Burp Issues):");
                    for (Finding f : result.findings) {
                        appendLog("  • [" + f.getSeverity() + "] " + f.getType());
                    }
                    statusLabel.setText(I18n.t("run.site.completed", n));
                }
                approveBtn.setEnabled(false);
                abortBtn.setEnabled(false);
            }
        });
    }

    private static class ResultRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean sel,
                boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, sel, focus, row, col);
            String s = value == null ? "" : value.toString().toLowerCase();
            if (s.contains("vulnerable") || s.contains("zafiyet")) {
                c.setForeground(new Color(0xE53935));
            } else if (s.contains("safe") || s.contains("güvenli")) {
                c.setForeground(new Color(0x43A047));
            } else if (s.contains("error") || s.contains("hata")) {
                c.setForeground(new Color(0xFB8C00));
            } else {
                c.setForeground(Color.GRAY);
            }
            return c;
        }
    }
}

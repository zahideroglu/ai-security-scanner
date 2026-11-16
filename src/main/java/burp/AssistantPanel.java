package burp;

import burp.ambient.BackgroundHunter;
import burp.ambient.Opportunity;
import burp.ambient.OpportunityQueue;
import burp.ambient.PassiveTriage;
import burp.ambient.TargetModel;
import burp.i18n.I18n;
import burp.i18n.I18nUI;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Ambient Security Copilot — the user-facing surface. Two stacked areas:
 *  - top: a live "Fırsatlar" table of endpoints {@link PassiveTriage} thinks are
 *    worth testing, with one-click actions (Test et / Hızlı tara / Yoksay);
 *  - bottom: a context-aware chat that injects the selected endpoint's
 *    {@link TargetModel} knowledge + prior findings into the prompt.
 *
 * Polls {@link OpportunityQueue#snapshot()} on a Swing timer (EDT) — no proxy
 * thread ever touches Swing. Actions delegate to {@link ScanManager}'s existing
 * daemon-threaded scan entry points and surface live in the Detection tab.
 *
 * @author Zahid Eroglu
 */
public class AssistantPanel extends JPanel {

    private final IBurpExtenderCallbacks callbacks;
    private final QwenAPIClient qwenClient;
    private final ScanManager scanManager;
    private final DatabaseManager databaseManager;
    private final TargetModel targetModel;
    private final OpportunityQueue queue;
    private final DetectionPanel detectionPanel;
    private final SettingsManager settingsManager;
    private final PrintWriter stdout;
    private final PrintWriter stderr;

    private final List<QwenAPIClient.Message> history = new ArrayList<QwenAPIClient.Message>();

    // Opportunities table
    private JTable oppTable;
    private DefaultTableModel oppModel;
    private final List<Opportunity> rowOps = new ArrayList<Opportunity>();
    private JLabel oppStatus;

    // Background hunter controls: ONE stop/resume toggle + terminate + live budget meter
    private volatile BackgroundHunter hunter;
    private JButton huntToggle;   // ⏸ Avlamayı Durdur ⟷ ▶ Avlamayı Sürdür (pause/resume)
    private JButton stopBtn;      // ⛔ Sonlandır (kill + disable setting)
    private JLabel meterLabel;

    // Chat
    private JTextPane chat;
    private StyledDocument doc;
    private JTextField input;
    private JButton sendButton;
    private JButton clearButton;
    private JLabel status;

    // ----- IDOR enrichment -------------------------------------------------
    // Confirmed IDOR/BOLA findings (any scan source) are announced once each in the chat feed;
    // suspected IDOR endpoints from passive triage are announced (throttled) as they appear and
    // their rows are highlighted in the Fırsatlar table. "🤖 IDOR'u açıkla" runs an on-demand AI deep-dive.
    private JButton explainIdorBtn;
    private final java.util.Set<String> announcedConfirmedIdor =
            java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final java.util.Set<String> announcedCandidateIdor =
            java.util.concurrent.ConcurrentHashMap.newKeySet();
    private volatile Finding lastIdorFinding;            // most recent confirmed IDOR (for AI explain)
    private volatile IHttpRequestResponse lastIdorMessage;
    private volatile Opportunity lastIdorCandidate;      // most recent suspected IDOR (fallback for AI explain)
    // Candidates the deep-dive has already filed as findings (dedup so re-clicking doesn't double-report).
    private final java.util.Set<String> copilotReportedKeys =
            java.util.Collections.synchronizedSet(new java.util.HashSet<String>());
    // Endpoints (host|path) that produced a CONFIRMED (non-suppressed) finding from ANY scan source →
    // their Fırsatlar row renders RED. Green = tested-clean (DONE, no finding), Yellow = pending candidate.
    private final java.util.Set<String> confirmedEndpoints =
            java.util.Collections.synchronizedSet(new java.util.HashSet<String>());
    private static final int CANDIDATE_ANNOUNCE_LIMIT = 3; // per refresh, to avoid flooding on history replay

    private static final String IDOR_EXPLAIN_SYSTEM =
            "You are an IDOR/BOLA (broken object-level authorization) specialist embedded in a Burp Suite " +
            "extension. Given one finding or candidate endpoint, decide whether it is a genuine IDOR and " +
            "explain it concretely: (1) verdict + why, (2) which foreign object/fields are exposed — cite " +
            "fields that appear in the tampered response but NOT in the negative-control/baseline, (3) exact " +
            "step-by-step verification & exploitation (show the tampered request and what a second identity " +
            "would prove), (4) business impact, (5) the precise server-side fix (per-object ownership check). " +
            "Be specific to THIS endpoint, not generic. Keep it tight. Answer in the user's language (Turkish). " +
            "AFTER the explanation, output EXACTLY ONE final line (no code fences) starting with the literal token " +
            "@@VERDICT@@ followed by a single compact JSON object: " +
            "{\"verdict\":\"vulnerable|not_vulnerable|uncertain\",\"severity\":\"High|Medium|Low\"," +
            "\"confidence\":0.0,\"summary\":\"one-sentence verdict\",\"evidence\":\"foreign object/fields exposed\"," +
            "\"verify\":\"how to confirm with a second identity\",\"remediation\":\"server-side fix\"}. " +
            "Use \"vulnerable\" ONLY when the evidence genuinely indicates cross-object / foreign-owner access; " +
            "otherwise use \"uncertain\" or \"not_vulnerable\". The summary/evidence/verify/remediation values " +
            "must be in the user's language (Turkish).";

    private static String[] columns() {
        return new String[]{
                I18n.t("copilot.col.score"), I18n.t("copilot.col.host"), I18n.t("copilot.col.method"),
                I18n.t("copilot.col.path"), I18n.t("copilot.col.class"), I18n.t("copilot.col.status")};
    }

    private static final String SYSTEM_PROMPT =
            "You are an ambient security-testing copilot embedded in a Burp Suite extension. " +
            "You watch the user's proxy traffic and help them find vulnerabilities Burp's scanner misses " +
            "(access control/IDOR/BOLA, business logic, auth/JWT, multi-step). When a target endpoint is " +
            "provided in context, give concrete, endpoint-specific testing advice. Be practical and concise. " +
            "Answer in the user's language.";

    public AssistantPanel(IBurpExtenderCallbacks callbacks, QwenAPIClient qwenClient,
                          ScanManager scanManager, DatabaseManager databaseManager,
                          TargetModel targetModel, OpportunityQueue queue,
                          DetectionPanel detectionPanel, SettingsManager settingsManager,
                          PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.qwenClient = qwenClient;
        this.scanManager = scanManager;
        this.databaseManager = databaseManager;
        this.targetModel = targetModel;
        this.queue = queue;
        this.detectionPanel = detectionPanel;
        this.settingsManager = settingsManager;
        this.stdout = stdout;
        this.stderr = stderr;
        resetHistory();
        initializeUI();
        startRefreshTimer();
        appendStyled(I18n.t("copilot.role.copilot"), roleCopilotColor(),
                I18n.t("copilot.welcome"));
    }

    private void resetHistory() {
        history.clear();
        history.add(new QwenAPIClient.Message("system", SYSTEM_PROMPT));
    }

    private void initializeUI() {
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);
        header.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));
        JLabel title = I18nUI.text(new JLabel(), "copilot.header.title");
        title.setFont(new Font("Segoe UI", Font.BOLD, 17));
        JLabel subtitle = I18nUI.text(new JLabel(), "copilot.header.subtitle");
        subtitle.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        subtitle.setForeground(Color.GRAY);
        JPanel titleBox = new JPanel();
        titleBox.setOpaque(false);
        titleBox.setLayout(new BoxLayout(titleBox, BoxLayout.Y_AXIS));
        title.setAlignmentX(LEFT_ALIGNMENT);
        subtitle.setAlignmentX(LEFT_ALIGNMENT);
        titleBox.add(title);
        titleBox.add(subtitle);
        status = new JLabel(" ");
        status.setFont(new Font("Segoe UI", Font.ITALIC, 12));
        status.setForeground(Color.GRAY);
        header.add(titleBox, BorderLayout.WEST);
        header.add(status, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildOpportunities(), buildChat());
        split.setResizeWeight(0.42);
        split.setBorder(null);
        add(split, BorderLayout.CENTER);
    }

    // ----- opportunities table ---------------------------------------------

    private JComponent buildOpportunities() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));

        JPanel top = new JPanel(new BorderLayout());
        JLabel label = I18nUI.text(new JLabel(), "copilot.opp.title");
        label.setFont(new Font("Segoe UI", Font.BOLD, 13));
        oppStatus = new JLabel(" ");
        oppStatus.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        oppStatus.setForeground(Color.GRAY);
        top.add(label, BorderLayout.WEST);
        top.add(oppStatus, BorderLayout.EAST);
        panel.add(top, BorderLayout.NORTH);

        oppModel = new DefaultTableModel(columns(), 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        oppTable = new JTable(oppModel);
        oppTable.setRowHeight(24);
        oppTable.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        oppTable.setAutoCreateRowSorter(false);
        oppTable.setShowGrid(false);
        oppTable.setIntercellSpacing(new Dimension(0, 0));
        oppTable.setSelectionBackground(ColorScheme.TABLE_SELECTION_BG);
        oppTable.setSelectionForeground(ColorScheme.TABLE_SELECTION_FG);
        oppTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        oppTable.getTableHeader().setReorderingAllowed(false);
        oppTable.getColumnModel().getColumn(0).setMaxWidth(54);
        oppTable.getColumnModel().getColumn(2).setMaxWidth(70);
        // One renderer for all columns: tints suspected-IDOR rows + keeps the score-cell colouring.
        OppCellRenderer oppRenderer = new OppCellRenderer();
        for (int i = 0; i < oppTable.getColumnModel().getColumnCount(); i++) {
            oppTable.getColumnModel().getColumn(i).setCellRenderer(oppRenderer);
        }

        oppTable.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    testSelected(true);
                } else if (SwingUtilities.isRightMouseButton(e)) {
                    int row = oppTable.rowAtPoint(e.getPoint());
                    if (row >= 0) oppTable.setRowSelectionInterval(row, row);
                    showPopup(e);
                }
            }
            @Override public void mousePressed(MouseEvent e) { if (e.isPopupTrigger()) showPopup(e); }
            @Override public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) showPopup(e); }
        });

        JScrollPane scroll = new JScrollPane(oppTable);
        scroll.setBorder(BorderFactory.createLineBorder(new Color(0xCCCCCC)));
        panel.add(scroll, BorderLayout.CENTER);

        // Hunter control bar: ONE stop/resume toggle (+ terminate) + live budget meter
        JPanel ctl = new JPanel(new BorderLayout(6, 0));
        ctl.setOpaque(false);
        ctl.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        btns.setOpaque(false);
        // Primary action: launch a whole-application IDOR/BAC/BOLA scenario from the Copilot.
        JButton scenarioBtn = I18nUI.text(new JButton(), "copilot.btn.scenario");
        styleButton(scenarioBtn, ColorScheme.PRIMARY_BLUE);
        I18nUI.tip(scenarioBtn, "copilot.btn.scenario.tip");
        scenarioBtn.addActionListener(a -> runWholeAppIdorScenario());
        huntToggle = new JButton(I18n.t("copilot.hunt.pause"));
        stopBtn = new JButton(I18n.t("copilot.hunt.terminate"));
        styleButton(huntToggle, ColorScheme.WARNING_ORANGE);
        styleButton(stopBtn, ColorScheme.ERROR_RED);
        huntToggle.setEnabled(false);
        stopBtn.setEnabled(false);
        I18nUI.tip(huntToggle, "copilot.hunt.toggle.tip");
        I18nUI.tip(stopBtn, "copilot.hunt.terminate.tip");
        huntToggle.addActionListener(a -> toggleHunt());
        stopBtn.addActionListener(a -> killHunter());
        btns.add(scenarioBtn);
        btns.add(huntToggle);
        btns.add(stopBtn);
        meterLabel = new JLabel(" ");
        meterLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        meterLabel.setForeground(Color.GRAY);
        ctl.add(btns, BorderLayout.WEST);
        ctl.add(meterLabel, BorderLayout.EAST);
        panel.add(ctl, BorderLayout.SOUTH);
        return panel;
    }

    public void setHunter(BackgroundHunter h) { this.hunter = h; }

    private void killHunter() {
        if (hunter != null) hunter.kill();
        try {
            Settings s = settingsManager.getSettings();
            s.setAmbientHunterEnabled(false);
            settingsManager.saveSettings(s);
        } catch (Exception ignore) {
        }
        status.setText(I18n.t("copilot.status.huntTerminated"));
        updateMeter();
    }

    /** The single stop/resume toggle the user asked for: pause when running, resume when paused. */
    private void toggleHunt() {
        if (hunter == null || !hunter.isRunning()) return;
        if (hunter.isPaused()) {
            hunter.resume();
            status.setText(I18n.t("copilot.status.huntResumed"));
        } else {
            hunter.pause();
            status.setText(I18n.t("copilot.status.huntPaused"));
        }
        updateMeter();
    }

    /** Flat, colored button styling — consistent with the rest of the app (ColorScheme). */
    private void styleButton(JButton b, Color bg) {
        b.setBackground(bg);
        b.setForeground(Color.WHITE);
        b.setFont(new Font("Segoe UI", Font.BOLD, 12));
        b.setFocusPainted(false);
        b.setBorder(BorderFactory.createEmptyBorder(7, 14, 7, 14));
        b.setCursor(new Cursor(Cursor.HAND_CURSOR));
    }

    private void updateMeter() {
        if (hunter == null || !hunter.isRunning()) {
            meterLabel.setText(hunter == null ? " " : I18n.t("copilot.meter.hunterOff"));
            huntToggle.setText(I18n.t("copilot.hunt.pause"));
            huntToggle.setBackground(ColorScheme.WARNING_ORANGE);
            huntToggle.setEnabled(false);
            stopBtn.setEnabled(false);
            return;
        }
        boolean paused = hunter.isPaused();
        huntToggle.setEnabled(true);
        stopBtn.setEnabled(true);
        if (paused) {
            huntToggle.setText(I18n.t("copilot.hunt.resume"));
            huntToggle.setBackground(ColorScheme.SUCCESS_GREEN);
        } else {
            huntToggle.setText(I18n.t("copilot.hunt.pause"));
            huntToggle.setBackground(ColorScheme.WARNING_ORANGE);
        }
        long used = hunter.tokensUsed();
        long budget = hunter.tokenBudget();
        long remMs = hunter.deadlineRemainingMs();
        String tok = budget > 0 ? (used + "/" + budget) : (used + " (∞)");
        String time = remMs < 0 ? "∞" : (remMs / 60000) + I18n.t("copilot.meter.minutesSuffix");
        meterLabel.setText((paused ? I18n.t("copilot.meter.pausedPrefix") : "")
                + I18n.t("copilot.meter.token") + ": " + tok + " · " + I18n.t("copilot.meter.time") + ": " + time
                + " · " + I18n.t("copilot.meter.active") + ": " + hunter.activeCount()
                + " · " + I18n.t("copilot.meter.queue") + ": " + hunter.queueDepth());
    }

    private void showPopup(MouseEvent e) {
        Opportunity op = selectedOpportunity();
        if (op == null) return;
        JPopupMenu popup = new JPopupMenu();

        JMenuItem testItem = new JMenuItem(I18n.t("copilot.menu.test"));
        testItem.addActionListener(a -> testSelected(true));
        popup.add(testItem);

        JMenuItem fastItem = new JMenuItem(I18n.t("copilot.menu.fastScan"));
        fastItem.addActionListener(a -> testSelected(false));
        popup.add(fastItem);

        popup.addSeparator();
        JMenuItem ignoreItem = new JMenuItem(I18n.t("copilot.menu.ignore"));
        ignoreItem.addActionListener(a -> {
            queue.markIgnored(op.host, op.dedupKey());
            refreshOpportunities();
        });
        popup.add(ignoreItem);

        popup.show(e.getComponent(), e.getX(), e.getY());
    }

    /** Run an opportunity: agentic playbook hunt for logic/authz, deterministic for signature. */
    private void testSelected(boolean agentic) {
        Opportunity op = selectedOpportunity();
        if (op == null) return;
        IHttpRequestResponse rr = op.toRequestResponse();
        DetectionRunView view = detectionPanel.beginSingle(op.url, false);
        boolean signatureOnly = isSignatureOnly(op);
        if (agentic && !signatureOnly) {
            scanManager.runPlaybookHunt(rr, view);
        } else {
            scanManager.runActiveScan(rr, view);
        }
        op.status = Opportunity.Status.RUNNING;
        refreshOpportunities();
        status.setText(I18n.t("copilot.status.runningInDetection", op.method + " " + op.path));
    }

    private boolean isSignatureOnly(Opportunity op) {
        List<String> cs = op.getSuspectedClasses();
        if (cs.isEmpty()) return false;
        for (String c : cs) {
            if (!PassiveTriage.C_MISCONFIG.equals(c)) return false;
        }
        return true;
    }

    /**
     * Launch a whole-application IDOR/BAC/BOLA scenario for the selected (or top) opportunity's host:
     * a cross-owner ground-truth BOLA pass + a per-endpoint IDOR/BAC pass that swaps URL **and**
     * request-body ids (e.g. {@code customerId}). Two Detection sub-tabs open; findings surface here.
     */
    private void runWholeAppIdorScenario() {
        Opportunity op = selectedOpportunity();
        if (op == null && !rowOps.isEmpty()) op = rowOps.get(0); // default to the highest-scored endpoint
        if (op == null) {
            appendStyled(I18n.t("copilot.idor.role"), roleIdorColor(), I18n.t("copilot.idor.scenario.noTarget"));
            return;
        }
        IHttpRequestResponse seed = op.toRequestResponse();
        String host = op.host;
        DetectionRunView crossOwner = detectionPanel.beginSite(I18n.t("copilot.idor.scenario.crossTab", host));
        DetectionRunView perEndpoint = detectionPanel.beginSite(I18n.t("copilot.idor.scenario.perEndpointTab", host));
        scanManager.runIdorBolaScenario(seed, crossOwner, perEndpoint);
        appendStyled(I18n.t("copilot.idor.role"), roleIdorColor(), I18n.t("copilot.idor.scenario.intro", host));
        status.setText(I18n.t("copilot.idor.scenario.status", host));
    }

    private Opportunity selectedOpportunity() {
        int row = oppTable.getSelectedRow();
        if (row < 0 || row >= rowOps.size()) return null;
        return rowOps.get(row);
    }

    private javax.swing.Timer refreshTimer;

    private void startRefreshTimer() {
        refreshTimer = new Timer(1500, e -> refreshOpportunities());
        refreshTimer.setRepeats(true);
        refreshTimer.start();
    }

    /** Stop the opportunities refresh timer; call before discarding this panel (e.g. on a language rebuild). */
    public void stopRefreshTimer() {
        if (refreshTimer != null) { refreshTimer.stop(); refreshTimer = null; }
    }

    private void refreshOpportunities() {
        List<Opportunity> snap = queue.snapshot();
        // remember selection by endpoint identity
        Opportunity sel = selectedOpportunity();
        String selKey = sel == null ? null : (sel.host + "|" + sel.dedupKey());

        oppModel.setRowCount(0);
        rowOps.clear();
        int active = 0;
        List<Opportunity> freshIdor = new ArrayList<Opportunity>(); // new suspected-IDOR endpoints this refresh
        for (Opportunity op : snap) {
            if (op.status == Opportunity.Status.IGNORED) {
                // keep showing but de-emphasized; skip if you prefer hiding
            }
            oppModel.addRow(new Object[]{
                    op.score, op.host, op.method, op.path,
                    String.join(",", op.getSuspectedClasses()), statusText(op.status)});
            rowOps.add(op);
            if (op.status == Opportunity.Status.QUEUED || op.status == Opportunity.Status.NEW) active++;
            if (op.status != Opportunity.Status.IGNORED && isIdorCandidate(op)
                    && announcedCandidateIdor.add(op.host + "|" + op.dedupKey())) {
                freshIdor.add(op);
            }
        }
        announceIdorCandidates(freshIdor);
        // restore selection
        if (selKey != null) {
            for (int i = 0; i < rowOps.size(); i++) {
                Opportunity op = rowOps.get(i);
                if (selKey.equals(op.host + "|" + op.dedupKey())) {
                    oppTable.setRowSelectionInterval(i, i);
                    break;
                }
            }
        }
        oppStatus.setText(I18n.t("copilot.opp.status", snap.size(), active));
        updateMeter();
    }

    private String statusText(Opportunity.Status s) {
        switch (s) {
            case QUEUED:  return I18n.t("copilot.oppStatus.queued");
            case RUNNING: return I18n.t("copilot.oppStatus.running");
            case DONE:    return I18n.t("copilot.oppStatus.done");
            case IGNORED: return I18n.t("copilot.oppStatus.ignored");
            default:      return I18n.t("copilot.oppStatus.new");
        }
    }

    // ----- chat ------------------------------------------------------------

    private JComponent buildChat() {
        JPanel panel = new JPanel(new BorderLayout(0, 6));

        chat = new JTextPane();
        chat.setEditable(false);
        chat.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        chat.setMargin(new Insets(8, 8, 8, 8));
        chat.setBackground(ColorScheme.CONSOLE_BG);
        chat.setForeground(ColorScheme.CONSOLE_FG);
        chat.setCaretColor(ColorScheme.CONSOLE_FG);
        doc = chat.getStyledDocument();
        JScrollPane scroll = new JScrollPane(chat);
        scroll.setBorder(BorderFactory.createLineBorder(new Color(0xCCCCCC)));
        panel.add(scroll, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout(6, 0));
        bottom.setOpaque(false);
        input = new JTextField();
        input.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        I18nUI.tip(input, "copilot.input.tip");
        input.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
                BorderFactory.createEmptyBorder(7, 9, 7, 9)));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        buttons.setOpaque(false);
        explainIdorBtn = I18nUI.text(new JButton(), "copilot.btn.explainIdor");
        I18nUI.tip(explainIdorBtn, "copilot.btn.explainIdor.tip");
        styleButton(explainIdorBtn, roleIdorColor());
        explainIdorBtn.setEnabled(false); // enabled once any IDOR (confirmed or suspected) is seen
        sendButton = I18nUI.text(new JButton(), "copilot.btn.send");
        clearButton = I18nUI.text(new JButton(), "copilot.btn.clear");
        styleButton(sendButton, ColorScheme.PRIMARY_BLUE);
        clearButton.setFocusPainted(false);
        clearButton.setCursor(new Cursor(Cursor.HAND_CURSOR));
        buttons.add(explainIdorBtn);
        buttons.add(clearButton);
        buttons.add(sendButton);

        bottom.add(input, BorderLayout.CENTER);
        bottom.add(buttons, BorderLayout.EAST);
        panel.add(bottom, BorderLayout.SOUTH);

        input.addActionListener(e -> send());
        sendButton.addActionListener(e -> send());
        explainIdorBtn.addActionListener(e -> explainIdorWithAI());
        clearButton.addActionListener(e -> {
            resetHistory();
            chat.setText("");
            appendStyled(I18n.t("copilot.role.copilot"), roleCopilotColor(), I18n.t("copilot.chatCleared"));
        });
        return panel;
    }

    private void send() {
        final String text = input.getText().trim();
        if (text.isEmpty()) return;
        input.setText("");
        appendStyled(I18n.t("copilot.role.you"), roleYouColor(), text);
        history.add(new QwenAPIClient.Message("user", text));

        final Opportunity selected = selectedOpportunity(); // capture on EDT
        setBusy(true);

        new Thread(() -> {
            String reply;
            boolean ok = true;
            try {
                java.util.List<QwenAPIClient.Message> apiMessages =
                        new ArrayList<QwenAPIClient.Message>(history);
                String ctx = buildCopilotContext(selected);
                if (!ctx.isEmpty()) {
                    apiMessages.add(1, new QwenAPIClient.Message("system", ctx)); // after system prompt
                }
                org.json.JSONObject resp = qwenClient.chatCompletion(apiMessages);
                reply = resp.getJSONArray("choices").getJSONObject(0)
                        .getJSONObject("message").getString("content");
                history.add(new QwenAPIClient.Message("assistant", reply));
            } catch (Exception e) {
                ok = false;
                stderr.println("[Copilot] error: " + e.getMessage());
                reply = I18n.t("copilot.error.noReply", e.getMessage());
            }
            final String finalReply = reply;
            final boolean finalOk = ok;
            SwingUtilities.invokeLater(() -> {
                appendStyled(I18n.t("copilot.role.copilot"), finalOk ? roleCopilotColor() : roleErrColor(), finalReply);
                setBusy(false);
            });
        }, "copilot-chat").start();
    }

    /** Build a fresh per-message context block from the selected endpoint + target model + RAG. */
    private String buildCopilotContext(Opportunity op) {
        if (op == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("## SEÇİLİ HEDEF\n");
        sb.append("Endpoint: ").append(op.method).append(" ").append(op.url).append("\n");
        sb.append("Şüpheli sınıflar: ").append(op.getSuspectedClasses()).append("\n");
        if (op.rationale != null && !op.rationale.isEmpty()) {
            sb.append("Triyaj gerekçesi: ").append(op.rationale).append("\n");
        }
        try {
            TargetModel.HostInfo h = targetModel.peek(op.host);
            if (h != null) {
                sb.append("Host auth şeması: ").append(h.authScheme == null ? "bilinmiyor" : h.authScheme).append("\n");
                sb.append("Bu host'ta görülen uç sayısı: ").append(h.endpoints.size()).append("\n");
                if (!h.paramNames.isEmpty()) sb.append("Bilinen parametreler: ").append(h.paramNames).append("\n");
                if (h.context != null) sb.append("Recon: ").append(h.context.toString()).append("\n");
            }
        } catch (Exception ignore) {
        }
        try {
            String rag = scanManager.getRagContext(op.url, safe(op.request), "");
            if (rag != null && !rag.isEmpty()) sb.append("\n").append(rag);
        } catch (Exception ignore) {
        }
        return sb.toString();
    }

    private String safe(byte[] b) {
        try { return b != null ? new String(b, "UTF-8") : ""; } catch (Exception e) { return ""; }
    }

    private void setBusy(boolean busy) {
        input.setEnabled(!busy);
        sendButton.setEnabled(!busy);
        status.setText(busy ? I18n.t("copilot.status.typing") : " ");
        refreshExplainBtn();
        if (!busy) input.requestFocusInWindow();
    }

    /** Enable "IDOR'u açıkla" only when idle AND at least one IDOR (confirmed or suspected) is known. */
    private void refreshExplainBtn() {
        if (explainIdorBtn == null) return;
        explainIdorBtn.setEnabled(input != null && input.isEnabled()
                && (lastIdorFinding != null || lastIdorCandidate != null));
    }

    /** Non-modal notification for high-value events (uses Burp's native Alerts + status strip). */
    public void notifyCopilot(String text) {
        try { if (callbacks != null) callbacks.issueAlert(text); } catch (Exception ignore) {}
        SwingUtilities.invokeLater(() -> status.setText(text));
    }

    // Role label colors — brighter on dark theme, deeper on light theme so they stay readable.
    // (Dark branch returns the lighter Material-400 shade; the deep -800 shade is for light theme.)
    private static Color roleCopilotColor() { return ColorScheme.isDarkMode() ? new Color(0x66BB6A) : new Color(0x2E7D32); }
    private static Color roleYouColor()     { return ColorScheme.isDarkMode() ? new Color(0x42A5F5) : new Color(0x1565C0); }
    private static Color roleErrColor()     { return ColorScheme.isDarkMode() ? new Color(0xEF5350) : new Color(0xC62828); }
    private static Color roleIdorColor()    { return ColorScheme.isDarkMode() ? new Color(0xFF7043) : new Color(0xD84315); }
    private static Color idorRowBg()        { return ColorScheme.isDarkMode() ? new Color(0x4A2F22) : new Color(0xFFEAD9); }
    // Opportunity row tint by outcome: green = tested clean · yellow = suspected/pending · red = confirmed.
    private static Color cleanRowBg()       { return ColorScheme.isDarkMode() ? new Color(0x22361F) : new Color(0xDDF3DD); }
    private static Color candidateRowBg()   { return ColorScheme.isDarkMode() ? new Color(0x4A4422) : new Color(0xFFF4CC); }
    private static Color confirmedRowBg()   { return ColorScheme.isDarkMode() ? new Color(0x4A2424) : new Color(0xFAD4D4); }

    private void appendStyled(String role, Color roleColor, String message) {
        try {
            SimpleAttributeSet roleAttr = new SimpleAttributeSet();
            StyleConstants.setBold(roleAttr, true);
            StyleConstants.setForeground(roleAttr, roleColor);
            SimpleAttributeSet bodyAttr = new SimpleAttributeSet();
            StyleConstants.setForeground(bodyAttr, ColorScheme.CONSOLE_FG);
            doc.insertString(doc.getLength(), role + ": ", roleAttr);
            doc.insertString(doc.getLength(), message + "\n\n", bodyAttr);
            chat.setCaretPosition(doc.getLength());
        } catch (BadLocationException e) {
            // ignore
        }
    }

    // ----- IDOR enrichment -------------------------------------------------

    /**
     * Called by {@link ScanManager} (via the finding observer) for every non-suppressed reported
     * finding, from any scan source (deterministic engine, agentic pentester, autonomous hunter).
     * Announces each confirmed IDOR/BOLA once into the chat feed + a Burp alert. Invoked on a scan
     * thread — all Swing work is marshalled to the EDT.
     */
    public void onFindingReported(final Finding f, final IHttpRequestResponse msg) {
        if (f == null) return;
        recordConfirmedEndpoint(f, msg); // mark its Fırsatlar row RED — any confirmed (non-suppressed) finding
        if (!isIdorType(f.getType())) return;
        if (!announcedConfirmedIdor.add(idorKey(f))) return; // already announced this exact IDOR
        this.lastIdorFinding = f;
        this.lastIdorMessage = msg;
        try {
            if (callbacks != null) callbacks.issueAlert(I18n.t("copilot.idor.confirmed.alert", shortLoc(f)));
        } catch (Exception ignore) {
        }
        final String summary = buildConfirmedIdorSummary(f);
        SwingUtilities.invokeLater(() -> {
            appendStyled(I18n.t("copilot.idor.role"), roleIdorColor(), summary);
            status.setText(I18n.t("copilot.idor.confirmed.status", shortLoc(f)));
            refreshExplainBtn();
        });
    }

    /** Mark a finding's endpoint (host|path) confirmed so its Fırsatlar row renders RED. Any scan source. */
    private void recordConfirmedEndpoint(Finding f, IHttpRequestResponse msg) {
        String host = null, path = null;
        try {
            String url = (f == null) ? null : f.getAffectedUrl();
            if (url != null && !url.isEmpty()) {
                java.net.URL u = new java.net.URL(url);
                host = u.getHost(); path = u.getPath();
            }
        } catch (Exception ignore) { }
        if ((host == null || path == null) && msg != null && callbacks != null) {
            try {
                if (msg.getRequest() != null) {
                    java.net.URL u = callbacks.getHelpers().analyzeRequest(msg).getUrl();
                    if (u != null) { host = u.getHost(); path = u.getPath(); }
                }
            } catch (Exception ignore) { }
        }
        if (host != null && path != null) {
            confirmedEndpoints.add(host + "|" + path);
            SwingUtilities.invokeLater(() -> { if (oppTable != null) oppTable.repaint(); });
        }
    }

    private String buildConfirmedIdorSummary(Finding f) {
        StringBuilder sb = new StringBuilder();
        sb.append(I18n.t("copilot.idor.confirmed.title")).append("\n");
        sb.append("• ").append(I18n.t("copilot.idor.field.type")).append(": ")
          .append(f.getType()).append(" (").append(f.getSeverity()).append(")\n");
        String url = f.getAffectedUrl();
        if (url != null && !url.isEmpty()) {
            sb.append("• ").append(I18n.t("copilot.idor.field.location")).append(": ").append(url).append("\n");
        }
        sb.append("• ").append(I18n.t("copilot.idor.field.confidence")).append(": ")
          .append(String.format("%.0f%%", f.getConfidence() * 100))
          .append(" · Oracle: ").append(f.getOracleVerdict()).append("\n");
        String ev = f.getEvidence();
        if (ev != null && !ev.isEmpty()) {
            sb.append("• ").append(I18n.t("copilot.idor.field.evidence")).append(": ")
              .append(oneLine(ev, 300)).append("\n");
        }
        sb.append(I18n.t("copilot.idor.confirmed.verify")).append("\n");
        sb.append(I18n.t("copilot.idor.confirmed.cta"));
        return sb.toString();
    }

    /** Announce newly-seen suspected-IDOR endpoints (throttled per refresh). Runs on the EDT (Swing timer). */
    private void announceIdorCandidates(List<Opportunity> fresh) {
        if (fresh == null || fresh.isEmpty()) return;
        int shown = 0;
        for (Opportunity op : fresh) {
            if (shown >= CANDIDATE_ANNOUNCE_LIMIT) {
                appendStyled(I18n.t("copilot.idor.role"), roleIdorColor(),
                        I18n.t("copilot.idor.candidate.more", fresh.size() - CANDIDATE_ANNOUNCE_LIMIT));
                break;
            }
            lastIdorCandidate = op;
            appendStyled(I18n.t("copilot.idor.role"), roleIdorColor(), buildCandidateIdorSummary(op));
            shown++;
        }
        refreshExplainBtn();
    }

    private String buildCandidateIdorSummary(Opportunity op) {
        StringBuilder sb = new StringBuilder();
        sb.append(I18n.t("copilot.idor.candidate.title")).append(": ")
          .append(op.method).append(" ").append(op.path).append("\n");
        sb.append("• ").append(I18n.t("copilot.idor.field.host")).append(": ").append(op.host)
          .append(" · ").append(I18n.t("copilot.idor.field.score")).append(" ").append(op.score).append("\n");
        if (op.rationale != null && !op.rationale.isEmpty()) {
            sb.append("• ").append(I18n.t("copilot.idor.field.reason")).append(": ")
              .append(oneLine(op.rationale, 200)).append("\n");
        }
        sb.append(I18n.t("copilot.idor.candidate.cta"));
        return sb.toString();
    }

    /**
     * On-demand AI deep-dive of the most relevant IDOR: a selected IDOR row wins (explicit focus),
     * else the last confirmed finding, else the last suspected candidate. Reuses the chat client; one
     * AI call only when clicked (no passive token cost).
     */
    private void explainIdorWithAI() {
        Opportunity selOp = selectedOpportunity();
        final Opportunity cand;
        final Finding fin;
        final IHttpRequestResponse fmsg;
        if (selOp != null && isIdorCandidate(selOp)) {
            cand = selOp; fin = null; fmsg = null;
        } else if (lastIdorFinding != null) {
            fin = lastIdorFinding; fmsg = lastIdorMessage; cand = null;
        } else if (lastIdorCandidate != null) {
            cand = lastIdorCandidate; fin = null; fmsg = null;
        } else {
            appendStyled(I18n.t("copilot.role.copilot"), roleCopilotColor(), I18n.t("copilot.idor.none"));
            return;
        }
        String youLine = (fin != null)
                ? I18n.t("copilot.idor.explain.you", shortLoc(fin))
                : I18n.t("copilot.idor.explain.candidateYou", cand.method + " " + cand.path);
        appendStyled(I18n.t("copilot.role.you"), roleYouColor(), youLine);
        setBusy(true);
        new Thread(() -> {
            String reply;
            boolean ok = true;
            try {
                java.util.List<QwenAPIClient.Message> msgs = new ArrayList<QwenAPIClient.Message>();
                msgs.add(new QwenAPIClient.Message("system", IDOR_EXPLAIN_SYSTEM));
                msgs.add(new QwenAPIClient.Message("user", buildIdorExplainPrompt(fin, fmsg, cand)));
                org.json.JSONObject resp = qwenClient.chatCompletion(msgs);
                reply = resp.getJSONArray("choices").getJSONObject(0)
                        .getJSONObject("message").getString("content");
            } catch (Exception e) {
                ok = false;
                stderr.println("[Copilot] IDOR explain error: " + e.getMessage());
                reply = I18n.t("copilot.error.noReply", e.getMessage());
            }

            // If the deep-dive judged this a GENUINE IDOR, file it to the Findings panel + Burp.
            // Only suspected candidates are filed here — a confirmed finding (fin != null) is already
            // in the panel. The verdict is AI judgement from observed traffic (not an active re-test),
            // so the finding is reported INCONCLUSIVE with capped confidence (stays honest / no FP inflation).
            String displayReply = reply;
            String filedNote = null;
            if (ok) {
                try {
                    org.json.JSONObject verdict = extractVerdict(reply);
                    displayReply = stripVerdictLine(reply);
                    if (verdict != null && cand != null
                            && "vulnerable".equalsIgnoreCase(verdict.optString("verdict"))) {
                        // Do NOT file on the AI opinion alone — that filed public-product / own-data FPs from
                        // un-tampered observed traffic. ACTIVELY verify with the hardened ownership-aware
                        // engine (id swap + invalid-id control + anonymous public probe + foreign-owner-token
                        // + AI confirm). Only a survivor is filed; a public/own-data candidate is explained
                        // in chat but not reported.
                        Finding nf = scanManager.verifyIdorCandidate(cand.toRequestResponse());
                        if (nf != null && scanManager.reportFindingDeduped(cand.toRequestResponse(), nf,
                                "copilot-idor", "Copilot IDOR", copilotReportedKeys)) {
                            filedNote = I18n.t("copilot.idor.reported", cand.method + " " + cand.path);
                        } else {
                            filedNote = I18n.t("copilot.idor.unconfirmed", cand.method + " " + cand.path);
                        }
                    }
                } catch (Exception ex) {
                    stderr.println("[Copilot] IDOR report error: " + ex.getMessage());
                }
            }

            final String finalReply = displayReply;
            final boolean finalOk = ok;
            final String finalFiled = filedNote;
            SwingUtilities.invokeLater(() -> {
                appendStyled(I18n.t("copilot.idor.role"), finalOk ? roleIdorColor() : roleErrColor(), finalReply);
                if (finalFiled != null) {
                    appendStyled(I18n.t("copilot.idor.role"), roleIdorColor(), finalFiled);
                }
                setBusy(false);
            });
        }, "copilot-idor-explain").start();
    }

    /** Build the AI prompt for a confirmed finding (with bodies + negative control) or a candidate endpoint. */
    private String buildIdorExplainPrompt(Finding f, IHttpRequestResponse msg, Opportunity cand) {
        StringBuilder sb = new StringBuilder();
        if (f != null) {
            sb.append("CONFIRMED FINDING\n");
            sb.append("Type: ").append(f.getType()).append(" (").append(f.getSeverity()).append(")\n");
            if (f.getAffectedUrl() != null) sb.append("URL: ").append(f.getAffectedUrl()).append("\n");
            sb.append("Confidence: ").append(String.format("%.0f%%", f.getConfidence() * 100))
              .append(" · Oracle verdict: ").append(f.getOracleVerdict()).append("\n");
            if (f.getEvidence() != null) sb.append("Evidence: ").append(oneLine(f.getEvidence(), 500)).append("\n");
            if (f.getDescription() != null)
                sb.append("Detector note: ").append(oneLine(f.getDescription(), 500)).append("\n");
            String req = (msg != null && msg.getRequest() != null) ? safe(msg.getRequest()) : null;
            if (req != null && !req.isEmpty())
                sb.append("\n-- Tampered request --\n").append(cut(req, 1500)).append("\n");
            String resp = f.getHttpResponse();
            if (resp != null && !resp.isEmpty())
                sb.append("\n-- Tampered response (id swapped) --\n").append(cut(resp, 1500)).append("\n");
            String ctrl = f.getControlResponse();
            if (ctrl != null && !ctrl.isEmpty())
                sb.append("\n-- Negative-control response (definitely-invalid id) --\n").append(cut(ctrl, 1200)).append("\n");
            sb.append("\nIs this a real IDOR? Explain per the system instructions.");
        } else {
            sb.append("CANDIDATE ENDPOINT (suspected by passive triage — NOT yet verified)\n");
            sb.append("Endpoint: ").append(cand.method).append(" ").append(cand.url).append("\n");
            sb.append("Suspected classes: ").append(cand.getSuspectedClasses()).append("\n");
            if (cand.rationale != null) sb.append("Why flagged: ").append(cand.rationale).append("\n");
            String req = (cand.request != null) ? safe(cand.request) : null;
            if (req != null && !req.isEmpty())
                sb.append("\n-- Observed request --\n").append(cut(req, 1500)).append("\n");
            sb.append("\nHow likely is IDOR here, which identifier should I tamper, and exactly how do I verify it ")
              .append("(negative control + a second identity)? Explain per the system instructions.");
        }
        return sb.toString();
    }

    // ----- deep-dive verdict → reported finding ----------------------------

    /** Extract the trailing {@code @@VERDICT@@ {json}} machine verdict the deep-dive appends; null if absent/invalid. */
    private static org.json.JSONObject extractVerdict(String reply) {
        if (reply == null) return null;
        int i = reply.lastIndexOf("@@VERDICT@@");
        if (i < 0) return null;
        String tail = reply.substring(i + "@@VERDICT@@".length()).trim();
        int b = tail.indexOf('{'), e = tail.lastIndexOf('}');
        if (b < 0 || e <= b) return null;
        try {
            return new org.json.JSONObject(tail.substring(b, e + 1));
        } catch (Exception ex) {
            return null;
        }
    }

    /** The chat shows only the human explanation — drop the machine-verdict line. */
    private static String stripVerdictLine(String reply) {
        if (reply == null) return "";
        int i = reply.lastIndexOf("@@VERDICT@@");
        return (i < 0) ? reply : reply.substring(0, i).trim();
    }

    // The Copilot deep-dive no longer fabricates a Finding from the AI verdict on un-tampered traffic
    // (that produced public-product / own-data false positives). It now calls
    // ScanManager.verifyIdorCandidate(...), which ACTIVELY re-tests the candidate through the hardened,
    // ownership-aware engine and only returns a Finding when it is proven — so this builder is gone.

    // ----- IDOR helpers ----------------------------------------------------

    /** True for access-control / IDOR / BOLA finding types (object-level authorization family). */
    private static boolean isIdorType(String type) {
        if (type == null) return false;
        String t = type.toLowerCase();
        return t.contains("idor") || t.contains("bola") || t.contains("object reference")
                || t.contains("object level") || t.contains("broken access control")
                || t.contains("horizontal access");
    }

    private static boolean isIdorCandidate(Opportunity op) {
        return op != null && op.getSuspectedClasses().contains(PassiveTriage.C_IDOR);
    }

    /** Stable dedup key so the same IDOR is announced only once (bounded length). */
    private static String idorKey(Finding f) {
        String url = f.getAffectedUrl() == null ? "" : f.getAffectedUrl();
        String ev = f.getEvidence() == null ? "" : f.getEvidence();
        String key = f.getType() + "|" + url + "|" + ev;
        return key.length() > 240 ? key.substring(0, 240) : key;
    }

    /** host + path of a finding's URL (for compact alerts/status). */
    private static String shortLoc(Finding f) {
        String url = f.getAffectedUrl();
        if (url == null || url.isEmpty()) return f.getType();
        try {
            java.net.URL u = new java.net.URL(url);
            String p = u.getPath();
            return u.getHost() + (p == null ? "" : p);
        } catch (Exception e) {
            return url;
        }
    }

    private static String oneLine(String s, int max) {
        if (s == null) return "";
        String t = s.replaceAll("\\s+", " ").trim();
        return t.length() > max ? t.substring(0, max) + "…" : t;
    }

    private static String cut(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "\n…(truncated)" : s;
    }

    private boolean isConfirmedEndpoint(Opportunity op) {
        return op != null && confirmedEndpoints.contains(op.host + "|" + op.path);
    }

    /**
     * Row tint by testing OUTCOME (null = no tint). Precedence: a confirmed finding wins (RED), else a
     * tested endpoint with nothing found is clean (GREEN), else a still-pending suspected endpoint is a
     * candidate (YELLOW). Ignored rows stay untinted.
     */
    private Color rowOutcomeBg(int row) {
        if (row < 0 || row >= rowOps.size()) return null;
        Opportunity op = rowOps.get(row);
        if (op == null || op.status == Opportunity.Status.IGNORED) return null;
        if (isConfirmedEndpoint(op)) return confirmedRowBg();              // tespit edildi → kırmızı
        if (op.status == Opportunity.Status.DONE) return cleanRowBg();     // test edildi, temiz → yeşil
        if (!op.getSuspectedClasses().isEmpty()) return candidateRowBg();  // aday (sırada/çalışıyor) → sarı
        return null;
    }

    /** One renderer for the whole table: tints each row by outcome (green/yellow/red) + colours the score cell. */
    private final class OppCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                Color bg = rowOutcomeBg(row);
                c.setBackground(bg != null ? bg : table.getBackground());
                if (column == 0) {
                    int score = 0;
                    try { score = Integer.parseInt(String.valueOf(value)); } catch (Exception ignore) {}
                    if (score >= 70) c.setForeground(new Color(0xC0392B));
                    else if (score >= 40) c.setForeground(new Color(0xB9770E));
                    else c.setForeground(new Color(0x7F8C8D));
                } else {
                    c.setForeground(table.getForeground());
                }
            }
            setHorizontalAlignment(column == 0 ? CENTER : LEFT);
            return c;
        }
    }
}

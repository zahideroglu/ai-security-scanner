package burp.authz;

import burp.ColorScheme;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.Settings;
import burp.SettingsManager;
import burp.i18n.Glyphs;
import burp.i18n.I18n;
import burp.i18n.I18nUI;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * User-friendly manager for the AI-Pentester login profiles (and the agent's max-steps / model),
 * opened as a modal popup from the "Yetki Matrisi" (Authorization Matrix) tab — the place these
 * profiles are actually used (they mint FRESH sessions per scan for the matrix / BOLA hunts).
 *
 * Replaces the old hand-written escaped-JSON textarea in Settings with a table the user can manage
 * with Add (capture-from-history wizard) / Edit / Delete / Test buttons. The raw JSON array stays
 * available behind an "Advanced" button for power users. Persists directly via {@link SettingsManager}.
 *
 * @author Zahid Eroglu
 */
public class LoginProfilesDialog extends JDialog {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final PrintWriter stdout;
    private final PrintWriter stderr;
    private final SettingsManager settingsManager;

    /** In-memory working copy; committed to Settings only on Save. */
    private final List<LoginProfile> profiles = new ArrayList<>();

    private final DefaultTableModel tableModel = new DefaultTableModel(
            new Object[]{I18n.t("login.mgr.col.role"), I18n.t("login.mgr.col.url"),
                    I18n.t("login.mgr.col.user"), I18n.t("login.mgr.col.token")}, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable table = new JTable(tableModel);
    private JComboBox<Integer> maxStepsCombo;
    private JTextField agentModelField;
    private final JLabel statusLbl = new JLabel(" ");

    public LoginProfilesDialog(Window owner, IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                               PrintWriter stdout, PrintWriter stderr, SettingsManager settingsManager) {
        super(owner, I18n.t("login.mgr.title"), ModalityType.APPLICATION_MODAL);
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
        this.stderr = stderr;
        this.settingsManager = settingsManager;
        loadFromSettings();
        buildUI();
        refreshTable();
        sizeToScreen(this, 760, 640);
        setMinimumSize(new Dimension(680, 480));
        setLocationRelativeTo(owner);
    }

    private Settings settings() {
        Settings s = settingsManager.getSettings();
        return s != null ? s : settingsManager.loadSettings();
    }

    private void loadFromSettings() {
        Settings s = settings();
        profiles.clear();
        if (s != null) profiles.addAll(LoginProfile.listFromJson(s.getLoginProfilesJson()));
    }

    // ---- layout ------------------------------------------------------------

    private void buildUI() {
        JPanel content = new JPanel(new BorderLayout(0, 10));
        content.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));
        content.setBackground(ColorScheme.BG_CARD);

        content.add(buildHeader(), BorderLayout.NORTH);
        content.add(buildCenter(), BorderLayout.CENTER);
        content.add(buildSouth(), BorderLayout.SOUTH);

        setContentPane(content);
    }

    private JComponent buildHeader() {
        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        north.setBackground(ColorScheme.BG_CARD);

        JTextArea intro = I18nUI.multiline("login.mgr.intro");
        intro.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        intro.setForeground(ColorScheme.TEXT_DARK);
        intro.setAlignmentX(Component.LEFT_ALIGNMENT);
        north.add(intro);
        north.add(Box.createVerticalStrut(10));

        // ── AI Pentester agent config (max steps + model) ──
        JPanel agent = new JPanel(new GridBagLayout());
        agent.setBackground(ColorScheme.BG_CARD);
        agent.setAlignmentX(Component.LEFT_ALIGNMENT);
        agent.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT),
                        I18n.t("settings.agent.title")),
                BorderFactory.createEmptyBorder(6, 8, 8, 8)));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 4, 3, 4);
        g.anchor = GridBagConstraints.WEST;

        g.gridx = 0; g.gridy = 0;
        agent.add(agentLabel(I18n.t("settings.agent.maxsteps")), g);
        maxStepsCombo = new JComboBox<>(new Integer[]{10, 15, 20, 30, 40, 60});
        g.gridx = 1; g.gridy = 0; g.fill = GridBagConstraints.NONE;
        agent.add(maxStepsCombo, g);

        g.gridx = 0; g.gridy = 1; g.fill = GridBagConstraints.NONE;
        agent.add(agentLabel(I18n.t("settings.agent.model")), g);
        agentModelField = new JTextField(22);
        g.gridx = 1; g.gridy = 1; g.weightx = 1.0; g.fill = GridBagConstraints.HORIZONTAL;
        agent.add(agentModelField, g);

        Settings s = settings();
        if (s != null) {
            maxStepsCombo.setSelectedItem(s.getAgentMaxSteps());
            agentModelField.setText(s.getAgentModelRaw());
        }
        north.add(agent);
        north.add(Box.createVerticalStrut(12));

        JLabel listLbl = I18nUI.text(new JLabel(), "login.mgr.profilesLabel");
        listLbl.setFont(new Font("Segoe UI", Font.BOLD, 12));
        listLbl.setForeground(ColorScheme.TEXT_DARK);
        listLbl.setAlignmentX(Component.LEFT_ALIGNMENT);
        north.add(listLbl);

        return north;
    }

    private JLabel agentLabel(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(ColorScheme.TEXT_DARK);
        l.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        return l;
    }

    private JComponent buildCenter() {
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setRowHeight(24);
        table.setBackground(ColorScheme.BG_CARD);
        table.setForeground(ColorScheme.TEXT_PRIMARY);
        table.setGridColor(ColorScheme.BORDER_DARKER);
        table.setSelectionBackground(ColorScheme.PRIMARY_BLUE);
        table.setSelectionForeground(Color.WHITE);
        table.getTableHeader().setReorderingAllowed(false);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        if (table.getTableHeader() != null) {
            table.getTableHeader().setBackground(ColorScheme.BG_LIGHT);
            table.getTableHeader().setForeground(ColorScheme.TEXT_PRIMARY);
        }
        // Double-click a row to edit it.
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) editSelected();
            }
        });
        JScrollPane sp = new JScrollPane(table);
        sp.getViewport().setBackground(ColorScheme.BG_CARD);
        sp.setBorder(BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT));

        // action buttons row
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        btns.setBackground(ColorScheme.BG_CARD);
        JButton add = primaryButton(I18n.t("login.mgr.add"));
        JButton edit = plainButton(I18n.t("login.mgr.edit"));
        JButton copy = plainButton("Kopyala");
        JButton del = plainButton(I18n.t("login.mgr.delete"));
        JButton test = plainButton(I18n.t("login.mgr.test"));
        JButton adv = plainButton(I18n.t("login.mgr.advanced"));
        add.addActionListener(e -> openProfileEditor(null));
        edit.addActionListener(e -> editSelected());
        copy.addActionListener(e -> copySelected());
        del.addActionListener(e -> deleteSelected());
        test.addActionListener(e -> testSelected());
        adv.addActionListener(e -> openAdvancedJson());
        btns.add(add); btns.add(edit); btns.add(copy); btns.add(del); btns.add(test); btns.add(adv);

        JPanel center = new JPanel(new BorderLayout(0, 6));
        center.setBackground(ColorScheme.BG_CARD);
        center.add(sp, BorderLayout.CENTER);
        center.add(btns, BorderLayout.SOUTH);
        return center;
    }

    private JComponent buildSouth() {
        statusLbl.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        statusLbl.setForeground(ColorScheme.TEXT_SECONDARY);

        JButton save = primaryButton(I18n.t("login.mgr.save"));
        save.setBackground(ColorScheme.SUCCESS_GREEN);
        JButton close = plainButton(I18n.t("login.mgr.close"));
        save.addActionListener(e -> save());
        close.addActionListener(e -> dispose());

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        bar.setBackground(ColorScheme.BG_CARD);
        bar.add(close);
        bar.add(save);

        JPanel south = new JPanel(new BorderLayout(0, 6));
        south.setBackground(ColorScheme.BG_CARD);
        south.add(statusLbl, BorderLayout.NORTH);
        south.add(bar, BorderLayout.SOUTH);
        return south;
    }

    private JButton primaryButton(String text) {
        JButton b = new JButton(text);
        b.setFont(new Font("Segoe UI", Font.BOLD, 12));
        b.setBackground(ColorScheme.PRIMARY_BLUE);
        b.setForeground(Color.WHITE);
        b.setOpaque(true);
        b.setBorderPainted(false);
        b.setFocusPainted(false);
        return b;
    }

    private JButton plainButton(String text) {
        JButton b = new JButton(text);
        b.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        return b;
    }

    /** Size a window to the preferred dimensions but never larger than the usable screen (keeps it fully visible). */
    private static void sizeToScreen(Window w, int prefW, int prefH) {
        Rectangle scr = GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();
        w.setSize(Math.min(prefW, scr.width - 40), Math.min(prefH, scr.height - 40));
    }

    /**
     * Truncate the MIDDLE of a long string (keep head + tail with "…" between) so URLs that share a
     * long common prefix still show their distinguishing tail. Head-only truncation made every
     * Gateway row look identical.
     */
    private static String midEllipsis(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        int tail = Math.max(12, (int) Math.round((max - 1) * 0.62)); // favour the end (the part that differs)
        int head = Math.max(8, max - 1 - tail);
        return s.substring(0, head) + "…" + s.substring(s.length() - tail);
    }

    /**
     * A scroll-pane body that always fills the viewport WIDTH (so {@code weightx} form fields stretch to
     * full width instead of shrinking to their text) while still scrolling VERTICALLY when too tall.
     */
    private static final class WidthTrackingPanel extends JPanel implements Scrollable {
        WidthTrackingPanel(LayoutManager lm) { super(lm); }
        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle r, int orientation, int dir) { return 16; }
        @Override public int getScrollableBlockIncrement(Rectangle r, int orientation, int dir) { return 120; }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() {
            // Fill the viewport when we're SHORTER than it (so the weighty body row can grow to use the
            // space); only scroll when the content is genuinely taller than the viewport.
            return getParent() instanceof JViewport && getParent().getHeight() > getPreferredSize().height;
        }
    }

    // ---- table model glue --------------------------------------------------

    private void refreshTable() {
        tableModel.setRowCount(0);
        for (LoginProfile p : profiles) {
            String url = p.loginUrl;
            String tok;
            if (p.isMultiStep()) {
                if (url == null || url.trim().isEmpty()) url = p.steps.get(0).url;   // show the chain's first step
                url = "⛓ " + p.steps.size() + " adım · " + url;
                tok = p.sessionTokenVar == null || p.sessionTokenVar.isEmpty() ? "?" : "{" + p.sessionTokenVar + "}";
            } else {
                tok = (p.tokenJsonPath != null && !p.tokenJsonPath.isEmpty())
                        ? p.tokenJsonPath
                        : (p.tokenRegex != null && !p.tokenRegex.isEmpty() ? "regex" : "—");
            }
            tableModel.addRow(new Object[]{p.roleName, url, p.username, tok});
        }
        statusLbl.setText(profiles.isEmpty() ? I18n.t("login.mgr.empty")
                : I18n.t("login.mgr.count", profiles.size()));
        statusLbl.setForeground(ColorScheme.TEXT_SECONDARY);
    }

    private LoginProfile selectedProfile() {
        int row = table.getSelectedRow();
        if (row < 0) return null;
        int mr = table.convertRowIndexToModel(row);
        return (mr >= 0 && mr < profiles.size()) ? profiles.get(mr) : null;
    }

    /** A non-empty roleName unique among the working profiles (excluding {@code keep}); appends -2,-3… on collision. */
    private String uniqueRole(String desired, LoginProfile keep) {
        String base = (desired == null || desired.trim().isEmpty()) ? "user" : desired.trim();
        String candidate = base;
        int n = 2;
        while (collidesRole(candidate, keep)) candidate = base + "-" + (n++);
        return candidate;
    }

    private boolean collidesRole(String role, LoginProfile keep) {
        for (LoginProfile q : profiles) {
            if (q == keep) continue;
            if (q.roleName != null && q.roleName.equalsIgnoreCase(role)) return true;
        }
        return false;
    }

    private void editSelected() {
        LoginProfile p = selectedProfile();
        if (p == null) { warnSelectRow(); return; }
        openProfileEditor(p);
    }

    /** Duplicate the selected profile under a new unique role name (e.g. "User 2 (kopya)"). */
    private void copySelected() {
        LoginProfile src = selectedProfile();
        if (src == null) { warnSelectRow(); return; }
        LoginProfile dup = LoginProfile.fromJSON(src.toJSON());          // deep copy via JSON round-trip
        dup.roleName = uniqueRole((src.roleName == null || src.roleName.trim().isEmpty()
                ? "user" : src.roleName.trim()) + " (kopya)", null);
        profiles.add(dup);
        refreshTable();
        int idx = profiles.indexOf(dup);                                 // select + reveal the new row
        if (idx >= 0) {
            int vr = table.convertRowIndexToView(idx);
            if (vr >= 0) { table.setRowSelectionInterval(vr, vr); table.scrollRectToVisible(table.getCellRect(vr, 0, true)); }
        }
        statusLbl.setText("Profil kopyalandı: " + dup.roleName + " — düzenleyip Kaydet'e basın.");
        statusLbl.setForeground(ColorScheme.SUCCESS_GREEN);
    }

    private void deleteSelected() {
        LoginProfile p = selectedProfile();
        if (p == null) { warnSelectRow(); return; }
        int ans = JOptionPane.showConfirmDialog(this,
                I18n.t("login.mgr.deleteConfirm", p.roleName),
                I18n.t("login.mgr.delete"), JOptionPane.YES_NO_OPTION);
        if (ans == JOptionPane.YES_OPTION) {
            profiles.remove(p);
            refreshTable();
        }
    }

    private void warnSelectRow() {
        statusLbl.setText(I18n.t("login.mgr.selectRow"));
        statusLbl.setForeground(ColorScheme.SEVERITY_MEDIUM);
    }

    /** Test the selected profile (or all profiles if none selected); show results in a dialog. */
    private void testSelected() {
        final List<LoginProfile> toTest = new ArrayList<>();
        LoginProfile sel = selectedProfile();
        if (sel != null) toTest.add(sel);
        else toTest.addAll(profiles);
        if (toTest.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18n.t("settings.login.empty"),
                    I18n.t("settings.login.test.title"), JOptionPane.WARNING_MESSAGE);
            return;
        }
        statusLbl.setText(I18n.t("login.wizard.testing"));
        statusLbl.setForeground(ColorScheme.TEXT_DARK);
        new Thread(() -> {
            LoginManager lm = new LoginManager(callbacks, helpers, stdout, stderr);
            StringBuilder sb = new StringBuilder();
            for (LoginProfile p : toTest) {
                LoginManager.LoginResult r = lm.test(p);
                sb.append(r.ok ? Glyphs.ok() + " " : Glyphs.fail() + " ").append(p.roleName).append(" — ")
                  .append(r.ok ? I18n.t("settings.login.token", r.detail) : I18n.t("settings.login.error", r.detail))
                  .append("\n");
            }
            final String msg = sb.toString().trim();
            SwingUtilities.invokeLater(() -> {
                statusLbl.setText(" ");
                JOptionPane.showMessageDialog(this, msg, I18n.t("settings.login.results.title"),
                        JOptionPane.INFORMATION_MESSAGE);
            });
        }, "login-mgr-test").start();
    }

    private void save() {
        Settings s = settings();
        if (s == null) { dispose(); return; }
        org.json.JSONArray arr = new org.json.JSONArray();
        for (LoginProfile p : profiles) arr.put(p.toJSON());
        s.setLoginProfilesJson(arr.toString());
        if (maxStepsCombo.getSelectedItem() != null) {
            s.setAgentMaxSteps((Integer) maxStepsCombo.getSelectedItem());
        }
        s.setAgentModel(agentModelField.getText().trim());
        settingsManager.saveSettings(s);
        if (stdout != null) stdout.println("[LoginProfiles] Saved " + profiles.size() + " profile(s)");
        JOptionPane.showMessageDialog(this, I18n.t("login.mgr.saved"),
                I18n.t("login.mgr.title"), JOptionPane.INFORMATION_MESSAGE);
        dispose();
    }

    // ---- advanced raw-JSON editor (power-user escape hatch) -----------------

    private void openAdvancedJson() {
        final JDialog dlg = new JDialog(this, I18n.t("login.mgr.advanced.title"), ModalityType.APPLICATION_MODAL);
        sizeToScreen(dlg, 680, 480);
        dlg.setMinimumSize(new Dimension(520, 360));
        dlg.setLocationRelativeTo(this);

        org.json.JSONArray arr = new org.json.JSONArray();
        for (LoginProfile p : profiles) arr.put(p.toJSON());
        final JTextArea area = new JTextArea(arr.toString(2));
        area.setFont(new Font("Monospaced", Font.PLAIN, 12));
        area.setLineWrap(true);

        JTextArea help = I18nUI.multiline("settings.agent.login.help");
        help.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        help.setForeground(ColorScheme.TEXT_DARK);

        JButton ok = primaryButton(I18n.t("login.wizard.add"));
        JButton cancel = plainButton(I18n.t("dialog.pick.cancel"));
        ok.addActionListener(e -> {
            List<LoginProfile> parsed = LoginProfile.listFromJson(area.getText());
            // Reject only when the text is non-blank yet yields nothing parseable.
            if (parsed.isEmpty() && !area.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(dlg, I18n.t("login.mgr.advanced.invalid"),
                        I18n.t("login.mgr.advanced.title"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            profiles.clear();
            profiles.addAll(parsed);
            refreshTable();
            dlg.dispose();
        });
        cancel.addActionListener(e -> dlg.dispose());

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        btns.add(cancel); btns.add(ok);

        JPanel content = new JPanel(new BorderLayout(8, 8));
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        content.add(new JScrollPane(area), BorderLayout.CENTER);
        JPanel south = new JPanel(new BorderLayout(0, 8));
        south.add(help, BorderLayout.NORTH);
        south.add(btns, BorderLayout.SOUTH);
        content.add(south, BorderLayout.SOUTH);
        dlg.setContentPane(content);
        dlg.setVisible(true);
    }

    // ---- per-profile editor (capture-from-history wizard) ------------------

    /**
     * Friendly editor for ONE login profile. {@code existing == null} → a blank "new" form with the
     * capture button prominent; otherwise the fields are pre-filled for editing. Capturing from proxy
     * history auto-fills URL / method / credentials / body / token path; Test logs in for real.
     */
    private void openProfileEditor(final LoginProfile existing) {
        final boolean isNew = existing == null;
        final JDialog dlg = new JDialog(this,
                I18n.t(isNew ? "login.mgr.editor.new" : "login.mgr.editor.edit"), ModalityType.APPLICATION_MODAL);

        final JTextField roleField = new JTextField();
        final JTextField urlField = new JTextField();
        final JComboBox<String> methodCombo = new JComboBox<>(new String[]{"POST", "PUT", "GET", "PATCH"});
        methodCombo.setEditable(true);
        final JTextField ctypeField = new JTextField("application/json");
        final JTextField userField = new JTextField();
        userField.setToolTipText("İstek gövdesinden çıkarılan kullanıcı / müşteri no (ör. customerId). "
                + "Gövdede {user} yer tutucusu ile temsil edilir; buradan düzenleyebilirsiniz.");
        final JTextField passField = new JTextField();
        passField.setToolTipText("İstek gövdesinden çıkarılan parola. Gövdede {pass} yer tutucusu ile "
                + "temsil edilir; buradan düzenleyebilirsiniz.");
        final JTextArea bodyArea = new JTextArea(12, 40);
        bodyArea.setLineWrap(true);
        bodyArea.setWrapStyleWord(false);
        bodyArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        final JTextField tokenPathField = new JTextField();
        final JTextField tokenRegexField = new JTextField();
        final JTextField authHeaderField = new JTextField("Authorization");
        final JTextField authValueField = new JTextField("Bearer {token}");
        // Body-carried session (Gateway): token is injected into this JSON body field of every replayed
        // request instead of an Authorization header. Auto-filled on capture; blank = header mode.
        final JTextField tokenBodyFieldInput = new JTextField();
        tokenBodyFieldInput.setToolTipText("Oturum gövdede taşınıyorsa token bu JSON alanına yazılır "
                + "(örn. Gateway: sessionToken). Boş = klasik Authorization başlığı.");
        // A wrapping, label-styled text area: long status lines (e.g. "token bulunamadı …") stay
        // fully readable instead of being truncated with an ellipsis like a JLabel would.
        final JTextArea editorStatus = new JTextArea(" ");
        editorStatus.setEditable(false);
        editorStatus.setFocusable(false);
        editorStatus.setLineWrap(true);
        editorStatus.setWrapStyleWord(true);
        editorStatus.setOpaque(false);
        editorStatus.setBorder(null);
        editorStatus.setFont(new Font("Segoe UI", Font.PLAIN, 12));

        // ── multi-step login chain (optional) working state ──
        final java.util.List<LoginStep> editorSteps = new java.util.ArrayList<>();
        final DefaultTableModel stepsModel = new DefaultTableModel(
                new Object[]{"#", "Ad", "Method", "URL", "Yakala"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        final JTable stepsTable = new JTable(stepsModel);
        final JTextField sessionTokenVarField = new JTextField();
        sessionTokenVarField.setToolTipText("Zincir bittikten sonra OTURUM olarak kullanılacak değişkenin adı "
                + "(bir adımda yakaladığınız değer, ör. sessionKey). Bu değer yukarıdaki 'Token gövde alanı' / "
                + "Authorization ayarıyla her isteğe uygulanır.");
        final Runnable refreshStepsTable = () -> {
            stepsModel.setRowCount(0);
            for (int i = 0; i < editorSteps.size(); i++) {
                LoginStep s = editorSteps.get(i);
                stepsModel.addRow(new Object[]{i + 1, s.name, s.method,
                        midEllipsis(s.url, 48), String.join(",", s.captures.keySet())});
            }
        };

        if (!isNew) {
            roleField.setText(existing.roleName);
            urlField.setText(existing.loginUrl);
            methodCombo.setSelectedItem(existing.method == null ? "POST" : existing.method.toUpperCase());
            ctypeField.setText(existing.contentType);
            userField.setText(existing.username);
            passField.setText(existing.password);
            bodyArea.setText(existing.bodyTemplate);
            tokenPathField.setText(existing.tokenJsonPath);
            tokenRegexField.setText(existing.tokenRegex);
            authHeaderField.setText(existing.authHeaderName == null ? "Authorization" : existing.authHeaderName);
            authValueField.setText(existing.authValueTemplate == null ? "Bearer {token}" : existing.authValueTemplate);
            tokenBodyFieldInput.setText(existing.tokenBodyField == null ? "" : existing.tokenBodyField);
            for (LoginStep s : existing.steps) editorSteps.add(s.copy());
            sessionTokenVarField.setText(existing.sessionTokenVar == null ? "" : existing.sessionTokenVar);
        }

        final java.util.function.Supplier<LoginProfile> collect = () -> {
            LoginProfile p = new LoginProfile();
            p.roleName = roleField.getText().trim();
            p.loginUrl = urlField.getText().trim();
            p.method = String.valueOf(methodCombo.getSelectedItem()).trim();
            p.contentType = ctypeField.getText().trim();
            p.username = userField.getText();
            p.password = passField.getText();
            p.bodyTemplate = bodyArea.getText();
            p.tokenJsonPath = tokenPathField.getText().trim();
            p.tokenRegex = tokenRegexField.getText().trim();
            String ah = authHeaderField.getText().trim();
            p.authHeaderName = ah.isEmpty() ? "Authorization" : ah;
            String tbf = tokenBodyFieldInput.getText().trim();
            p.tokenBodyField = tbf;
            // Body-carried session ⇒ no Authorization header (mirror what the real client does).
            String av = authValueField.getText().trim();
            if (tbf.isEmpty()) {
                p.authHeaderName = ah.isEmpty() ? "Authorization" : ah;
                p.authValueTemplate = av.isEmpty() ? "Bearer {token}" : av;
            } else {
                p.authHeaderName = ah;          // keep whatever the user set (usually blank)
                p.authValueTemplate = av;
            }
            for (LoginStep s : editorSteps) p.steps.add(s.copy());
            p.sessionTokenVar = sessionTokenVarField.getText().trim();
            return p;
        };

        // ── field-mapping combos: user picks WHICH body field carries {user}/{pass} ──
        // (gateway bodies have several id/secret-looking fields — UserName, CustomerId, ExtUPassword, Password —
        //  and auto-detection often picks the wrong one, so let the user choose explicitly.)
        final JComboBox<String> userFieldCombo = new JComboBox<>();
        final JComboBox<String> passFieldCombo = new JComboBox<>();
        userFieldCombo.setToolTipText("İstek gövdesindeki hangi alanın KULLANICI/müşteri no olduğunu seçin "
                + "(ör. CustomerId). Seçince o alan gövdede {user} ile işaretlenir.");
        passFieldCombo.setToolTipText("İstek gövdesindeki hangi alanın PAROLA olduğunu seçin (ör. Password). "
                + "Seçince o alan gövdede {pass} ile işaretlenir.");
        final String NONE = "— seç —";
        final boolean[] muting = {false};  // suppress the combo listeners during programmatic repopulate
        // The IMMUTABLE original captured body (all literal values). Field-mapping ALWAYS re-derives the
        // template from THIS, so switching a mapping can never corrupt a previously-mapped field (the bug
        // where picking Password overwrote the app-channel ExtUPassword secret with the user's password).
        final String[] rawBody = {""};

        // Rebuild the template from rawBody for the CURRENT combo choice — both {user} and {pass} at once,
        // every other field kept at its original raw value.
        final Runnable applyMapping = () -> {
            Object us = userFieldCombo.getSelectedItem(), ps = passFieldCombo.getSelectedItem();
            String uk = (us == null || NONE.equals(us)) ? null : us.toString();
            String pk = (ps == null || NONE.equals(ps)) ? null : ps.toString();
            String[] creds = new String[2];
            bodyArea.setText(LoginProfileBuilder.retemplatizeByKeys(rawBody[0], uk, pk, creds));
            userField.setText(creds[0] == null ? "" : creds[0]);
            passField.setText(creds[1] == null ? "" : creds[1]);
        };

        // Recompute rawBody from the current fields, repopulate the combos, preselect whichever fields
        // currently hold {user}/{pass}. Call after capture / edit-load (bodyArea + user/pass already set).
        final Runnable refreshMapping = () -> {
            muting[0] = true;
            try {
                rawBody[0] = LoginProfileBuilder.detemplatize(bodyArea.getText(), userField.getText(), passField.getText());
                java.util.List<String> names = LoginProfileBuilder.leafFieldNames(rawBody[0]);
                userFieldCombo.removeAllItems();
                passFieldCombo.removeAllItems();
                userFieldCombo.addItem(NONE);
                passFieldCombo.addItem(NONE);
                for (String n : names) { userFieldCombo.addItem(n); passFieldCombo.addItem(n); }
                String uk = LoginProfileBuilder.keyOfPlaceholder(bodyArea.getText(), "{user}");
                String pk = LoginProfileBuilder.keyOfPlaceholder(bodyArea.getText(), "{pass}");
                userFieldCombo.setSelectedItem(uk != null ? uk : NONE);
                passFieldCombo.setSelectedItem(pk != null ? pk : NONE);
            } finally {
                muting[0] = false;
            }
        };
        userFieldCombo.addActionListener(e -> { if (!muting[0]) applyMapping.run(); });
        passFieldCombo.addActionListener(e -> { if (!muting[0]) applyMapping.run(); });

        final JPanel form = new JPanel(new GridBagLayout());
        form.setBackground(ColorScheme.BG_CARD);
        final int[] rowHolder = {0};
        final java.util.function.BiConsumer<String, JComponent> addRow = (label, comp) -> {
            GridBagConstraints gl = new GridBagConstraints();
            gl.insets = new Insets(4, 6, 4, 6);
            gl.gridx = 0; gl.gridy = rowHolder[0];
            gl.anchor = GridBagConstraints.NORTHWEST;
            JLabel jl = new JLabel(label);
            jl.setForeground(ColorScheme.TEXT_DARK);
            jl.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            form.add(jl, gl);
            GridBagConstraints gc = new GridBagConstraints();
            gc.insets = new Insets(4, 6, 4, 6);
            gc.gridx = 1; gc.gridy = rowHolder[0];
            gc.weightx = 1.0; gc.fill = GridBagConstraints.HORIZONTAL;
            form.add(comp, gc);
            rowHolder[0]++;
        };
        final java.util.function.Consumer<String> addSection = (title) -> {
            GridBagConstraints gs = new GridBagConstraints();
            gs.insets = new Insets(14, 6, 4, 6);
            gs.gridx = 0; gs.gridy = rowHolder[0]++; gs.gridwidth = 2;
            gs.anchor = GridBagConstraints.WEST; gs.fill = GridBagConstraints.HORIZONTAL;
            JLabel jl = new JLabel(title);
            jl.setForeground(ColorScheme.PRIMARY_BLUE);
            jl.setFont(new Font("Segoe UI", Font.BOLD, 12));
            form.add(jl, gs);
        };

        addRow.accept(I18n.t("login.wizard.field.role"), roleField);
        addRow.accept(I18n.t("login.wizard.field.url"), urlField);
        addRow.accept(I18n.t("login.wizard.field.method"), methodCombo);

        // ── credential mapping ──
        addSection.accept("Kimlik eşleme (login gövdesinden)");
        JTextArea mapHelp = new JTextArea(
                "Login gövdesinde KULLANICI (ör. müşteri no / CustomerId) ve PAROLA hangi alansa aşağıdan seçin. "
              + "Seçtiğiniz alan gövdede {user} / {pass} ile işaretlenir; gerçek değer yandaki kutuya taşınır ve "
              + "her girişte gövdeye yazılır. Dilerseniz alt taraftaki gövdede {user}/{pass} yazarak elle de "
              + "işaretleyebilirsiniz.");
        mapHelp.setEditable(false); mapHelp.setFocusable(false); mapHelp.setOpaque(false);
        mapHelp.setLineWrap(true); mapHelp.setWrapStyleWord(true);
        mapHelp.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        mapHelp.setForeground(ColorScheme.TEXT_SECONDARY);
        GridBagConstraints gh = new GridBagConstraints();
        gh.insets = new Insets(0, 6, 6, 6);
        gh.gridx = 0; gh.gridy = rowHolder[0]++; gh.gridwidth = 2;
        gh.weightx = 1.0; gh.fill = GridBagConstraints.HORIZONTAL;
        form.add(mapHelp, gh);
        addRow.accept("Kullanıcı alanı ({user})", userFieldCombo);
        addRow.accept(I18n.t("login.wizard.field.user"), userField);
        addRow.accept("Parola alanı ({pass})", passFieldCombo);
        addRow.accept(I18n.t("login.wizard.field.pass"), passField);

        // ── request body: full-width, weighted so it GRABS vertical space and NEVER collapses to a sliver ──
        GridBagConstraints gbl = new GridBagConstraints();
        gbl.insets = new Insets(12, 6, 2, 6);
        gbl.gridx = 0; gbl.gridy = rowHolder[0]++; gbl.gridwidth = 2;
        gbl.anchor = GridBagConstraints.WEST; gbl.fill = GridBagConstraints.HORIZONTAL;
        JLabel bodyLbl = new JLabel(I18n.t("login.wizard.field.body") + "  (JSON — {user}/{pass} yer tutucuları)");
        bodyLbl.setForeground(ColorScheme.TEXT_DARK);
        bodyLbl.setFont(new Font("Segoe UI", Font.BOLD, 12));
        form.add(bodyLbl, gbl);

        JScrollPane bodyScrollPane = new JScrollPane(bodyArea,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        bodyScrollPane.setPreferredSize(new Dimension(560, 260));
        bodyScrollPane.setMinimumSize(new Dimension(200, 220));   // GridBag must NEVER shrink the body below this
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(0, 6, 8, 6);
        gbc.gridx = 0; gbc.gridy = rowHolder[0]++; gbc.gridwidth = 2;
        gbc.weightx = 1.0; gbc.weighty = 1.0; gbc.fill = GridBagConstraints.BOTH;
        form.add(bodyScrollPane, gbc);

        addRow.accept(I18n.t("login.wizard.field.tokenpath"), tokenPathField);

        // ── advanced ──
        addSection.accept(I18n.t("login.wizard.advanced"));
        addRow.accept(I18n.t("login.wizard.field.ctype"), ctypeField);
        addRow.accept(I18n.t("login.wizard.field.tokenregex"), tokenRegexField);
        addRow.accept(I18n.t("login.wizard.field.authheader"), authHeaderField);
        addRow.accept(I18n.t("login.wizard.field.authvalue"), authValueField);
        addRow.accept("Token gövde alanı", tokenBodyFieldInput);

        // ── multi-step login chain (optional) ──
        addSection.accept("Çok adımlı login (zincir — opsiyonel)");
        JTextArea stepsHelp = new JTextArea(
                "Login birden çok istekten oluşuyorsa (ör. Gateway multi-step: Login → VerifyOtp "
              + "→ Register) adımları buraya SIRAYLA ekleyin. Adım eklerseniz giriş bu zinciri çalıştırır "
              + "(yukarıdaki tekli gövde yok sayılır). Her adım, yanıtından JSON-yolu ile değişken YAKALAYABİLİR; "
              + "sonraki adımların gövdesinde {değişken} olarak kullanılır. OTURUM token'ı, aşağıya yazdığınız "
              + "değişkenden alınır ve yukarıdaki 'Token gövde alanı' (ör. sessionToken) / Authorization ile uygulanır.");
        stepsHelp.setEditable(false); stepsHelp.setFocusable(false); stepsHelp.setOpaque(false);
        stepsHelp.setLineWrap(true); stepsHelp.setWrapStyleWord(true);
        stepsHelp.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        stepsHelp.setForeground(ColorScheme.TEXT_SECONDARY);
        GridBagConstraints gsh = new GridBagConstraints();
        gsh.insets = new Insets(0, 6, 6, 6);
        gsh.gridx = 0; gsh.gridy = rowHolder[0]++; gsh.gridwidth = 2;
        gsh.weightx = 1.0; gsh.fill = GridBagConstraints.HORIZONTAL;
        form.add(stepsHelp, gsh);

        stepsTable.setRowHeight(22);
        stepsTable.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        stepsTable.getTableHeader().setReorderingAllowed(false);
        stepsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        if (stepsTable.getColumnModel().getColumnCount() >= 5) {
            stepsTable.getColumnModel().getColumn(0).setMaxWidth(30);
            stepsTable.getColumnModel().getColumn(2).setMaxWidth(70);
        }
        JScrollPane stepsScroll = new JScrollPane(stepsTable);
        stepsScroll.setPreferredSize(new Dimension(560, 116));
        stepsScroll.setMinimumSize(new Dimension(200, 96));
        GridBagConstraints gst = new GridBagConstraints();
        gst.insets = new Insets(2, 6, 4, 6);
        gst.gridx = 0; gst.gridy = rowHolder[0]++; gst.gridwidth = 2;
        gst.weightx = 1.0; gst.fill = GridBagConstraints.HORIZONTAL;
        form.add(stepsScroll, gst);

        JButton stepAdd = plainButton("＋ History'den adım ekle");
        JButton stepEdit = plainButton("Düzenle");
        JButton stepUp = plainButton("↑");
        JButton stepDown = plainButton("↓");
        JButton stepDel = plainButton("Sil");
        stepAdd.addActionListener(e -> openStepEditor(dlg, null, ns -> {
            editorSteps.add(ns);
            refreshStepsTable.run();
            int last = editorSteps.size() - 1;
            if (last >= 0) stepsTable.setRowSelectionInterval(last, last);
        }));
        final Runnable editSelStep = () -> {
            int r = stepsTable.getSelectedRow();
            if (r < 0 || r >= editorSteps.size()) { editorStatus.setText("Önce bir adım seçin."); return; }
            openStepEditor(dlg, editorSteps.get(r), ns -> {
                editorSteps.set(r, ns);
                refreshStepsTable.run();
                stepsTable.setRowSelectionInterval(r, r);
            });
        };
        stepEdit.addActionListener(e -> editSelStep.run());
        stepsTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) editSelStep.run();
            }
        });
        stepUp.addActionListener(e -> {
            int r = stepsTable.getSelectedRow();
            if (r > 0) {
                editorSteps.add(r - 1, editorSteps.remove(r));
                refreshStepsTable.run();
                stepsTable.setRowSelectionInterval(r - 1, r - 1);
            }
        });
        stepDown.addActionListener(e -> {
            int r = stepsTable.getSelectedRow();
            if (r >= 0 && r < editorSteps.size() - 1) {
                editorSteps.add(r + 1, editorSteps.remove(r));
                refreshStepsTable.run();
                stepsTable.setRowSelectionInterval(r + 1, r + 1);
            }
        });
        stepDel.addActionListener(e -> {
            int r = stepsTable.getSelectedRow();
            if (r >= 0 && r < editorSteps.size()) {
                editorSteps.remove(r);
                refreshStepsTable.run();
            }
        });
        JPanel stepBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        stepBtns.setBackground(ColorScheme.BG_CARD);
        stepBtns.add(stepAdd); stepBtns.add(stepEdit); stepBtns.add(stepUp); stepBtns.add(stepDown); stepBtns.add(stepDel);
        GridBagConstraints gsb = new GridBagConstraints();
        gsb.insets = new Insets(0, 2, 4, 6);
        gsb.gridx = 0; gsb.gridy = rowHolder[0]++; gsb.gridwidth = 2;
        gsb.anchor = GridBagConstraints.WEST; gsb.fill = GridBagConstraints.HORIZONTAL;
        form.add(stepBtns, gsb);

        addRow.accept("Oturum token değişkeni", sessionTokenVarField);
        refreshStepsTable.run();

        refreshMapping.run();  // populate the mapping combos from whatever body we have (edit prefilled it)

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.setBackground(ColorScheme.BG_CARD);
        JTextArea intro = I18nUI.multiline("login.wizard.intro");
        intro.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        intro.setForeground(ColorScheme.TEXT_DARK);
        intro.setAlignmentX(Component.LEFT_ALIGNMENT);
        top.add(intro);
        top.add(Box.createVerticalStrut(8));
        JButton captureBtn = primaryButton(I18n.t("login.wizard.capture"));
        captureBtn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        captureBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        captureBtn.addActionListener(e -> pickLoginRequestThen(dlg, rr -> {
            LoginProfile d = LoginProfileBuilder.draftFromRequest(rr, helpers);
            roleField.setText(d.roleName);
            urlField.setText(d.loginUrl);
            methodCombo.setSelectedItem(d.method == null ? "POST" : d.method.toUpperCase());
            ctypeField.setText(d.contentType);
            userField.setText(d.username);
            passField.setText(d.password);
            bodyArea.setText(d.bodyTemplate);
            tokenPathField.setText(d.tokenJsonPath);
            tokenBodyFieldInput.setText(d.tokenBodyField == null ? "" : d.tokenBodyField);
            refreshMapping.run();   // list the captured body's fields in the {user}/{pass} pickers
            boolean bodyMode = d.tokenBodyField != null && !d.tokenBodyField.isEmpty();
            if (bodyMode) {
                // Detected a body-carried session — mirror it: drop the Authorization header.
                authHeaderField.setText(d.authHeaderName == null ? "" : d.authHeaderName);
                authValueField.setText(d.authValueTemplate == null ? "" : d.authValueTemplate);
            }
            boolean tokenFound = d.tokenJsonPath != null && !d.tokenJsonPath.isEmpty();
            if (bodyMode) {
                editorStatus.setText("Yakalandı — oturum gövdede taşınıyor; token '" + d.tokenBodyField
                        + "' alanına enjekte edilecek.");
                editorStatus.setForeground(ColorScheme.SUCCESS_GREEN);
            } else {
                editorStatus.setText(I18n.t(tokenFound ? "login.wizard.captured" : "login.wizard.captured.notoken"));
                editorStatus.setForeground(tokenFound ? ColorScheme.SUCCESS_GREEN : ColorScheme.SEVERITY_MEDIUM);
            }
            // Warn if this is a single-use OTP/STS login — replaying it won't mint a fresh session (SessionKey
            // comes back empty). The user should capture the PLAIN login instead.
            String capBody = d.bodyTemplate == null ? "" : d.bodyTemplate.replace(" ", "");
            if (capBody.contains("StsLoginOtp") || capBody.contains("\"IsStsLogin\":true")) {
                editorStatus.setText("⚠ Bu tek-kullanımlık OTP/STS login gibi görünüyor (StsLoginOtp / "
                        + "IsStsLogin:true). Tekrar oynatınca SessionKey BOŞ dönebilir → düz login isteğini "
                        + "yakalayın: IsStsLogin:false, sadece CustomerId + Password.");
                editorStatus.setForeground(ColorScheme.SEVERITY_MEDIUM);
            }
        }));
        top.add(captureBtn);
        top.add(Box.createVerticalStrut(10));

        JButton testBtn = plainButton(I18n.t("login.wizard.test"));
        JButton addBtn = primaryButton(I18n.t(isNew ? "login.wizard.add" : "login.mgr.save"));
        JButton cancelBtn = plainButton(I18n.t("dialog.pick.cancel"));

        testBtn.addActionListener(e -> {
            final LoginProfile p = collect.get();
            if (!p.isValid()) {
                editorStatus.setText(I18n.t("login.wizard.needfields"));
                editorStatus.setForeground(ColorScheme.ERROR_RED);
                return;
            }
            testBtn.setEnabled(false);
            editorStatus.setText(I18n.t("login.wizard.testing"));
            editorStatus.setForeground(ColorScheme.TEXT_DARK);
            new Thread(() -> {
                LoginManager lm = new LoginManager(callbacks, helpers, stdout, stderr);
                try {
                    // Single-request token auto-detect only — a multi-step chain has no single loginUrl to probe.
                    if (!p.isMultiStep() && p.tokenJsonPath.trim().isEmpty() && p.tokenRegex.trim().isEmpty()) {
                        String body = lm.fetchResponseBody(p);
                        String path = LoginProfileBuilder.detectTokenPath(body);
                        if (path != null) {
                            p.tokenJsonPath = path;
                            SwingUtilities.invokeLater(() -> tokenPathField.setText(path));
                        }
                    }
                    final LoginManager.LoginResult r = lm.test(p);
                    SwingUtilities.invokeLater(() -> {
                        editorStatus.setText(r.ok ? (Glyphs.ok() + " " + I18n.t("login.wizard.ok", r.detail))
                                : (Glyphs.fail() + " " + r.detail));
                        editorStatus.setForeground(r.ok ? ColorScheme.SUCCESS_GREEN : ColorScheme.ERROR_RED);
                        testBtn.setEnabled(true);
                    });
                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() -> {
                        editorStatus.setText(Glyphs.fail() + " " + ex.getMessage());
                        editorStatus.setForeground(ColorScheme.ERROR_RED);
                        testBtn.setEnabled(true);
                    });
                }
            }, "login-editor-test").start();
        });

        addBtn.addActionListener(e -> {
            LoginProfile p = collect.get();
            if (!p.isValid()) {
                editorStatus.setText(I18n.t("login.wizard.needfields"));
                editorStatus.setForeground(ColorScheme.ERROR_RED);
                return;
            }
            if (isNew) {
                // A NEW profile must never overwrite an existing one: if the (often auto-guessed, e.g.
                // "user1" when the customer-no couldn't be read) role collides, uniquify it — do NOT replace
                // the other user. This was the "2 profiles added, only 1 shows" bug.
                p.roleName = uniqueRole(p.roleName, null);
                profiles.add(p);
            } else {
                // Editing: replace THIS entry by identity; uniquify only if a rename collides with a different one.
                p.roleName = uniqueRole(p.roleName, existing);
                int idx = profiles.indexOf(existing);
                if (idx >= 0) profiles.set(idx, p); else profiles.add(p);
            }
            refreshTable();
            dlg.dispose();
        });
        cancelBtn.addActionListener(e -> dlg.dispose());

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        btns.setBackground(ColorScheme.BG_CARD);
        btns.add(testBtn);
        btns.add(cancelBtn);
        btns.add(addBtn);

        JPanel south = new JPanel(new BorderLayout(0, 8));
        south.setBackground(ColorScheme.BG_CARD);
        south.add(editorStatus, BorderLayout.NORTH);
        south.add(btns, BorderLayout.SOUTH);

        // Intro + capture button + form all scroll together as one unit; only the action bar is pinned
        // at the bottom — so on a short screen Test/İptal/Ekle are ALWAYS reachable (never clipped).
        // WidthTrackingPanel makes the form fill the viewport width so every field is full-width.
        JPanel scrollBody = new WidthTrackingPanel(new BorderLayout(0, 10));
        scrollBody.setBackground(ColorScheme.BG_CARD);
        scrollBody.add(top, BorderLayout.NORTH);
        scrollBody.add(form, BorderLayout.CENTER);
        JScrollPane bodyScroll = new JScrollPane(scrollBody,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        bodyScroll.setBorder(BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT));
        bodyScroll.getVerticalScrollBar().setUnitIncrement(16);
        bodyScroll.getViewport().setBackground(ColorScheme.BG_CARD);

        JPanel content = new JPanel(new BorderLayout(10, 10));
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        content.setBackground(ColorScheme.BG_CARD);
        content.add(bodyScroll, BorderLayout.CENTER);
        content.add(south, BorderLayout.SOUTH);

        dlg.setContentPane(content);
        sizeToScreen(dlg, 720, 760);
        dlg.setMinimumSize(new Dimension(620, 480));
        dlg.setLocationRelativeTo(this);
        dlg.setVisible(true);
    }

    /**
     * Editor for ONE chain step: capture the request from proxy history (fills URL/method/body), then declare
     * which response values to CAPTURE as named variables (JSON dot-path) for later steps / the session token.
     */
    private void openStepEditor(Window parent, final LoginStep existing,
                                final java.util.function.Consumer<LoginStep> onSave) {
        final boolean isNew = existing == null;
        final JDialog dlg = new JDialog(parent instanceof Frame ? (Frame) parent : null,
                isNew ? "Zincir adımı — Yeni" : "Zincir adımı — Düzenle", Dialog.ModalityType.APPLICATION_MODAL);

        final JTextField nameField = new JTextField();
        final JTextField urlField = new JTextField();
        final JComboBox<String> methodCombo = new JComboBox<>(new String[]{"POST", "PUT", "GET", "PATCH"});
        methodCombo.setEditable(true);
        final JTextField ctypeField = new JTextField("application/json");
        final JTextArea bodyArea = new JTextArea(9, 40);
        bodyArea.setLineWrap(true);
        bodyArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        final DefaultTableModel capsModel = new DefaultTableModel(new Object[]{"Değişken adı", "Yanıt JSON yolu"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return true; }
        };
        final JTable capsTable = new JTable(capsModel);
        capsTable.setRowHeight(22);
        capsTable.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);

        if (!isNew) {
            nameField.setText(existing.name);
            urlField.setText(existing.url);
            methodCombo.setSelectedItem(existing.method == null ? "POST" : existing.method.toUpperCase());
            ctypeField.setText(existing.contentType == null ? "application/json" : existing.contentType);
            bodyArea.setText(existing.bodyTemplate);
            for (java.util.Map.Entry<String, String> en : existing.captures.entrySet()) {
                capsModel.addRow(new Object[]{en.getKey(), en.getValue()});
            }
        }

        JButton captureBtn = primaryButton("＋ History'den yakala");
        captureBtn.addActionListener(e -> pickLoginRequestThen(dlg, rr -> {
            LoginProfile d = LoginProfileBuilder.draftFromRequest(rr, helpers);
            if (nameField.getText().trim().isEmpty()) nameField.setText(lastPathSegment(d.loginUrl));
            urlField.setText(d.loginUrl);
            methodCombo.setSelectedItem(d.method == null ? "POST" : d.method.toUpperCase());
            ctypeField.setText(d.contentType);
            // Keep literal captured values (do NOT re-template {user}/{pass}); a chain step's body is mostly
            // static device blobs + one {captured} placeholder the user wires up by hand.
            String body = LoginProfileBuilder.detemplatize(d.bodyTemplate, d.username, d.password);
            bodyArea.setText(body);
            // Auto-suggest a capture when a token-looking value was detected in the response.
            if (d.tokenJsonPath != null && !d.tokenJsonPath.isEmpty() && capsModel.getRowCount() == 0) {
                capsModel.addRow(new Object[]{"sessionKey", d.tokenJsonPath});
            }
        }));

        JButton capAdd = plainButton("＋ Yakalama");
        JButton capDel = plainButton("Yakalamayı sil");
        capAdd.addActionListener(e -> capsModel.addRow(new Object[]{"", ""}));
        capDel.addActionListener(e -> {
            if (capsTable.isEditing()) capsTable.getCellEditor().stopCellEditing();
            int r = capsTable.getSelectedRow();
            if (r >= 0 && r < capsModel.getRowCount()) capsModel.removeRow(r);
        });

        final JPanel form = new JPanel(new GridBagLayout());
        form.setBackground(ColorScheme.BG_CARD);
        final int[] row = {0};
        final java.util.function.BiConsumer<String, JComponent> addRow = (label, comp) -> {
            GridBagConstraints gl = new GridBagConstraints();
            gl.insets = new Insets(4, 6, 4, 6);
            gl.gridx = 0; gl.gridy = row[0]; gl.anchor = GridBagConstraints.NORTHWEST;
            JLabel jl = new JLabel(label);
            jl.setForeground(ColorScheme.TEXT_DARK);
            jl.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            form.add(jl, gl);
            GridBagConstraints gc = new GridBagConstraints();
            gc.insets = new Insets(4, 6, 4, 6);
            gc.gridx = 1; gc.gridy = row[0]; gc.weightx = 1.0; gc.fill = GridBagConstraints.HORIZONTAL;
            form.add(comp, gc);
            row[0]++;
        };
        addRow.accept("Adım adı", nameField);
        addRow.accept("URL", urlField);
        addRow.accept("Method", methodCombo);
        addRow.accept("Content-Type", ctypeField);

        GridBagConstraints gbl = new GridBagConstraints();
        gbl.insets = new Insets(10, 6, 2, 6);
        gbl.gridx = 0; gbl.gridy = row[0]++; gbl.gridwidth = 2;
        gbl.anchor = GridBagConstraints.WEST; gbl.fill = GridBagConstraints.HORIZONTAL;
        JLabel bodyLbl = new JLabel("İstek gövdesi  (JSON — {değişken} yer tutucuları kullanılabilir)");
        bodyLbl.setForeground(ColorScheme.TEXT_DARK);
        bodyLbl.setFont(new Font("Segoe UI", Font.BOLD, 12));
        form.add(bodyLbl, gbl);
        JScrollPane bodySp = new JScrollPane(bodyArea,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        bodySp.setPreferredSize(new Dimension(560, 180));
        GridBagConstraints gb = new GridBagConstraints();
        gb.insets = new Insets(0, 6, 8, 6);
        gb.gridx = 0; gb.gridy = row[0]++; gb.gridwidth = 2;
        gb.weightx = 1.0; gb.weighty = 1.0; gb.fill = GridBagConstraints.BOTH;
        form.add(bodySp, gb);

        GridBagConstraints gcl = new GridBagConstraints();
        gcl.insets = new Insets(8, 6, 2, 6);
        gcl.gridx = 0; gcl.gridy = row[0]++; gcl.gridwidth = 2;
        gcl.anchor = GridBagConstraints.WEST; gcl.fill = GridBagConstraints.HORIZONTAL;
        JLabel capLbl = new JLabel("Yakalanacak değişkenler  (yanıttan; ör. sessionKey ← LoginResponse.token)");
        capLbl.setForeground(ColorScheme.TEXT_DARK);
        capLbl.setFont(new Font("Segoe UI", Font.BOLD, 12));
        form.add(capLbl, gcl);
        JScrollPane capSp = new JScrollPane(capsTable);
        capSp.setPreferredSize(new Dimension(560, 96));
        GridBagConstraints gct = new GridBagConstraints();
        gct.insets = new Insets(0, 6, 4, 6);
        gct.gridx = 0; gct.gridy = row[0]++; gct.gridwidth = 2;
        gct.weightx = 1.0; gct.fill = GridBagConstraints.HORIZONTAL;
        form.add(capSp, gct);
        JPanel capBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        capBtns.setBackground(ColorScheme.BG_CARD);
        capBtns.add(capAdd); capBtns.add(capDel);
        GridBagConstraints gcb = new GridBagConstraints();
        gcb.gridx = 0; gcb.gridy = row[0]++; gcb.gridwidth = 2;
        gcb.anchor = GridBagConstraints.WEST; gcb.fill = GridBagConstraints.HORIZONTAL;
        form.add(capBtns, gcb);

        JPanel top = new JPanel(new BorderLayout(0, 8));
        top.setBackground(ColorScheme.BG_CARD);
        top.add(captureBtn, BorderLayout.WEST);

        JButton ok = primaryButton(isNew ? "Ekle" : "Kaydet");
        JButton cancel = plainButton(I18n.t("dialog.pick.cancel"));
        ok.addActionListener(e -> {
            if (capsTable.isEditing()) capsTable.getCellEditor().stopCellEditing();
            LoginStep s = new LoginStep();
            s.name = nameField.getText().trim();
            s.url = urlField.getText().trim();
            s.method = String.valueOf(methodCombo.getSelectedItem()).trim();
            s.contentType = ctypeField.getText().trim();
            s.bodyTemplate = bodyArea.getText();
            if (!s.isValid()) {
                JOptionPane.showMessageDialog(dlg, "Adım için en azından URL gerekli.",
                        "Eksik alan", JOptionPane.WARNING_MESSAGE);
                return;
            }
            for (int i = 0; i < capsModel.getRowCount(); i++) {
                String k = String.valueOf(capsModel.getValueAt(i, 0)).trim();
                String v = String.valueOf(capsModel.getValueAt(i, 1)).trim();
                if (!k.isEmpty() && !v.isEmpty()) s.captures.put(k, v);
            }
            onSave.accept(s);
            dlg.dispose();
        });
        cancel.addActionListener(e -> dlg.dispose());

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        btns.setBackground(ColorScheme.BG_CARD);
        btns.add(cancel); btns.add(ok);

        JPanel scrollBody = new WidthTrackingPanel(new BorderLayout(0, 10));
        scrollBody.setBackground(ColorScheme.BG_CARD);
        scrollBody.add(top, BorderLayout.NORTH);
        scrollBody.add(form, BorderLayout.CENTER);
        JScrollPane bodyScroll = new JScrollPane(scrollBody,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        bodyScroll.setBorder(BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT));
        bodyScroll.getViewport().setBackground(ColorScheme.BG_CARD);

        JPanel content = new JPanel(new BorderLayout(10, 10));
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        content.setBackground(ColorScheme.BG_CARD);
        content.add(bodyScroll, BorderLayout.CENTER);
        content.add(btns, BorderLayout.SOUTH);
        dlg.setContentPane(content);
        sizeToScreen(dlg, 700, 720);
        dlg.setMinimumSize(new Dimension(560, 460));
        dlg.setLocationRelativeTo(parent);
        dlg.setVisible(true);
    }

    /** Last non-empty path segment of a URL, e.g. ".../AuthenticationService.svc/Login" → "Login". */
    private static String lastPathSegment(String url) {
        if (url == null) return "";
        try {
            String path = new java.net.URL(url).getPath();
            if (path == null) return "";
            String[] segs = path.split("/");
            for (int i = segs.length - 1; i >= 0; i--) {
                if (!segs[i].trim().isEmpty()) return segs[i].trim();
            }
        } catch (Exception ignore) {
        }
        return "";
    }

    /** Proxy-history request picker for the editor; login-looking requests (🔑) are listed first. */
    private void pickLoginRequestThen(Window parent, java.util.function.Consumer<IHttpRequestResponse> action) {
        IHttpRequestResponse[] history = callbacks.getProxyHistory();
        if (history == null || history.length == 0) {
            JOptionPane.showMessageDialog(parent, I18n.t("login.wizard.nohistory"),
                    I18n.t("login.wizard.capture"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        // Collect ALL history entries — login-looking first (🔑), then most-recent-first — up to a high cap.
        final class Item {
            final int historyIdx; final String display; final String search;
            Item(int h, String d, String s) { historyIdx = h; display = d; search = s; }
        }
        final java.util.List<Item> allItems = new java.util.ArrayList<>();
        final int CAP = 1000;
        for (int pass = 0; pass < 2 && allItems.size() < CAP; pass++) {
            for (int i = history.length - 1; i >= 0 && allItems.size() < CAP; i--) {
                try {
                    IRequestInfo info = helpers.analyzeRequest(history[i]);
                    boolean login = LoginProfileBuilder.looksLikeLoginRequest(info, history[i]);
                    if ((pass == 0) != login) continue;   // pass 0 = login-looking; pass 1 = everything else
                    String url = info.getUrl() != null ? info.getUrl().toString() : "?";
                    String method = info.getMethod() == null ? "" : info.getMethod();
                    String marker = login ? (Glyphs.emojiOk() ? "🔑 " : "* ") : "     ";
                    allItems.add(new Item(i, marker + method + "  " + url,
                            (method + " " + url).toLowerCase(java.util.Locale.ROOT)));
                } catch (Exception ignore) {
                }
            }
        }
        if (allItems.isEmpty()) {
            JOptionPane.showMessageDialog(parent, I18n.t("login.wizard.nohistory"),
                    I18n.t("login.wizard.capture"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        final JDialog dialog = new JDialog(parent instanceof Frame ? (Frame) parent : null,
                I18n.t("login.wizard.pick.title"), true);
        sizeToScreen(dialog, 720, 540);
        dialog.setMinimumSize(new Dimension(520, 340));
        dialog.setLocationRelativeTo(parent);

        final DefaultListModel<String> model = new DefaultListModel<>();
        final java.util.List<Integer> visibleOrder = new java.util.ArrayList<>();  // history idx, parallel to model

        final JList<String> list = new JList<String>(model) {
            // Fill the viewport width so the renderer can fit text to the ACTUAL dialog width (and re-fit on resize).
            @Override public boolean getScrollableTracksViewportWidth() { return true; }
            @Override public String getToolTipText(java.awt.event.MouseEvent e) {
                int i = locationToIndex(e.getPoint());
                return (i >= 0 && i < model.getSize()) ? model.getElementAt(i) : null;
            }
        };
        list.setFont(new Font("Monospaced", Font.PLAIN, 12));
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        // Responsive middle-ellipsis: widen the dialog → more of the URL shows; wide enough → the WHOLE URL.
        list.setCellRenderer(new DefaultListCellRenderer() {
            @Override public Component getListCellRendererComponent(JList<?> l, Object value, int index,
                                                                    boolean sel, boolean foc) {
                super.getListCellRendererComponent(l, value, index, sel, foc);
                String full = value == null ? "" : value.toString();
                int cw = Math.max(1, getFontMetrics(getFont()).charWidth('0'));
                int maxChars = Math.max(12, (l.getWidth() - 28) / cw); // 28px slack for insets + scrollbar
                setText(midEllipsis(full, maxChars));
                setToolTipText(full);
                return this;
            }
        });
        ToolTipManager.sharedInstance().registerComponent(list); // full URL on hover, regardless of width

        // Live search: filter the list by method/URL substring (case-insensitive). Blank = show all.
        final JTextField searchField = new JTextField();
        searchField.setToolTipText("URL/method içinde ara (ör. 'login', 'Login', 'auth'). Boş = tümü.");
        final Runnable refilter = () -> {
            String q = searchField.getText().trim().toLowerCase(java.util.Locale.ROOT);
            model.clear(); visibleOrder.clear();
            for (Item it : allItems) {
                if (q.isEmpty() || it.search.contains(q)) {
                    model.addElement(it.display);
                    visibleOrder.add(it.historyIdx);
                }
            }
            if (!model.isEmpty()) list.setSelectedIndex(0);
        };
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { refilter.run(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { refilter.run(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { refilter.run(); }
        });
        refilter.run(); // initial fill (all items)

        JPanel content = new JPanel(new BorderLayout(10, 10));
        content.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));
        JPanel north = new JPanel(new BorderLayout(0, 8));
        north.add(new JLabel(I18n.t("login.wizard.pick.hint")), BorderLayout.NORTH);
        JPanel searchRow = new JPanel(new BorderLayout(6, 0));
        searchRow.add(new JLabel(Glyphs.emojiOk() ? "🔎 Ara:" : "Ara:"), BorderLayout.WEST);
        searchRow.add(searchField, BorderLayout.CENTER);
        north.add(searchRow, BorderLayout.SOUTH);
        content.add(north, BorderLayout.NORTH);

        JScrollPane listScroll = new JScrollPane(list,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        content.add(listScroll, BorderLayout.CENTER);

        JButton run = new JButton(I18n.t("dialog.pick.run"));
        run.addActionListener(e -> {
            int sel = list.getSelectedIndex();
            if (sel < 0 || sel >= visibleOrder.size()) {
                JOptionPane.showMessageDialog(dialog, I18n.t("dialog.pick.selectOne"));
                return;
            }
            int idx = visibleOrder.get(sel);
            dialog.dispose();
            if (idx >= 0 && idx < history.length) action.accept(history[idx]);
        });
        list.addMouseListener(new java.awt.event.MouseAdapter() {   // double-click a row = pick it
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) run.doClick();
            }
        });
        JButton cancel = new JButton(I18n.t("dialog.pick.cancel"));
        cancel.addActionListener(e -> dialog.dispose());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.add(cancel);
        buttons.add(run);
        content.add(buttons, BorderLayout.SOUTH);

        dialog.setContentPane(content);
        dialog.setVisible(true);
    }
}

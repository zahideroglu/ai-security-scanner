package burp.authz;

import burp.ColorScheme;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.SettingsManager;
import burp.i18n.I18n;
import burp.i18n.I18nUI;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

/**
 * Findings-style panel that renders the authorization matrix as a colour-coded
 * table (green = granted, red = denied, grey = error), lists the detected
 * violations, and exports the matrix to CSV / HTML.
 *
 * @author Zahid Eroglu
 */
public class AuthMatrixPanel extends JPanel {

    // Verdict cell colours — saturated so they read on both light and dark Burp themes (white text on top).
    private static final Color GRANTED = new Color(0x2E, 0x7D, 0x32); // green 700
    private static final Color DENIED  = new Color(0xC6, 0x28, 0x28); // red 700
    private static final Color NEUTRAL = new Color(0x60, 0x60, 0x60); // grey (ERROR/unknown)
    private static final Color CELL_TEXT = Color.WHITE;

    private final JLabel summary = new JLabel(I18n.t("authz.summary.empty"));
    private final DefaultTableModel matrixModel = new DefaultTableModel();
    private final JTable matrixTable = new JTable(matrixModel);
    private final DefaultTableModel violModel = new DefaultTableModel(
            new Object[]{I18n.t("authz.col.severity"), I18n.t("authz.col.type"),
                    I18n.t("authz.col.endpoint"), I18n.t("authz.col.evidence")}, 0);
    private final JTable violTable = new JTable(violModel);

    private AuthMatrix matrix;
    private List<String> roleCols = new ArrayList<>();

    // Faz 4: identity manager embedded in this tab (list/delete saved roles).
    private burp.MultiSessionTester sessionTester;

    // Login-profile manager popup access (set by BurpExtender after construction).
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private SettingsManager settingsManager;
    private final DefaultTableModel idModel = new DefaultTableModel(
            new Object[]{I18n.t("authz.col.role"), I18n.t("authz.col.token"),
                    I18n.t("authz.col.created"), "id"}, 0);
    private final JTable idTable = new JTable(idModel);
    // Auto-harvested identities (with validity), shown alongside the manually-added sessions.
    private List<IdentityInfo> discovered = new ArrayList<>();

    /** A harvested identity to surface in the Kimlikler table: role, token count, validity note. */
    public static class IdentityInfo {
        public final String roleName;
        public final int tokens;
        public final String info;      // human-readable source + validity (e.g. "history · doğrulandı · 12 istek")
        public final boolean harvested; // true = auto from history (not a stored session)
        public final boolean verified;  // true = replay confirmed the token is live
        public IdentityInfo(String roleName, int tokens, String info, boolean harvested, boolean verified) {
            this.roleName = roleName; this.tokens = tokens; this.info = info;
            this.harvested = harvested; this.verified = verified;
        }
    }

    public AuthMatrixPanel() {
        super(new BorderLayout(0, 6));
        setBackground(ColorScheme.BG_DARK);

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        top.setBackground(ColorScheme.BG_DARK);
        summary.setForeground(ColorScheme.TEXT_PRIMARY);
        top.add(summary);
        JButton csv = I18nUI.text(new JButton(), "authz.btn.exportCsv");
        JButton html = I18nUI.text(new JButton(), "authz.btn.exportHtml");
        JButton clear = I18nUI.text(new JButton(), "authz.btn.clear");
        csv.addActionListener(e -> export(false));
        html.addActionListener(e -> export(true));
        clear.addActionListener(e -> setMatrix(null));
        top.add(csv); top.add(html); top.add(clear);
        add(top, BorderLayout.NORTH);

        matrixTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        matrixTable.setRowSelectionAllowed(true);
        matrixTable.getTableHeader().setReorderingAllowed(false);
        matrixTable.setDefaultRenderer(Object.class, new VerdictRenderer());
        styleTable(matrixTable);

        violTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        styleTable(violTable);
        violTable.getColumnModel().getColumn(0).setCellRenderer(new SeverityCellRenderer());

        JSplitPane lower = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(violTable), buildIdentitiesPanel());
        lower.setResizeWeight(0.6);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(matrixTable), lower);
        split.setResizeWeight(0.6);
        add(split, BorderLayout.CENTER);
    }

    /** Wire the identity store so the embedded manager can list/delete saved roles. */
    public void setSessionTester(burp.MultiSessionTester t) {
        this.sessionTester = t;
        refreshIdentities();
    }

    /**
     * Wire the dependencies the "Login Profilleri" popup needs (proxy history, login test, settings
     * persistence). Until this is called the button still shows but reports it is unavailable.
     */
    public void setLoginAccess(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
                               PrintWriter stdout, PrintWriter stderr, SettingsManager settingsManager) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.stdout = stdout;
        this.stderr = stderr;
        this.settingsManager = settingsManager;
    }

    /** Open the login-profile / AI-Pentester manager popup (moved here from Settings). */
    private void openLoginProfiles() {
        if (callbacks == null || settingsManager == null) {
            JOptionPane.showMessageDialog(this, I18n.t("login.mgr.unavailable"));
            return;
        }
        Window owner = SwingUtilities.getWindowAncestor(this);
        new LoginProfilesDialog(owner, callbacks, helpers, stdout, stderr, settingsManager).setVisible(true);
        refreshIdentities();
    }

    /**
     * Show the auto-harvested identities (with validity) discovered for the last run, alongside the
     * manually-added sessions. Lets the user SEE which tokens were detected and why one was skipped,
     * instead of an empty table when role discovery happened automatically.
     */
    public void setDiscoveredIdentities(List<IdentityInfo> ids) {
        this.discovered = (ids == null) ? new ArrayList<>() : new ArrayList<>(ids);
        refreshIdentities();
    }

    private JPanel buildIdentitiesPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 4));
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        bar.setBackground(ColorScheme.BG_DARK);
        JLabel idLbl = I18nUI.text(new JLabel(), "authz.identities.label");
        idLbl.setForeground(ColorScheme.TEXT_PRIMARY);
        bar.add(idLbl);
        // Primary action: open the login-profile / AI-Pentester manager popup (moved from Settings).
        JButton loginProfiles = I18nUI.text(new JButton(), "authz.btn.loginProfiles");
        loginProfiles.setFont(loginProfiles.getFont().deriveFont(Font.BOLD));
        loginProfiles.setBackground(ColorScheme.PRIMARY_BLUE);
        loginProfiles.setForeground(Color.WHITE);
        loginProfiles.setOpaque(true);
        loginProfiles.setBorderPainted(false);
        loginProfiles.setFocusPainted(false);
        I18nUI.tip(loginProfiles, "authz.btn.loginProfiles.tip");
        loginProfiles.addActionListener(e -> openLoginProfiles());
        bar.add(loginProfiles);
        JButton refresh = I18nUI.text(new JButton(), "authz.btn.refresh");
        JButton del = I18nUI.text(new JButton(), "authz.btn.deleteRole");
        refresh.addActionListener(e -> refreshIdentities());
        del.addActionListener(e -> {
            int row = idTable.getSelectedRow();
            if (row < 0 || sessionTester == null) return;
            int mr = idTable.convertRowIndexToModel(row);
            String id = String.valueOf(idModel.getValueAt(mr, 3));
            if (id == null || id.isEmpty() || "null".equals(id)) {
                JOptionPane.showMessageDialog(this, I18n.t("authz.dialog.autoRole"));
                return; // auto-harvested row, not a stored session
            }
            sessionTester.removeSession(id);
            refreshIdentities();
        });
        bar.add(refresh);
        bar.add(del);
        p.add(bar, BorderLayout.NORTH);
        idTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        idTable.removeColumn(idTable.getColumnModel().getColumn(3)); // hide raw id column (kept in model)
        styleTable(idTable);
        p.setBackground(ColorScheme.BG_DARK);
        p.add(new JScrollPane(idTable), BorderLayout.CENTER);
        return p;
    }

    private void refreshIdentities() {
        Runnable r = () -> {
            idModel.setRowCount(0);
            if (sessionTester != null) {
                java.util.List<burp.MultiSessionTester.UserSession> ss = sessionTester.getSessions();
                if (ss != null) {
                    java.text.SimpleDateFormat fmt = new java.text.SimpleDateFormat("MM-dd HH:mm");
                    for (burp.MultiSessionTester.UserSession s : ss) {
                        int tok = s.authTokens == null ? 0 : s.authTokens.size();
                        String when = s.createdAt == null ? "" : fmt.format(s.createdAt);
                        idModel.addRow(new Object[]{s.roleName, tok, when, s.id});
                    }
                }
            }
            // Auto-harvested identities (id column empty → not deletable: they are not stored sessions).
            for (IdentityInfo d : discovered) {
                idModel.addRow(new Object[]{d.roleName, d.tokens, d.info, ""});
            }
        };
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }

    /** Populate from a completed matrix (call on the EDT). */
    public void setMatrix(AuthMatrix m) {
        Runnable r = () -> {
            this.matrix = m;
            matrixModel.setRowCount(0);
            matrixModel.setColumnCount(0);
            violModel.setRowCount(0);
            roleCols = new ArrayList<>();

            if (m == null) {
                summary.setText(I18n.t("authz.summary.empty"));
                return;
            }
            roleCols.addAll(m.roles);

            List<String> cols = new ArrayList<>();
            cols.add(I18n.t("authz.col.method"));
            cols.add(I18n.t("authz.col.path"));
            cols.addAll(m.roles);
            matrixModel.setColumnIdentifiers(cols.toArray());

            for (AuthMatrix.Row row : m.rows) {
                Object[] cells = new Object[2 + m.roles.size()];
                cells[0] = row.method;
                cells[1] = row.path;
                for (int i = 0; i < m.roles.size(); i++) {
                    AuthMatrix.Cell c = row.cell(m.roles.get(i));
                    cells[2 + i] = (c == null || c.verdict == AuthMatrix.Verdict.ERROR) ? "—" : String.valueOf(c.status);
                }
                matrixModel.addRow(cells);
            }
            sizeColumns();

            for (AuthMatrix.Violation v : m.violations) {
                violModel.addRow(new Object[]{v.severity, v.type, v.endpoint, v.evidence});
            }

            int high = 0;
            for (AuthMatrix.Violation v : m.violations) if ("High".equalsIgnoreCase(v.severity)) high++;
            summary.setText(I18n.t("authz.summary.stats",
                    m.rows.size(), m.roles.size(), m.violations.size(), high));
        };
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }

    private void sizeColumns() {
        if (matrixTable.getColumnCount() == 0) return;
        matrixTable.getColumnModel().getColumn(0).setPreferredWidth(60);
        matrixTable.getColumnModel().getColumn(1).setPreferredWidth(340);
        for (int i = 2; i < matrixTable.getColumnCount(); i++) {
            matrixTable.getColumnModel().getColumn(i).setPreferredWidth(90);
        }
    }

    private void export(boolean html) {
        if (matrix == null) {
            JOptionPane.showMessageDialog(this, I18n.t("authz.dialog.runFirst"));
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File(html ? "auth-matrix.html" : "auth-matrix.csv"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try (Writer w = new FileWriter(fc.getSelectedFile())) {
            w.write(html ? matrix.renderHtml() : matrix.renderCsv());
            JOptionPane.showMessageDialog(this, I18n.t("authz.dialog.saved", fc.getSelectedFile().getName()));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, I18n.t("authz.dialog.exportError", ex.getMessage()));
        }
    }

    private void styleTable(JTable t) {
        t.setBackground(ColorScheme.BG_CARD);
        t.setForeground(ColorScheme.TEXT_PRIMARY);
        t.setGridColor(ColorScheme.BORDER_DARKER);
        t.setSelectionBackground(ColorScheme.PRIMARY_BLUE);
        t.setSelectionForeground(Color.WHITE);
        t.setRowHeight(24);
        t.setShowGrid(true);
        t.setIntercellSpacing(new Dimension(1, 1));
        javax.swing.table.JTableHeader h = t.getTableHeader();
        if (h != null) {
            h.setBackground(ColorScheme.BG_LIGHT);
            h.setForeground(ColorScheme.TEXT_PRIMARY);
            h.setReorderingAllowed(false);
        }
    }

    /** Colours the violations table's severity column (High=red, Medium=orange, Low=blue, Info=grey). */
    private class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object value, boolean sel,
                                                       boolean focus, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
            if (!sel) {
                c.setBackground(ColorScheme.BG_CARD);
                c.setForeground(ColorScheme.getSeverityColor(String.valueOf(value)));
            }
            setFont(getFont().deriveFont(Font.BOLD));
            return c;
        }
    }

    /** Colours role columns by verdict (green=granted, red=denied, grey=error), white text. */
    private class VerdictRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object value, boolean sel,
                                                       boolean focus, int viewRow, int viewCol) {
            Component c = super.getTableCellRendererComponent(t, value, sel, focus, viewRow, viewCol);
            setHorizontalAlignment(viewCol >= 2 ? CENTER : LEFT);
            if (sel) return c;
            int modelCol = t.convertColumnIndexToModel(viewCol);
            int modelRow = t.convertRowIndexToModel(viewRow);
            Color bg = ColorScheme.BG_CARD;
            Color fg = ColorScheme.TEXT_PRIMARY;
            if (matrix != null && modelCol >= 2 && modelRow < matrix.rows.size()
                    && (modelCol - 2) < roleCols.size()) {
                AuthMatrix.Cell cell = matrix.rows.get(modelRow).cell(roleCols.get(modelCol - 2));
                if (cell != null && cell.verdict == AuthMatrix.Verdict.GRANTED) { bg = GRANTED; fg = CELL_TEXT; }
                else if (cell != null && cell.verdict == AuthMatrix.Verdict.DENIED) { bg = DENIED; fg = CELL_TEXT; }
                else { bg = NEUTRAL; fg = CELL_TEXT; }
            }
            c.setBackground(bg);
            c.setForeground(fg);
            return c;
        }
    }
}

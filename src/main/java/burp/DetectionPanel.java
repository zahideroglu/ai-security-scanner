package burp;

import burp.i18n.Glyphs;
import burp.i18n.I18n;
import burp.i18n.I18nUI;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Detection tab container. Each detection run (single target or whole-site)
 * gets its OWN sub-tab ({@link DetectionRunView}), so starting a new run never
 * wipes a previous one - the user can switch between concurrent/past runs.
 *
 * <p>Tabs are closable: every run tab carries an ✕ button, a right-click menu
 * (Kapat / Diğerlerini Kapat / Tümünü Kapat), and the header offers
 * "Bitenleri Kapat" / "Tümünü Kapat". Closing a still-running tab aborts it.
 *
 * @author Zahid Eroglu
 */
public class DetectionPanel extends JPanel {

    /** Safety cap so a runaway "Hepsini Tara" (≈7 tabs each) can't grow without bound. */
    private static final int MAX_RUNS = 24;

    private static final Color HOVER_RED = new Color(0xE53935);

    private final JTabbedPane runs = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);
    private final JLabel countLabel = new JLabel();
    private final JButton closeFinishedBtn = new JButton("Bitenleri Kapat");
    private final JButton closeAllBtn = new JButton("Tümünü Kapat");
    private int counter = 0;

    // Launcher actions (wired by BurpExtender). This panel is the unified "Scanner" tab:
    // a launcher toolbar on top + the live active-scan run list below. Every launched scan
    // (full-auto, single-request, whole-domain) becomes a run in this same list.
    private Runnable onScanEverything;
    private Runnable onScanThisRequest;
    private Runnable onScanDomain;

    public DetectionPanel() {
        setLayout(new BorderLayout(0, 6));
        setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

        JPanel north = new JPanel(new BorderLayout(0, 6));
        north.setOpaque(false);
        north.add(buildLauncher(), BorderLayout.NORTH);
        north.add(buildHeader(), BorderLayout.CENTER);
        add(north, BorderLayout.NORTH);

        runs.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        runs.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e) { maybeShowTabMenu(e); }
            @Override public void mouseReleased(MouseEvent e) { maybeShowTabMenu(e); }
        });
        add(runs, BorderLayout.CENTER);

        showPlaceholder();
        updateCount();
    }

    // ---- Header -------------------------------------------------------------

    private JComponent buildHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);

        JLabel title = I18nUI.text(new JLabel(), "scan.header.title");
        title.setFont(new Font("Segoe UI", Font.BOLD, 15));
        countLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        countLabel.setForeground(Color.GRAY);

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        left.setOpaque(false);
        left.add(title);
        left.add(countLabel);

        I18nUI.text(closeFinishedBtn, "scan.btn.closeFinished");
        I18nUI.text(closeAllBtn, "scan.btn.closeAll");
        styleToolButton(closeFinishedBtn, "scan.btn.closeFinished.tip", e -> closeFinished());
        styleToolButton(closeAllBtn, "scan.btn.closeAll.tip", e -> closeAll());

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        right.setOpaque(false);
        right.add(closeFinishedBtn);
        right.add(closeAllBtn);

        header.add(left, BorderLayout.WEST);
        header.add(right, BorderLayout.EAST);
        return header;
    }

    private void styleToolButton(JButton b, String tipKey, ActionListener al) {
        b.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        I18nUI.tip(b, tipKey);
        b.setFocusPainted(false);
        b.setCursor(new Cursor(Cursor.HAND_CURSOR));
        b.addActionListener(al);
    }

    // ---- Launcher toolbar ---------------------------------------------------

    /**
     * Wire the three scan launchers (called once by BurpExtender right after construction).
     * Each launcher picks a request and starts a campaign that surfaces here as a run.
     */
    public void setLauncherActions(Runnable everything, Runnable thisRequest, Runnable domain) {
        this.onScanEverything = everything;
        this.onScanThisRequest = thisRequest;
        this.onScanDomain = domain;
    }

    private JComponent buildLauncher() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        bar.setOpaque(false);
        bar.add(launcherButton("scan.launch.everything", new Color(156, 39, 176), "scan.launch.everything.tip",
                () -> { if (onScanEverything != null) onScanEverything.run(); }));
        bar.add(launcherButton("scan.launch.thisreq", new Color(33, 150, 243), "scan.launch.thisreq.tip",
                () -> { if (onScanThisRequest != null) onScanThisRequest.run(); }));
        bar.add(launcherButton("scan.launch.domain", new Color(67, 160, 71), "scan.launch.domain.tip",
                () -> { if (onScanDomain != null) onScanDomain.run(); }));
        return bar;
    }

    private JButton launcherButton(String textKey, Color bg, String tipKey, Runnable action) {
        JButton b = new JButton();
        I18nUI.text(b, textKey);
        I18nUI.tip(b, tipKey);
        b.setFont(new Font("Segoe UI", Font.BOLD, 12));
        b.setBackground(bg);
        b.setForeground(Color.WHITE);
        b.setFocusPainted(false);
        b.setBorder(BorderFactory.createEmptyBorder(7, 14, 7, 14));
        b.setCursor(new Cursor(Cursor.HAND_CURSOR));
        b.addActionListener(e -> action.run());
        return b;
    }

    // ---- Run lifecycle (public API used by ScanManager / BurpExtender) ------

    /** Create a new run sub-tab and return its view (call on the EDT). */
    public DetectionRunView newRun(String title) {
        dropPlaceholderIfPresent();
        enforceCap();
        DetectionRunView v = new DetectionRunView();
        counter++;
        addClosableTab(counter + ". " + title, v);
        runs.setSelectedComponent(v);
        updateCount();
        return v;
    }

    /** Begin a single-target run (creates a sub-tab, resets it). */
    public DetectionRunView beginSingle(String url, boolean guided) {
        String pfx = Glyphs.emojiOk() ? (guided ? "▸ " : "▶ ") : "";
        DetectionRunView v = newRun(pfx + shortLabel(url));
        v.startRun(url, guided);
        return v;
    }

    /** Begin a whole-site run (creates a sub-tab; caller drives prepareSiteScan). */
    public DetectionRunView beginSite(String host) {
        DetectionRunView v = newRun((Glyphs.emojiOk() ? "🌐 " : "") + host);
        v.markRunning(); // running from creation; the driver's siteDone()/REPORT clears it (so "Bitenleri
                         // Kapat" can't close a site/matrix run that hasn't set running via startRun yet)
        return v;
    }

    // ---- Closable tabs ------------------------------------------------------

    private void addClosableTab(String title, DetectionRunView view) {
        runs.addTab(title, view);
        int idx = runs.indexOfComponent(view);
        runs.setTabComponentAt(idx, new TabHeader(title, view));
    }

    /** Title label + ✕ close button shown as the tab's component. */
    private class TabHeader extends JPanel {
        TabHeader(String title, DetectionRunView view) {
            super(new FlowLayout(FlowLayout.LEFT, 6, 0));
            setOpaque(false);

            JLabel lbl = new JLabel(title);
            lbl.setFont(new Font("Segoe UI", Font.PLAIN, 12));
            lbl.setForeground(ColorScheme.TEXT_PRIMARY);
            add(lbl);

            JButton rerun = new JButton(Icons.getRetestIcon(13)); // vector icon — font-independent, never tofu
            rerun.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 2));
            rerun.setContentAreaFilled(false);
            rerun.setFocusPainted(false);
            rerun.setCursor(new Cursor(Cursor.HAND_CURSOR));
            I18nUI.tip(rerun, "scan.run.rerun.tip");
            rerun.addActionListener(e -> {
                if (view.isRunning()) {
                    JOptionPane.showMessageDialog(DetectionPanel.this,
                            I18n.t("scan.run.rerun.running"),
                            I18n.t("scan.run.rerun.title"), JOptionPane.INFORMATION_MESSAGE);
                } else if (view.canRerun()) {
                    view.rerun();
                } else {
                    JOptionPane.showMessageDialog(DetectionPanel.this,
                            I18n.t("scan.run.rerun.unsupported"),
                            I18n.t("scan.run.rerun.title"), JOptionPane.INFORMATION_MESSAGE);
                }
            });
            rerun.addMouseListener(new MouseAdapter() {
                @Override public void mouseEntered(MouseEvent e) { rerun.setForeground(new Color(0x4CAF50)); }
                @Override public void mouseExited(MouseEvent e) { rerun.setForeground(Color.GRAY); }
            });
            add(rerun);

            JButton close = new JButton("×"); // multiplication sign × — always has a glyph
            close.setFont(new Font("Segoe UI", Font.BOLD, 13));
            close.setForeground(Color.GRAY);
            close.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 0));
            close.setContentAreaFilled(false);
            close.setFocusPainted(false);
            close.setCursor(new Cursor(Cursor.HAND_CURSOR));
            I18nUI.tip(close, "scan.run.closeTab.tip");
            close.addActionListener(e -> closeRun(view));
            close.addMouseListener(new MouseAdapter() {
                @Override public void mouseEntered(MouseEvent e) { close.setForeground(HOVER_RED); }
                @Override public void mouseExited(MouseEvent e) { close.setForeground(Color.GRAY); }
            });
            add(close);
        }
    }

    private void maybeShowTabMenu(MouseEvent e) {
        if (!e.isPopupTrigger()) return;
        int idx = runs.indexAtLocation(e.getX(), e.getY());
        if (idx < 0) return;
        Component c = runs.getComponentAt(idx);
        if (!(c instanceof DetectionRunView)) return; // placeholder tab
        final DetectionRunView view = (DetectionRunView) c;

        JPopupMenu menu = new JPopupMenu();
        JMenuItem close = new JMenuItem(I18n.t("scan.run.close"));
        close.addActionListener(a -> closeRun(view));
        JMenuItem others = new JMenuItem(I18n.t("scan.run.closeOthers"));
        others.addActionListener(a -> closeOthers(view));
        JMenuItem all = new JMenuItem(I18n.t("scan.run.closeAll"));
        all.addActionListener(a -> closeAll());
        menu.add(close);
        menu.add(others);
        menu.addSeparator();
        menu.add(all);
        menu.show(runs, e.getX(), e.getY());
    }

    // ---- Close actions ------------------------------------------------------

    private void closeRun(DetectionRunView view) {
        if (view == null) return;
        if (view.isRunning()) view.requestAbort();
        int idx = runs.indexOfComponent(view);
        if (idx >= 0) runs.removeTabAt(idx);
        showPlaceholderIfEmpty();
        updateCount();
    }

    private void closeOthers(DetectionRunView keep) {
        for (DetectionRunView v : runViews()) {
            if (v != keep) {
                if (v.isRunning()) v.requestAbort();
                int idx = runs.indexOfComponent(v);
                if (idx >= 0) runs.removeTabAt(idx);
            }
        }
        showPlaceholderIfEmpty();
        updateCount();
    }

    private void closeFinished() {
        for (DetectionRunView v : runViews()) {
            if (!v.isRunning()) {
                int idx = runs.indexOfComponent(v);
                if (idx >= 0) runs.removeTabAt(idx);
            }
        }
        showPlaceholderIfEmpty();
        updateCount();
    }

    private void closeAll() {
        for (DetectionRunView v : runViews()) {
            if (v.isRunning()) v.requestAbort();
        }
        runs.removeAll();
        showPlaceholder();
        updateCount();
    }

    // ---- Helpers ------------------------------------------------------------

    /** Snapshot of the current run views (excludes the placeholder), oldest first. */
    private List<DetectionRunView> runViews() {
        List<DetectionRunView> list = new ArrayList<>();
        for (int i = 0; i < runs.getTabCount(); i++) {
            Component c = runs.getComponentAt(i);
            if (c instanceof DetectionRunView) list.add((DetectionRunView) c);
        }
        return list;
    }

    /** Drop the oldest FINISHED run while over the cap; never kills a live run to make room. */
    private void enforceCap() {
        while (runViews().size() >= MAX_RUNS) {
            DetectionRunView victim = null;
            for (DetectionRunView v : runViews()) {
                if (!v.isRunning()) { victim = v; break; }
            }
            if (victim == null) break; // all running — let it temporarily exceed
            int idx = runs.indexOfComponent(victim);
            if (idx >= 0) runs.removeTabAt(idx);
            else break;
        }
    }

    private void dropPlaceholderIfPresent() {
        if (runs.getTabCount() == 1 && !(runs.getComponentAt(0) instanceof DetectionRunView)) {
            runs.removeTabAt(0);
        }
    }

    private void showPlaceholderIfEmpty() {
        if (runViews().isEmpty() && runs.getTabCount() == 0) showPlaceholder();
    }

    private void showPlaceholder() {
        runs.removeAll();
        JLabel empty = new JLabel(I18n.t("scan.placeholder"), SwingConstants.CENTER);
        empty.setForeground(Color.GRAY);
        runs.addTab(I18n.t("scan.tab.info"), empty);
    }

    private void updateCount() {
        int n = runViews().size();
        countLabel.setText(n == 0 ? "" : I18n.t("scan.count", n));
        closeFinishedBtn.setEnabled(n > 0);
        closeAllBtn.setEnabled(n > 0);
    }

    /**
     * Re-apply the current language to the dynamic bits the tree-walker can't reach: the run-count
     * label and (when shown) the empty-state placeholder. Static labels/buttons/tooltips bound via
     * {@link I18nUI} are handled by {@link I18nUI#relocalize}. Call on the EDT.
     */
    public void applyLanguage() {
        if (runViews().isEmpty()) showPlaceholder(); // rebuild placeholder text + "Info" tab title
        updateCount();
    }

    private String shortLabel(String url) {
        try {
            URL u = new URL(url);
            String path = u.getPath();
            String tail = (path == null || path.isEmpty() || "/".equals(path))
                    ? u.getHost()
                    : u.getHost() + path;
            if (tail.length() > 40) {
                tail = "…" + tail.substring(tail.length() - 39);
            }
            return tail;
        } catch (Exception e) {
            return url.length() > 40 ? url.substring(0, 40) : url;
        }
    }
}

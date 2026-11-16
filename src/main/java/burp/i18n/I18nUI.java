package burp.i18n;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Swing glue for {@link I18n}: helpers that bind a component's text/tooltip/titled-border to a
 * catalog key (remembered in a client property), plus a tree walker that re-applies the current
 * language to an entire component subtree — so a language switch updates live, in place, with no
 * panel recreation (and therefore no state loss or stale cross-references).
 *
 * @author Zahid Eroglu
 */
public final class I18nUI {

    private static final String KEY_TEXT   = "i18n.text";
    private static final String KEY_TIP    = "i18n.tip";
    private static final String KEY_BORDER = "i18n.border";

    private I18nUI() {}

    // ---- binders (use while building UI) ------------------------------------

    /** Bind a button/menu-item's label to {@code key}. */
    public static <T extends AbstractButton> T text(T b, String key) {
        b.putClientProperty(KEY_TEXT, key);
        b.setText(I18n.t(key));
        return b;
    }

    /** Bind a label's text to {@code key}. */
    public static JLabel text(JLabel l, String key) {
        l.putClientProperty(KEY_TEXT, key);
        l.setText(I18n.t(key));
        return l;
    }

    /** Bind a component's tooltip to {@code key}. */
    public static <T extends JComponent> T tip(T c, String key) {
        c.putClientProperty(KEY_TIP, key);
        c.setToolTipText(I18n.t(key));
        return c;
    }

    /** Give {@code c} a titled border whose title is bound to {@code key}. */
    public static <T extends JComponent> T titled(T c, String key) {
        c.putClientProperty(KEY_BORDER, key);
        c.setBorder(BorderFactory.createTitledBorder(I18n.t(key)));
        return c;
    }

    /**
     * A read-only, word-wrapping "label" backed by a {@link JTextArea}, bound to {@code key}.
     * Use this for multi-line descriptions/notes instead of an HTML {@link JLabel}: Burp's L&F does
     * not render {@code <html>} in JLabels (the raw tags show), and a JLabel can't wrap plain text.
     * The text area is transparent, non-editable and non-focusable so it reads like a label, and it
     * reports a label-like maximum size so it wraps to the container width inside a BoxLayout.
     */
    public static JTextArea multiline(String key) {
        JTextArea ta = new JTextArea() {
            @Override public java.awt.Dimension getMaximumSize() {
                return new java.awt.Dimension(Integer.MAX_VALUE, getPreferredSize().height);
            }
        };
        ta.setEditable(false);
        ta.setLineWrap(true);
        ta.setWrapStyleWord(true);
        ta.setOpaque(false);
        ta.setFocusable(false);
        ta.setBorder(null);
        ta.setAlignmentX(java.awt.Component.LEFT_ALIGNMENT);
        ta.putClientProperty(KEY_TEXT, key);
        ta.setText(I18n.t(key));
        return ta;
    }

    // ---- live re-localization ----------------------------------------------

    /**
     * Re-apply the current language to {@code root} and all descendants. Call on the EDT after
     * {@link I18n#setLang}. Components without an i18n client property are left untouched.
     */
    public static void relocalize(Component root) {
        if (root == null) return;

        if (root instanceof JComponent) {
            JComponent jc = (JComponent) root;

            Object tk = jc.getClientProperty(KEY_TEXT);
            if (tk instanceof String) {
                if (jc instanceof AbstractButton)      ((AbstractButton) jc).setText(I18n.t((String) tk));
                else if (jc instanceof JLabel)         ((JLabel) jc).setText(I18n.t((String) tk));
                else if (jc instanceof javax.swing.text.JTextComponent)
                                                        ((javax.swing.text.JTextComponent) jc).setText(I18n.t((String) tk));
            }

            Object tip = jc.getClientProperty(KEY_TIP);
            if (tip instanceof String) jc.setToolTipText(I18n.t((String) tip));

            Object bk = jc.getClientProperty(KEY_BORDER);
            if (bk instanceof String) {
                Border b = jc.getBorder();
                if (b instanceof TitledBorder) ((TitledBorder) b).setTitle(I18n.t((String) bk));
            }
        }

        if (root instanceof Container) {
            for (Component child : ((Container) root).getComponents()) {
                relocalize(child);
            }
        }
        // Note: JTabbedPane tab *titles* aren't child components; callers re-apply those explicitly
        // (see BurpExtender.applyLanguage). Tab *content* is walked above as normal children.
    }
}

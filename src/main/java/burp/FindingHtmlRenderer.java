package burp;

import burp.i18n.I18n;

import java.util.List;

/**
 * Renders a {@link Finding} into the themed HTML used by the "Vulnerability Info"
 * views (inline detail pane + full-details dialog). Extracted from FindingsPanel
 * so the rendering is a stateless, reusable, separately-testable unit.
 *
 * <p>Swing's HTML engine only honours a small CSS subset (background-color, color,
 * font-*, padding, margin, border-left, text-align). Everything here sticks to that
 * subset so the layout renders the same in every Burp/JDK theme.
 *
 * <p>All methods are pure functions of their inputs (plus {@link I18n} for the UI
 * language). The cross-used helpers ({@link #escapeHtml}, {@link #stripHtmlTags},
 * {@link #severityFriendly}, {@link #priorityFriendly}, {@link #getSeverityHtmlColor})
 * and the palette constants are {@code public} because other FindingsPanel views
 * (references tab, text report) reuse them.
 *
 * @author Zahid Eroglu
 */
public final class FindingHtmlRenderer {

    // ── Palette (shared by all finding HTML views) ──────────────────────────────
    public static final String INK         = "#1f2933";  // primary text
    public static final String INK_SOFT    = "#3a4654";  // headings
    public static final String LABEL_GREY  = "#7a8794";  // small metric labels
    public static final String CARD_BG     = "#f6f8fa";  // neutral card surface
    public static final String CARD_ACCENT = "#9aa6b2";  // neutral accent stripe

    private FindingHtmlRenderer() {}

    /** Severity → CSS color (badge / accent). */
    public static String getSeverityHtmlColor(String severity) {
        switch (severity.toLowerCase()) {
            case "critical": return "#b71c1c";
            case "high": return "#d32f2f";
            case "medium": return "#ff9800";
            case "low": return "#4caf50";
            default: return "#9e9e9e";
        }
    }

    /** Severity in plain words instead of EN codes ("Medium" -> "Orta"/"Medium"). */
    public static String severityFriendly(String severity) {
        if (severity == null) return I18n.t("findings.sev.info");
        switch (severity.toLowerCase()) {
            case "critical": return I18n.t("findings.sev.critical");
            case "high":     return I18n.t("findings.sev.high");
            case "medium":   return I18n.t("findings.sev.medium");
            case "low":      return I18n.t("findings.sev.low");
            default:         return I18n.t("findings.sev.info");
        }
    }

    /** Priority code annotated with its meaning ("P2" -> "P2 (orta)"/"P2 (medium)"). */
    public static String priorityFriendly(String priority) {
        if (priority == null) return "—";
        switch (priority.toUpperCase()) {
            case "P1": return "P1 (" + I18n.t("findings.prio.high") + ")";
            case "P2": return "P2 (" + I18n.t("findings.prio.medium") + ")";
            case "P3": return "P3 (" + I18n.t("findings.prio.low") + ")";
            default:   return priority + " (" + I18n.t("findings.prio.veryLow") + ")";
        }
    }

    /** Escape HTML special characters. */
    public static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }

    /** Strip HTML tags from text (for plain-text reuse, e.g. text reports). */
    public static String stripHtmlTags(String text) {
        if (text == null) return "";
        return text.replaceAll("<[^>]*>", "")
                   .replaceAll("&nbsp;", " ")
                   .replaceAll("&lt;", "<")
                   .replaceAll("&gt;", ">")
                   .replaceAll("&amp;", "&")
                   .replaceAll("&quot;", "\"")
                   .replaceAll("&#x27;", "'");
    }

    /** Plain-text body → HTML-safe, with line breaks preserved as &lt;br/&gt;. */
    private static String htmlInline(String s) {
        return escapeHtml(stripHtmlTags(s)).replace("\n", "<br/>");
    }

    /** One consistent section "card": soft surface + coloured left accent + bold heading. */
    private static String sectionCardHtml(String title, String accent, String bg, String titleColor, String bodyHtml) {
        return "<div style='margin-bottom:11px; background-color:" + bg
             + "; border-left:4px solid " + accent + "; padding:10px;'>"
             + "<div style='color:" + titleColor + "; font-weight:bold; font-size:11px; margin-bottom:5px;'>"
             + title + "</div>"
             + bodyHtml
             + "</div>";
    }

    /** At-a-glance metrics strip: Severity · Priority · CVSS · Confidence. */
    private static String metricsCardHtml(Finding f) {
        String sev = f.getEffectiveSeverity();
        String sevColor = getSeverityHtmlColor(sev);
        String lbl = "color:" + LABEL_GREY + "; font-size:10px;";
        String val = "font-size:13px; font-weight:bold; color:" + INK + ";";
        StringBuilder h = new StringBuilder();
        h.append("<table width='100%' cellspacing='0' cellpadding='9' style='margin-bottom:14px; background-color:#f4f7fb; border-left:4px solid ")
         .append(sevColor).append(";'><tr>");
        h.append("<td valign='top'><div style='").append(lbl).append("'>").append(I18n.t("findings.col.severity"))
         .append("</div><div style='").append(val).append("'><font color='").append(sevColor).append("'>● ")
         .append(severityFriendly(sev)).append("</font></div></td>");
        h.append("<td valign='top'><div style='").append(lbl).append("'>").append(I18n.t("findings.col.priority"))
         .append("</div><div style='").append(val).append("'>").append(priorityFriendly(f.getEffectivePriority()))
         .append("</div></td>");
        h.append("<td valign='top'><div style='").append(lbl).append("'>").append(I18n.t("findings.col.cvss"))
         .append("</div><div style='").append(val).append("'><font color='#0f7d8c'>")
         .append(String.format("%.1f", f.getEffectiveCvss())).append(" / 10</font></div></td>");
        h.append("<td valign='top'><div style='").append(lbl).append("'>").append(I18n.t("findings.col.confidence"))
         .append("</div><div style='").append(val).append("'>%")
         .append(String.format("%.0f", f.getConfidence() * 100)).append("</div></td>");
        h.append("</tr></table>");
        return h.toString();
    }

    /**
     * Build the complete, themed HTML body for a finding's "Vulnerability Info" view.
     * Shared by the inline detail pane and the full-details dialog so both stay consistent.
     */
    public static String buildFindingDetailHtml(Finding f, boolean includeSummary) {
        StringBuilder h = new StringBuilder();
        h.append("<html><body style='font-family:\"Segoe UI\",sans-serif; font-size:12px; color:")
         .append(INK).append("; background-color:#ffffff; margin:0; padding:14px 16px;'>");

        if (includeSummary) h.append(metricsCardHtml(f));

        // Needs-review banner: first gate liked it, the independent second pass could not reproduce it.
        if (f.isNeedsReview()) {
            h.append("<div style='margin:0 0 10px 0; padding:8px 12px; border-radius:6px; "
                    + "background-color:#fff4d6; border:1px solid #e0a106; color:#7a5600;'>"
                    + "<b>⚠ " + I18n.t("findings.badge.needsReview") + "</b> &nbsp; "
                    + escapeHtml(I18n.t("indep.needsReview")) + "</div>");
        }

        String url = f.getAffectedUrl();
        if (url != null && !url.isEmpty()) {
            h.append(sectionCardHtml(I18n.t("findings.heading.affectedUrl"),
                    "#1f6feb", "#eef4ff", "#1f6feb",
                    "<span style='font-family:Consolas,monospace; color:#0b4ea2;'>" + escapeHtml(url) + "</span>"));
        }

        if (f.getDescription() != null && !f.getDescription().isEmpty()) {
            h.append(sectionCardHtml(I18n.t("findings.heading.description"),
                    CARD_ACCENT, CARD_BG, INK_SOFT,
                    "<span style='color:" + INK + ";'>" + htmlInline(f.getDescription()) + "</span>"));
        }

        if (f.getEvidence() != null && !f.getEvidence().isEmpty()) {
            h.append(sectionCardHtml(I18n.t("findings.heading.evidence"),
                    "#e0a106", "#fff8e6", "#8a6300",
                    "<pre style='margin:0; white-space:pre-wrap; font-family:Consolas,monospace; color:#5f4700;'>"
                            + escapeHtml(stripHtmlTags(f.getEvidence())) + "</pre>"));
        }

        if (f.getExploitation() != null && !f.getExploitation().isEmpty()) {
            h.append(sectionCardHtml(I18n.t("findings.heading.exploitation"),
                    "#e5484d", "#fdeef0", "#a11620",
                    "<span style='color:#7d1620;'>" + htmlInline(f.getExploitation()) + "</span>"));
        }

        if (f.getRemediation() != null && !f.getRemediation().isEmpty()) {
            h.append(sectionCardHtml(I18n.t("findings.heading.remediation"),
                    "#2faa5e", "#eef9f1", "#1d6b3a",
                    "<span style='color:#155724;'>" + htmlInline(f.getRemediation()) + "</span>"));
        }

        String cwe = f.getCweId(), owasp = f.getOwaspCategory();
        String owaspApi = f.getOwaspApiCategory(), wstg = f.getWstgId(), cvssVec = f.getCvssVector();
        if ((cwe != null && !cwe.isEmpty()) || (owasp != null && !owasp.isEmpty())
                || !owaspApi.isEmpty() || !wstg.isEmpty()) {
            StringBuilder cls = new StringBuilder();
            if (cwe != null && !cwe.isEmpty()) {
                cls.append("<b style='color:").append(INK_SOFT).append(";'>").append(I18n.t("findings.label.cwe"))
                   .append("</b> <font color='#1f6feb'>").append(escapeHtml(cwe)).append("</font>");
            }
            if (owasp != null && !owasp.isEmpty()) {
                if (cls.length() > 0) cls.append(" &nbsp;&nbsp;&nbsp; ");
                cls.append("<b style='color:").append(INK_SOFT).append(";'>").append(I18n.t("findings.label.owasp"))
                   .append("</b> <font color='#1f6feb'>").append(escapeHtml(owasp)).append("</font>");
            }
            if (!owaspApi.isEmpty()) {
                if (cls.length() > 0) cls.append(" &nbsp;&nbsp;&nbsp; ");
                cls.append("<b style='color:").append(INK_SOFT).append(";'>").append(I18n.t("findings.label.owaspApi"))
                   .append("</b> <font color='#1f6feb'>").append(escapeHtml(owaspApi)).append("</font>");
            }
            if (!wstg.isEmpty()) {
                if (cls.length() > 0) cls.append(" &nbsp;&nbsp;&nbsp; ");
                cls.append("<b style='color:").append(INK_SOFT).append(";'>").append(I18n.t("findings.label.wstg"))
                   .append("</b> <font color='#1f6feb'>").append(escapeHtml(wstg)).append("</font>");
            }
            if (cvssVec != null && !cvssVec.isEmpty()) {
                cls.append("<br><b style='color:").append(INK_SOFT).append(";'>").append(I18n.t("findings.label.cvssVector"))
                   .append("</b> <font color='").append(INK_SOFT).append("'>").append(escapeHtml(cvssVec)).append("</font>");
            }
            h.append(sectionCardHtml(I18n.t("findings.heading.classification"),
                    CARD_ACCENT, CARD_BG, INK_SOFT, cls.toString()));
        }

        List<String> refs = f.getReferences();
        if (refs != null && !refs.isEmpty()) {
            StringBuilder rb = new StringBuilder("<ul style='margin:2px 0 0 0; padding-left:18px;'>");
            for (String ref : refs) {
                String safe = escapeHtml(ref);
                rb.append("<li style='margin-bottom:4px;'><a href='").append(safe)
                  .append("' style='color:#1f6feb;'>").append(safe).append("</a></li>");
            }
            rb.append("</ul>");
            h.append(sectionCardHtml(I18n.t("findings.heading.references"),
                    CARD_ACCENT, CARD_BG, INK_SOFT, rb.toString()));
        }

        h.append("</body></html>");
        return h.toString();
    }
}

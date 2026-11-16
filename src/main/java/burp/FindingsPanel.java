package burp;

import burp.i18n.I18n;
import burp.i18n.I18nUI;
import javax.swing.*;
import javax.swing.table.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.regex.*;

/**
 * Findings Panel - Displays vulnerability findings in a professional table
 * with Request/Response viewer and evidence highlighting
 *
 * @author Zahid Eroglu
 */
public class FindingsPanel extends JPanel {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private DefaultTableModel tableModel;
    private JTable findingsTable;
    private List<Finding> findings;
    private List<IHttpRequestResponse> requestResponses;
    private DatabaseManager dbManager;
    private Set<String> findingHashes; // For duplicate detection

    // Performance optimization
    private volatile boolean bulkAddMode = false;
    private java.util.Timer updateTimer;
    private volatile boolean needsUpdate = false;

    // Detail panel components
    private JSplitPane mainSplitPane;
    private JPanel detailPanel;
    private JTextPane requestPane;
    private JTextPane responsePane;
    private JTextPane infoPane;
    private JLabel detailTitleLabel;
    private Finding selectedFinding;
    private IHttpRequestResponse selectedRequestResponse;
    private JLabel countLabel; // Direct reference for performance
    private QwenAPIClient qwenClient; // for AI-written report narrative (optional)

    public FindingsPanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, DatabaseManager dbManager) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        this.dbManager = dbManager;
        this.findings = new ArrayList<>();
        this.requestResponses = new ArrayList<>();
        this.findingHashes = new HashSet<>();

        setLayout(new BorderLayout());
        setBackground(ColorScheme.BG_LIGHT);

        createUI();
        startUpdateTimer();
    }

    /**
     * Start timer for batched UI updates (improves performance)
     */
    private void startUpdateTimer() {
        updateTimer = new java.util.Timer("FindingsPanelUpdater", true);
        updateTimer.scheduleAtFixedRate(new java.util.TimerTask() {
            @Override
            public void run() {
                if (needsUpdate && !bulkAddMode) {
                    SwingUtilities.invokeLater(() -> {
                        updateCountLabel();
                        needsUpdate = false;
                    });
                }
            }
        }, 500, 500); // Update every 500ms if needed
    }

    private void createUI() {
        // Main split pane - table on top, details on bottom
        mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setDividerLocation(250);
        mainSplitPane.setResizeWeight(0.4);

        // TOP: Table panel
        JPanel tablePanel = createTablePanel();
        mainSplitPane.setTopComponent(tablePanel);

        // BOTTOM: Detail panel
        detailPanel = createDetailPanel();
        mainSplitPane.setBottomComponent(detailPanel);

        add(mainSplitPane, BorderLayout.CENTER);
    }

    /**
     * Create the findings table panel
     */
    public void setQwenClient(QwenAPIClient q) { this.qwenClient = q; }

    /** Export the current findings as a professional .docx report (AI summary + structured sections). */
    private void exportProReport() {
        if (findings == null || findings.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18n.t("findings.report.none"));
            return;
        }
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new java.io.File("AppSecHunter-Rapor.docx"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        java.io.File sel = fc.getSelectedFile();
        if (!sel.getName().toLowerCase().endsWith(".docx")) {
            sel = new java.io.File(sel.getParentFile(), sel.getName() + ".docx");
        }
        final java.io.File out = sel;
        final List<Finding> snapshot = new ArrayList<>(findings);
        JOptionPane.showMessageDialog(this, I18n.t("findings.report.generating"));
        new Thread(() -> {
            try {
                new burp.report.ProReportGenerator(qwenClient).generate(snapshot, out);
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this,
                        I18n.t("findings.report.saved") + "\n" + out.getAbsolutePath()));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(this,
                        I18n.t("findings.report.error") + " " + ex.getMessage()));
            }
        }, "pro-report").start();
    }

    private JPanel createTablePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(ColorScheme.BG_LIGHT);

        // Title with icon
        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setBackground(ColorScheme.BG_LIGHT);
        titlePanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        JLabel titleLabel = I18nUI.text(new JLabel("Vulnerability Findings"), "findings.title");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        titleLabel.setForeground(ColorScheme.PRIMARY_BLUE);
        titleLabel.setIcon(Icons.getShieldIcon(18, ColorScheme.PRIMARY_BLUE));
        titlePanel.add(titleLabel, BorderLayout.WEST);

        countLabel = new JLabel(I18n.t("findings.count", 0)); // Store reference for direct access
        countLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        countLabel.setForeground(ColorScheme.TEXT_SECONDARY);
        JButton proReportBtn = I18nUI.text(new JButton("Pro Rapor (DOCX)"), "findings.btn.proReport");
        I18nUI.tip(proReportBtn, "findings.btn.proReport.tip");
        proReportBtn.addActionListener(e -> exportProReport());
        JPanel eastPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        eastPanel.setOpaque(false);
        eastPanel.add(proReportBtn);
        eastPanel.add(countLabel);
        titlePanel.add(eastPanel, BorderLayout.EAST);

        panel.add(titlePanel, BorderLayout.NORTH);

        // Table with enhanced columns
        String[] columnNames = {"#", I18n.t("findings.col.type"), I18n.t("findings.col.severity"),
                I18n.t("findings.col.cvss"), I18n.t("findings.col.priority"),
                I18n.t("findings.col.confidence"), I18n.t("findings.col.url")};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
            @Override
            public Class<?> getColumnClass(int column) {
                return String.class;
            }
        };

        findingsTable = new JTable(tableModel);
        findingsTable.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        findingsTable.setRowHeight(32);
        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        findingsTable.setShowGrid(false);
        findingsTable.setIntercellSpacing(new Dimension(0, 1));

        // Performance optimizations for large datasets
        findingsTable.setAutoCreateRowSorter(false); // Disable auto sorting for performance
        findingsTable.setFillsViewportHeight(false); // Don't fill entire viewport
        findingsTable.setRowMargin(0); // Reduce margin for faster rendering

        // Custom cell renderer for professional dark theme look
        findingsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                                                          boolean isSelected, boolean hasFocus,
                                                          int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                setOpaque(true);
                setHorizontalAlignment(column == 0 ? CENTER : LEFT);
                setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
                setToolTipText(value == null ? null : value.toString()); // full text on hover (URL/Type)
                if (column == 0) setText(String.valueOf(row + 1));        // finding number

                // Theme-adaptive colors (follow Burp's light/dark theme via ColorScheme)
                Color bgColor = ColorScheme.TABLE_BG;            // base row background
                Color bgAltColor = ColorScheme.TABLE_BG_ALT;     // alternating row background
                Color selectedBg = ColorScheme.TABLE_SELECTION_BG;
                Color textColor = ColorScheme.TEXT_PRIMARY;      // readable on either theme

                // Severity column (2) - bold colored text
                if (column == 2 && value != null) {
                    String severity = value.toString();
                    setForeground(ColorScheme.getSeverityColor(severity));
                    setFont(getFont().deriveFont(Font.BOLD));
                }
                // CVSS column (3)
                else if (column == 3 && value != null) {
                    try {
                        double cvss = Double.parseDouble(value.toString());
                        if (cvss >= 9.0) setForeground(new Color(229, 57, 53));      // Red
                        else if (cvss >= 7.0) setForeground(new Color(244, 81, 30)); // Deep Orange
                        else if (cvss >= 4.0) setForeground(new Color(0xC79100));    // Amber (readable on white)
                        else setForeground(new Color(67, 160, 71));                  // Green
                        setFont(getFont().deriveFont(Font.BOLD));
                    } catch (Exception e) {
                        setForeground(textColor);
                    }
                }
                // Priority column (4)
                else if (column == 4 && value != null) {
                    String priority = value.toString();
                    switch (priority) {
                        case "P1": setForeground(new Color(229, 57, 53)); break;  // Red
                        case "P2": setForeground(new Color(245, 124, 0)); break;  // Orange
                        case "P3": setForeground(new Color(0xC79100)); break;     // Gold (readable on white)
                        case "P4": setForeground(new Color(67, 160, 71)); break;  // Green
                        default: setForeground(ColorScheme.TEXT_DISABLED);        // Grey
                    }
                    setFont(getFont().deriveFont(Font.BOLD));
                }
                // Type column (1) - white/light text
                else if (column == 1) {
                    setForeground(textColor);
                    setFont(new Font("Segoe UI", Font.PLAIN, 12));
                }
                // URL column (6) - slightly dimmer
                else if (column == 6) {
                    setForeground(ColorScheme.TEXT_SECONDARY);
                    setFont(new Font("Segoe UI", Font.PLAIN, 11));
                }
                // Confidence column (5)
                else if (column == 5) {
                    setForeground(ColorScheme.PRIMARY_BLUE);
                    setFont(new Font("Segoe UI", Font.PLAIN, 12));
                }
                else {
                    setForeground(textColor);
                    setFont(new Font("Segoe UI", Font.PLAIN, 12));
                }

                // Background colors
                if (isSelected) {
                    setBackground(selectedBg);
                    // Keep special column colors on selection
                } else {
                    setBackground(row % 2 == 0 ? bgColor : bgAltColor);
                }

                return c;
            }
        });

        // Theme-adaptive table chrome (follows Burp's light/dark theme)
        findingsTable.setBackground(ColorScheme.TABLE_BG);
        findingsTable.setForeground(ColorScheme.TEXT_PRIMARY);
        findingsTable.setSelectionBackground(ColorScheme.TABLE_SELECTION_BG);
        findingsTable.setSelectionForeground(ColorScheme.TABLE_SELECTION_FG);
        findingsTable.setGridColor(ColorScheme.TABLE_GRID);
        findingsTable.getTableHeader().setBackground(ColorScheme.TABLE_HEADER_BG);
        findingsTable.getTableHeader().setForeground(ColorScheme.TABLE_HEADER_FG);

        // Column widths
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(44);   // # number
        findingsTable.getColumnModel().getColumn(0).setMaxWidth(60);
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(200);  // Type
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(80);   // Severity
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(60);   // CVSS
        findingsTable.getColumnModel().getColumn(4).setPreferredWidth(60);   // Priority
        findingsTable.getColumnModel().getColumn(5).setPreferredWidth(80);   // Confidence
        findingsTable.getColumnModel().getColumn(6).setPreferredWidth(300);  // URL

        // Selection listener - show details in bottom panel
        findingsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = findingsTable.getSelectedRow();
                if (row >= 0 && row < findings.size()) {
                    selectedFinding = findings.get(row);
                    selectedRequestResponse = (row < requestResponses.size()) ? requestResponses.get(row) : null;
                    updateDetailPanel();
                }
            }
        });

        // Double click to show full details dialog
        findingsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = findingsTable.getSelectedRow();
                    if (row >= 0 && row < findings.size()) {
                        showFindingDetailsDialog(findings.get(row),
                            (row < requestResponses.size()) ? requestResponses.get(row) : null);
                    }
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) showContextMenu(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) showContextMenu(e);
            }

            private void showContextMenu(MouseEvent e) {
                int row = findingsTable.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    findingsTable.setRowSelectionInterval(row, row);
                    JPopupMenu popup = createContextMenu(row);
                    popup.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(findingsTable);
        scrollPane.setBorder(BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT));
        panel.add(scrollPane, BorderLayout.CENTER);

        // Bottom panel with action buttons
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        bottomPanel.setBackground(ColorScheme.BG_LIGHT);
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));

        JButton clearBtn = I18nUI.text(createStyledButton("Clear All", ColorScheme.ERROR_RED), "findings.btn.clearAll");
        clearBtn.addActionListener(e -> clearFindings());
        bottomPanel.add(clearBtn);

        JButton exportBtn = I18nUI.text(createStyledButton("Export", ColorScheme.SUCCESS_GREEN), "findings.btn.export");
        exportBtn.addActionListener(e -> exportFindings());
        bottomPanel.add(exportBtn);

        JButton markFPBtn = I18nUI.text(createStyledButton("False Positive", ColorScheme.WARNING_ORANGE), "findings.btn.falsePositive");
        markFPBtn.addActionListener(e -> markAsFalsePositive());
        bottomPanel.add(markFPBtn);

        panel.add(bottomPanel, BorderLayout.SOUTH);

        return panel;
    }

    /**
     * Create the detail panel showing Request/Response with evidence highlighting
     */
    private JPanel createDetailPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(ColorScheme.BG_CARD);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, ColorScheme.BORDER_LIGHT),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));

        // Header with finding info
        JPanel headerPanel = new JPanel(new BorderLayout(10, 5));
        headerPanel.setBackground(ColorScheme.BG_CARD);
        headerPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

        detailTitleLabel = new JLabel(I18n.t("findings.detail.selectPrompt"));
        detailTitleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        detailTitleLabel.setForeground(ColorScheme.TEXT_DARK);
        headerPanel.add(detailTitleLabel, BorderLayout.CENTER);

        // Action buttons for selected finding
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        actionPanel.setBackground(ColorScheme.BG_CARD);

        JButton repeaterBtn = I18nUI.text(createSmallButton("Send to Repeater", ColorScheme.PRIMARY_BLUE), "findings.btn.sendToRepeater");
        repeaterBtn.addActionListener(e -> {
            int row = findingsTable.getSelectedRow();
            if (row >= 0) sendToRepeater(row);
        });
        actionPanel.add(repeaterBtn);

        JButton pocBtn = I18nUI.text(createSmallButton("Generate PoC", ColorScheme.WARNING_ORANGE), "findings.btn.generatePoC");
        pocBtn.addActionListener(e -> {
            int row = findingsTable.getSelectedRow();
            if (row >= 0) generatePoC(row);
        });
        actionPanel.add(pocBtn);

        JButton detailsBtn = I18nUI.text(createSmallButton("Full Details", ColorScheme.SUCCESS_GREEN), "findings.btn.fullDetails");
        detailsBtn.addActionListener(e -> {
            if (selectedFinding != null) {
                showFindingDetailsDialog(selectedFinding, selectedRequestResponse);
            }
        });
        actionPanel.add(detailsBtn);

        headerPanel.add(actionPanel, BorderLayout.EAST);
        panel.add(headerPanel, BorderLayout.NORTH);

        // Tab pane for Info/Request/Response
        JTabbedPane detailTabs = new JTabbedPane();
        detailTabs.setFont(new Font("Segoe UI", Font.PLAIN, 12));

        // Info tab — light "report card" pane (white fill removes the dark seam below content)
        infoPane = new JTextPane();
        infoPane.setEditable(false);
        infoPane.setContentType("text/html");
        infoPane.setBackground(Color.WHITE);
        infoPane.setBorder(BorderFactory.createEmptyBorder());
        installLinkOpener(infoPane);
        JScrollPane infoScroll = new JScrollPane(infoPane);
        infoScroll.getViewport().setBackground(Color.WHITE);
        detailTabs.addTab(I18n.t("findings.tab.vulnInfo"), infoScroll);

        // Request tab
        requestPane = new JTextPane();
        requestPane.setEditable(false);
        requestPane.setFont(new Font("Consolas", Font.PLAIN, 12));
        requestPane.setBackground(ColorScheme.CONSOLE_BG);
        JScrollPane requestScroll = new JScrollPane(requestPane);
        detailTabs.addTab(I18n.t("findings.tab.request"), requestScroll);

        // Response tab with evidence highlighting
        responsePane = new JTextPane();
        responsePane.setEditable(false);
        responsePane.setFont(new Font("Consolas", Font.PLAIN, 12));
        responsePane.setBackground(ColorScheme.CONSOLE_BG);
        JScrollPane responseScroll = new JScrollPane(responsePane);
        detailTabs.addTab(I18n.t("findings.tab.responseHighlighted"), responseScroll);

        panel.add(detailTabs, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Update the detail panel when a finding is selected (lazy loading for performance)
     */
    private void updateDetailPanel() {
        if (selectedFinding == null) {
            detailTitleLabel.setText(I18n.t("findings.detail.selectPrompt"));
            detailTitleLabel.setForeground(ColorScheme.TEXT_DARK);
            infoPane.setText("");
            requestPane.setText("");
            responsePane.setText("");
            return;
        }

        // Update title — friendly, colour-coded ("Broken Access Control — Orta önem · CVSS 5.0")
        String effSev = selectedFinding.getEffectiveSeverity();
        detailTitleLabel.setText(selectedFinding.getType()
            + "   —   " + FindingHtmlRenderer.severityFriendly(effSev) + " " + I18n.t("findings.label.severityWord")
            + "   ·   CVSS " + String.format("%.1f", selectedFinding.getEffectiveCvss()));
        detailTitleLabel.setForeground(ColorScheme.getSeverityColor(effSev));

        // Update info pane immediately (lightweight)
        updateInfoPane();

        // Load request/response in background to avoid UI freeze
        new Thread(() -> {
            try {
                // Prepare text in background
                final String requestText = prepareRequestText();
                final String responseText = prepareResponseText();

                // Update UI on EDT
                SwingUtilities.invokeLater(() -> {
                    updateRequestPane(requestText);
                    updateResponsePane(responseText);
                });
            } catch (Exception e) {
                // Ignore errors during background loading
            }
        }, "FindingDetailLoader").start();
    }

    /**
     * Prepare request text in background
     */
    private String prepareRequestText() {
        if (selectedFinding.getHttpRequest() != null && !selectedFinding.getHttpRequest().isEmpty()) {
            return selectedFinding.getHttpRequest();
        } else if (selectedRequestResponse != null && selectedRequestResponse.getRequest() != null) {
            return new String(selectedRequestResponse.getRequest());
        }
        return I18n.t("findings.noRequestData");
    }

    /**
     * Prepare response text in background
     */
    private String prepareResponseText() {
        if (selectedFinding.getHttpResponse() != null && !selectedFinding.getHttpResponse().isEmpty()) {
            return selectedFinding.getHttpResponse();
        } else if (selectedRequestResponse != null && selectedRequestResponse.getResponse() != null) {
            return new String(selectedRequestResponse.getResponse());
        }
        return I18n.t("findings.noResponseData");
    }

    /**
     * Update the info pane with vulnerability details
     */
    private void updateInfoPane() {
        if (selectedFinding == null) {
            infoPane.setText("");
            return;
        }
        infoPane.setText(FindingHtmlRenderer.buildFindingDetailHtml(selectedFinding, true));
        infoPane.setCaretPosition(0);
    }

    /**
     * Update the request pane (optimized with pre-prepared text)
     */
    private void updateRequestPane(String requestText) {
        StyledDocument doc = requestPane.getStyledDocument();

        // Clear existing content
        try {
            doc.remove(0, doc.getLength());
        } catch (BadLocationException e) {}

        // Style for request text (theme-adaptive ink)
        Style defaultStyle = doc.addStyle("default", null);
        StyleConstants.setForeground(defaultStyle, ColorScheme.CONSOLE_FG);
        StyleConstants.setFontFamily(defaultStyle, "Consolas");
        StyleConstants.setFontSize(defaultStyle, 12);

        Style headerStyle = doc.addStyle("header", null);
        StyleConstants.setForeground(headerStyle, ColorScheme.isDarkMode() ? new Color(86, 156, 214) : new Color(0x1F6FEB));
        StyleConstants.setFontFamily(headerStyle, "Consolas");
        StyleConstants.setFontSize(headerStyle, 12);
        StyleConstants.setBold(headerStyle, true);

        try {
            String[] lines = requestText.split("\n");
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                if (i == 0 || line.contains(":")) {
                    doc.insertString(doc.getLength(), line + "\n", headerStyle);
                } else {
                    doc.insertString(doc.getLength(), line + "\n", defaultStyle);
                }
            }
        } catch (BadLocationException e) {}

        requestPane.setCaretPosition(0);
    }

    /**
     * Update the response pane with evidence highlighting (optimized with pre-prepared text)
     */
    private void updateResponsePane(String responseText) {
        StyledDocument doc = responsePane.getStyledDocument();

        // Clear existing content
        try {
            doc.remove(0, doc.getLength());
        } catch (BadLocationException e) {}

        // Limit response size for performance (large responses slow down highlighting)
        if (responseText.length() > 100000) {
            responseText = responseText.substring(0, 100000) + "\n\n" + I18n.t("findings.responseTruncated");
        }

        // Styles (theme-adaptive ink)
        Style defaultStyle = doc.addStyle("default", null);
        StyleConstants.setForeground(defaultStyle, ColorScheme.CONSOLE_FG);
        StyleConstants.setFontFamily(defaultStyle, "Consolas");
        StyleConstants.setFontSize(defaultStyle, 12);

        Style highlightStyle = doc.addStyle("highlight", null);
        StyleConstants.setBackground(highlightStyle, new Color(255, 235, 59)); // Yellow
        StyleConstants.setForeground(highlightStyle, new Color(0, 0, 0));
        StyleConstants.setFontFamily(highlightStyle, "Consolas");
        StyleConstants.setFontSize(highlightStyle, 12);
        StyleConstants.setBold(highlightStyle, true);

        Style sensitiveStyle = doc.addStyle("sensitive", null);
        StyleConstants.setBackground(sensitiveStyle, new Color(255, 152, 0)); // Orange
        StyleConstants.setForeground(sensitiveStyle, Color.WHITE);
        StyleConstants.setFontFamily(sensitiveStyle, "Consolas");
        StyleConstants.setFontSize(sensitiveStyle, 12);
        StyleConstants.setBold(sensitiveStyle, true);

        Style errorStyle = doc.addStyle("error", null);
        StyleConstants.setBackground(errorStyle, new Color(244, 67, 54)); // Red
        StyleConstants.setForeground(errorStyle, Color.WHITE);
        StyleConstants.setFontFamily(errorStyle, "Consolas");
        StyleConstants.setFontSize(errorStyle, 12);
        StyleConstants.setBold(errorStyle, true);

        // Get evidence patterns to highlight
        List<String> evidencePatterns = getEvidencePatterns();

        try {
            // Highlight response with evidence
            highlightTextWithPatterns(doc, responseText, evidencePatterns, defaultStyle, highlightStyle, sensitiveStyle, errorStyle);
        } catch (BadLocationException e) {}

        responsePane.setCaretPosition(0);
    }

    /**
     * Get evidence patterns from finding
     */
    private List<String> getEvidencePatterns() {
        List<String> patterns = new ArrayList<>();

        if (selectedFinding == null) return patterns;

        // Add evidence text as pattern
        if (selectedFinding.getEvidence() != null && !selectedFinding.getEvidence().isEmpty()) {
            String evidence = FindingHtmlRenderer.stripHtmlTags(selectedFinding.getEvidence());
            // Split evidence into searchable patterns
            String[] words = evidence.split("\\s+");
            for (String word : words) {
                if (word.length() > 3) {
                    patterns.add(word.trim());
                }
            }
        }

        // Add common patterns based on vulnerability type
        String vulnType = selectedFinding.getType().toLowerCase();

        if (vulnType.contains("sql")) {
            patterns.add("SQL syntax");
            patterns.add("mysql");
            patterns.add("ORA-");
            patterns.add("syntax error");
            patterns.add("SQLSTATE");
        } else if (vulnType.contains("xss")) {
            patterns.add("<script");
            patterns.add("javascript:");
            patterns.add("onerror");
            patterns.add("onload");
            patterns.add("alert(");
        } else if (vulnType.contains("information") || vulnType.contains("disclosure")) {
            patterns.add("password");
            patterns.add("secret");
            patterns.add("api_key");
            patterns.add("apikey");
            patterns.add("token");
            patterns.add("Authorization");
        } else if (vulnType.contains("cors")) {
            patterns.add("Access-Control-Allow-Origin");
            patterns.add("Access-Control-Allow-Credentials");
        }

        return patterns;
    }

    /**
     * Highlight text with patterns
     */
    private void highlightTextWithPatterns(StyledDocument doc, String text, List<String> patterns,
                                           Style defaultStyle, Style highlightStyle,
                                           Style sensitiveStyle, Style errorStyle) throws BadLocationException {
        // Build a combined pattern for sensitive data
        String sensitivePattern = "(?i)(password|secret|api.?key|token|authorization|bearer|credential)";
        String errorPattern = "(?i)(error|exception|stacktrace|warning|fatal|denied)";

        int lastEnd = 0;
        String lowerText = text.toLowerCase();

        // First pass - add all text with default style
        doc.insertString(doc.getLength(), text, defaultStyle);

        // Second pass - highlight patterns
        for (String pattern : patterns) {
            if (pattern == null || pattern.isEmpty()) continue;

            String lowerPattern = pattern.toLowerCase();
            int index = 0;

            while ((index = lowerText.indexOf(lowerPattern, index)) != -1) {
                // Apply highlight style
                doc.setCharacterAttributes(index, pattern.length(), highlightStyle, true);
                index += pattern.length();
            }
        }

        // Highlight sensitive data
        Pattern sensitive = Pattern.compile(sensitivePattern);
        Matcher sensitiveMatcher = sensitive.matcher(text);
        while (sensitiveMatcher.find()) {
            doc.setCharacterAttributes(sensitiveMatcher.start(), sensitiveMatcher.end() - sensitiveMatcher.start(), sensitiveStyle, true);
        }

        // Highlight errors
        Pattern error = Pattern.compile(errorPattern);
        Matcher errorMatcher = error.matcher(text);
        while (errorMatcher.find()) {
            doc.setCharacterAttributes(errorMatcher.start(), errorMatcher.end() - errorMatcher.start(), errorStyle, true);
        }
    }

    /**
     * Create a styled button
     */
    private JButton createStyledButton(String text, Color bgColor) {
        JButton button = new JButton(text);
        button.setBackground(bgColor);
        button.setForeground(Color.WHITE);
        button.setFont(new Font("Segoe UI", Font.BOLD, 11));
        button.setFocusPainted(false);
        button.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 12));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        return button;
    }

    /**
     * Create a small styled button
     */
    private JButton createSmallButton(String text, Color bgColor) {
        JButton button = new JButton(text);
        button.setBackground(bgColor);
        button.setForeground(Color.WHITE);
        button.setFont(new Font("Segoe UI", Font.PLAIN, 10));
        button.setFocusPainted(false);
        button.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        return button;
    }

    /**
     * Get severity icon
     */
    private String getSeverityIcon(String severity) {
        switch (severity.toLowerCase()) {
            case "critical": return "\u26A0"; // Warning
            case "high": return "\u2757"; // Exclamation
            case "medium": return "\u26AB"; // Circle
            case "low": return "\u2139"; // Info
            default: return "\u2022"; // Bullet
        }
    }

    /** Make &lt;a href&gt; links inside an HTML pane open in the user's default browser. */
    private void installLinkOpener(JTextPane pane) {
        pane.addHyperlinkListener(e -> {
            if (e.getEventType() == javax.swing.event.HyperlinkEvent.EventType.ACTIVATED && e.getURL() != null) {
                try {
                    if (java.awt.Desktop.isDesktopSupported()
                            && java.awt.Desktop.getDesktop().isSupported(java.awt.Desktop.Action.BROWSE)) {
                        java.awt.Desktop.getDesktop().browse(e.getURL().toURI());
                    }
                } catch (Exception ignored) { /* opening a reference link is best-effort */ }
            }
        });
    }


    /**
     * Add a finding to the table
     */
    public void addFinding(Finding finding) {
        addFinding(finding, null);
    }

    /**
     * Add a finding with associated request/response (optimized for performance)
     */
    public void addFinding(Finding finding, IHttpRequestResponse requestResponse) {
        if (finding == null) return;
        // Faz 0: AI-flagged false positives are not shown in the Findings panel (still persisted in DB).
        if (finding.isFalsePositive()) return;

        // Generate hash for duplicate detection: URL + Type + Severity
        String url = finding.getAffectedUrl();
        if ((url == null || url.isEmpty()) && requestResponse != null) {
            try {
                url = helpers.analyzeRequest(requestResponse).getUrl().toString();
            } catch (Exception e) {
                url = "N/A";
            }
        }

        // Site-wide config/transport/session issues (headers, version/tech disclosure, transport,
        // misconfig, a token carried in the URL) are listed ONCE PER HOST: the same issue on a
        // different path of the same domain is the same finding, but a different sub-domain or
        // domain is reported separately. Per-endpoint issues (IDOR, injection, access control)
        // stay once per URL.
        //
        // Host-scoped key deliberately EXCLUDES severity (the AI can score the same banner Low on one
        // request and Medium on the next — that must NOT split it) and uses a volatile-insensitive
        // evidence SIGNATURE instead of the raw text (so a per-request token/timestamp in the evidence
        // doesn't create a fresh row). Per-URL key strips volatile query params (socket.io t/sid, cache
        // busters) so the same endpoint polled many times collapses too.
        String findingHash = Finding.isHostScopedType(finding.getType())
                ? "SITEWIDE|" + Finding.hostOf(url) + "|" + finding.getType()
                        + "|" + Finding.evidenceSignature(finding.getEvidence())
                : Finding.normalizeUrlForDedup(url) + "|" + finding.getType() + "|" + finding.getEffectiveSeverity();

        // Check for duplicate (fast O(1) lookup)
        synchronized (findingHashes) {
            if (findingHashes.contains(findingHash)) {
                // Duplicate found - skip adding
                return;
            }
            // Add to hash set to track
            findingHashes.add(findingHash);
        }

        // Add to lists (synchronized for thread safety)
        synchronized (findings) {
            findings.add(finding);
            requestResponses.add(requestResponse);
        }

        // Prepare row data (do this before EDT to reduce EDT work)
        final String findingUrl = (url != null && !url.isEmpty()) ? url : "N/A";
        final Object[] row = {
            "",                              // # column — the renderer fills it with the row number
            finding.getType(),
            finding.getEffectiveSeverity(),
            String.format("%.1f", finding.getEffectiveCvss()),
            finding.getEffectivePriority(),
            String.format("%.0f%%", finding.getConfidence() * 100),
            findingUrl                       // full URL (truncation is visual only; hover shows all)
        };

        // Update UI on EDT (batched if in bulk mode)
        SwingUtilities.invokeLater(() -> {
            tableModel.addRow(row);

            // Only auto-select if not in bulk mode
            if (!bulkAddMode) {
                int newRow = tableModel.getRowCount() - 1;
                if (newRow >= 0) {
                    findingsTable.setRowSelectionInterval(newRow, newRow);
                }
            }
        });

        // Mark for update (will be processed by timer)
        needsUpdate = true;
    }

    /**
     * Get severity icon image
     */
    private Icon getSeverityIconImage(String severity) {
        Color color;
        switch (severity.toLowerCase()) {
            case "critical": color = new Color(183, 28, 28); break;
            case "high": color = new Color(211, 47, 47); break;
            case "medium": color = new Color(255, 152, 0); break;
            case "low": color = new Color(76, 175, 80); break;
            default: color = ColorScheme.TEXT_SECONDARY;
        }
        return Icons.getCircleIcon(12, color);
    }

    /**
     * Update the findings count label (optimized with direct reference)
     */
    private void updateCountLabel() {
        if (countLabel != null) {
            int count = findings.size();
            countLabel.setText(I18n.t("findings.count", count));
        }
    }

    /**
     * Add multiple findings (optimized - uses bulk mode)
     */
    public void addFindings(List<Finding> findingsList) {
        if (findingsList == null || findingsList.isEmpty()) return;

        // Enable bulk mode for better performance
        setBulkAddMode(true);

        try {
            for (Finding finding : findingsList) {
                addFinding(finding);
            }
        } finally {
            // Disable bulk mode and force UI update
            setBulkAddMode(false);
            SwingUtilities.invokeLater(() -> updateCountLabel());
        }
    }

    /**
     * Set bulk add mode (disables auto-selection and batches updates)
     */
    public void setBulkAddMode(boolean enabled) {
        this.bulkAddMode = enabled;
    }
    
    /**
     * Clear all findings (optimized)
     */
    public void clearFindings() {
        synchronized (findings) {
            findings.clear();
            requestResponses.clear();
        }
        synchronized (findingHashes) {
            findingHashes.clear();
        }
        SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            updateCountLabel();
        });
    }

    /**
     * Cleanup resources (call when panel is removed)
     */
    public void cleanup() {
        if (updateTimer != null) {
            updateTimer.cancel();
            updateTimer = null;
        }
    }
    
    /**
     * Get all findings
     */
    public List<Finding> getFindings() {
        return new ArrayList<>(findings);
    }
    
    /**
     * Show finding details dialog with enhanced format and Request/Response tabs
     */
    private void showFindingDetailsDialog(Finding finding, IHttpRequestResponse requestResponse) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this),
                                     I18n.t("findings.dialog.details.title") + " - " + finding.getType(), true);
        dialog.setSize(1000, 750);
        dialog.setLocationRelativeTo(this);

        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBackground(ColorScheme.BG_CARD);
        contentPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        // Header with severity badge
        JPanel headerPanel = new JPanel(new BorderLayout(10, 10));
        headerPanel.setBackground(ColorScheme.BG_CARD);
        headerPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

        JLabel titleLabel = new JLabel(finding.getType());
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        titleLabel.setForeground(ColorScheme.PRIMARY_BLUE);
        titleLabel.setIcon(Icons.getShieldIcon(24, ColorScheme.getSeverityColor(finding.getSeverity())));

        JPanel badgePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        badgePanel.setBackground(ColorScheme.BG_CARD);

        JLabel severityBadge = createBadge(finding.getSeverity().toUpperCase(), ColorScheme.getSeverityColor(finding.getSeverity()));
        JLabel priorityBadge = createBadge(finding.getPriority(), new Color(108, 117, 125));
        JLabel cvssBadge = createBadge("CVSS: " + String.format("%.1f", finding.getCvssScore()), new Color(23, 162, 184));

        badgePanel.add(severityBadge);
        badgePanel.add(priorityBadge);
        badgePanel.add(cvssBadge);

        headerPanel.add(titleLabel, BorderLayout.WEST);
        headerPanel.add(badgePanel, BorderLayout.EAST);
        contentPanel.add(headerPanel, BorderLayout.NORTH);

        // Main tabbed pane
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(new Font("Segoe UI", Font.PLAIN, 12));

        // Tab 1: Vulnerability Details
        JPanel detailsTab = createDetailsTab(finding);
        tabbedPane.addTab(I18n.t("findings.tab.details"), Icons.getInfoIcon(14), detailsTab);

        // Tab 2: Request
        JPanel requestTab = createRequestTab(finding, requestResponse);
        tabbedPane.addTab(I18n.t("findings.tab.request"), Icons.getSendIcon(14), requestTab);

        // Tab 3: Response with Highlighting
        JPanel responseTab = createResponseTab(finding, requestResponse);
        tabbedPane.addTab(I18n.t("findings.tab.responseHighlighted"), Icons.getResponseIcon(14), responseTab);

        // Tab 4: References & Resources
        JPanel referencesTab = createReferencesTab(finding);
        tabbedPane.addTab(I18n.t("findings.tab.references"), Icons.getLinkIcon(14), referencesTab);

        contentPanel.add(tabbedPane, BorderLayout.CENTER);

        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        buttonPanel.setBackground(ColorScheme.BG_CARD);

        JButton repeaterBtn = I18nUI.text(createStyledButton("Send to Repeater", ColorScheme.PRIMARY_BLUE), "findings.btn.sendToRepeater");
        repeaterBtn.addActionListener(e -> {
            sendFindingToRepeater(finding, requestResponse, dialog);
        });
        buttonPanel.add(repeaterBtn);

        JButton pocBtn = I18nUI.text(createStyledButton("Generate PoC", ColorScheme.WARNING_ORANGE), "findings.btn.generatePoC");
        pocBtn.addActionListener(e -> {
            generatePoCForFinding(finding, requestResponse, dialog);
        });
        buttonPanel.add(pocBtn);

        JButton copyBtn = I18nUI.text(createStyledButton("Copy Report", ColorScheme.SUCCESS_GREEN), "findings.btn.copyReport");
        copyBtn.addActionListener(e -> {
            String report = generateTextReport(finding);
            java.awt.datatransfer.StringSelection selection =
                new java.awt.datatransfer.StringSelection(report);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            JOptionPane.showMessageDialog(dialog, I18n.t("findings.msg.reportCopied"), I18n.t("findings.title.success"), JOptionPane.INFORMATION_MESSAGE);
        });
        buttonPanel.add(copyBtn);

        JButton closeBtn = I18nUI.text(createStyledButton("Close", new Color(108, 117, 125)), "findings.btn.close");
        closeBtn.addActionListener(e -> dialog.dispose());
        buttonPanel.add(closeBtn);

        contentPanel.add(buttonPanel, BorderLayout.SOUTH);

        dialog.add(contentPanel);
        dialog.setVisible(true);
    }

    /**
     * Create badge label
     */
    private JLabel createBadge(String text, Color color) {
        JLabel badge = new JLabel(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(color);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        badge.setForeground(Color.WHITE);
        badge.setFont(new Font("Segoe UI", Font.BOLD, 11));
        badge.setHorizontalAlignment(SwingConstants.CENTER);
        badge.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));
        badge.setOpaque(false);
        return badge;
    }

    /**
     * Create details tab
     */
    private JPanel createDetailsTab(Finding finding) {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(ColorScheme.BG_LIGHT);
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JTextPane detailsPane = new JTextPane();
        detailsPane.setEditable(false);
        detailsPane.setContentType("text/html");
        detailsPane.setBackground(Color.WHITE);
        detailsPane.setBorder(BorderFactory.createEmptyBorder());
        installLinkOpener(detailsPane);
        // Same professional "report card" layout as the inline detail pane.
        detailsPane.setText(FindingHtmlRenderer.buildFindingDetailHtml(finding, true));
        detailsPane.setCaretPosition(0);

        JScrollPane scrollPane = new JScrollPane(detailsPane);
        scrollPane.setBorder(BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT));
        scrollPane.getViewport().setBackground(Color.WHITE);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Create request tab
     */
    private JPanel createRequestTab(Finding finding, IHttpRequestResponse requestResponse) {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(new Color(45, 45, 45));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTextPane requestPane = new JTextPane();
        requestPane.setEditable(false);
        requestPane.setFont(new Font("Consolas", Font.PLAIN, 12));
        requestPane.setBackground(new Color(45, 45, 45));

        String requestText = "";
        if (finding.getHttpRequest() != null && !finding.getHttpRequest().isEmpty()) {
            requestText = finding.getHttpRequest();
        } else if (requestResponse != null && requestResponse.getRequest() != null) {
            requestText = new String(requestResponse.getRequest());
        } else {
            requestText = I18n.t("findings.noRequestData");
        }

        // Apply syntax highlighting
        applySyntaxHighlighting(requestPane, requestText, true);

        JScrollPane scrollPane = new JScrollPane(requestPane);
        scrollPane.setBorder(null);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Create response tab with evidence highlighting
     */
    private JPanel createResponseTab(Finding finding, IHttpRequestResponse requestResponse) {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(new Color(45, 45, 45));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Legend panel
        JPanel legendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        legendPanel.setBackground(new Color(60, 60, 60));
        legendPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        legendPanel.add(createLegendItem(I18n.t("findings.legend.evidence"), new Color(255, 235, 59)));
        legendPanel.add(createLegendItem(I18n.t("findings.legend.sensitive"), new Color(255, 152, 0)));
        legendPanel.add(createLegendItem(I18n.t("findings.legend.error"), new Color(244, 67, 54)));

        panel.add(legendPanel, BorderLayout.NORTH);

        JTextPane responsePane = new JTextPane();
        responsePane.setEditable(false);
        responsePane.setFont(new Font("Consolas", Font.PLAIN, 12));
        responsePane.setBackground(new Color(45, 45, 45));

        String responseText = "";
        if (finding.getHttpResponse() != null && !finding.getHttpResponse().isEmpty()) {
            responseText = finding.getHttpResponse();
        } else if (requestResponse != null && requestResponse.getResponse() != null) {
            responseText = new String(requestResponse.getResponse());
        } else {
            responseText = I18n.t("findings.noResponseData");
        }

        // Apply highlighting with evidence patterns
        applyResponseHighlighting(responsePane, responseText, finding);

        JScrollPane scrollPane = new JScrollPane(responsePane);
        scrollPane.setBorder(null);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Create legend item
     */
    private JPanel createLegendItem(String text, Color color) {
        JPanel item = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 0));
        item.setOpaque(false);

        JPanel colorBox = new JPanel();
        colorBox.setBackground(color);
        colorBox.setPreferredSize(new Dimension(12, 12));
        colorBox.setBorder(BorderFactory.createLineBorder(Color.WHITE));

        JLabel label = new JLabel(text);
        label.setForeground(Color.WHITE);
        label.setFont(new Font("Segoe UI", Font.PLAIN, 10));

        item.add(colorBox);
        item.add(label);
        return item;
    }

    /**
     * Create references tab
     */
    private JPanel createReferencesTab(Finding finding) {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(ColorScheme.BG_LIGHT);
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JTextPane refsPane = new JTextPane();
        refsPane.setEditable(false);
        refsPane.setContentType("text/html");
        refsPane.setBackground(Color.WHITE);
        refsPane.setBorder(BorderFactory.createEmptyBorder());
        installLinkOpener(refsPane);

        StringBuilder html = new StringBuilder();
        html.append("<html><body style='font-family:\"Segoe UI\",sans-serif; font-size:12px; color:")
            .append(FindingHtmlRenderer.INK).append("; background-color:#ffffff; margin:0; padding:14px 16px;'>");

        html.append("<div style='color:").append(FindingHtmlRenderer.INK_SOFT).append("; font-weight:bold; font-size:13px; margin-bottom:8px;'>")
            .append(I18n.t("findings.heading.securityReferences")).append("</div>");

        if (finding.getReferences() != null && !finding.getReferences().isEmpty()) {
            html.append("<ul style='margin:0; padding-left:18px;'>");
            for (String ref : finding.getReferences()) {
                String safe = FindingHtmlRenderer.escapeHtml(ref);
                html.append("<li style='margin-bottom:6px;'><a href='").append(safe).append("' style='color:#1f6feb;'>").append(safe).append("</a></li>");
            }
            html.append("</ul>");
        } else {
            html.append("<p style='color:").append(FindingHtmlRenderer.LABEL_GREY).append(";'>").append(I18n.t("findings.noReferences")).append("</p>");
        }

        // Add standard resources based on CWE
        if (finding.getCweId() != null && !finding.getCweId().isEmpty()) {
            html.append("<div style='color:").append(FindingHtmlRenderer.INK_SOFT).append("; font-weight:bold; font-size:13px; margin:18px 0 8px 0;'>")
                .append(I18n.t("findings.heading.relatedResources")).append("</div>");
            html.append("<ul style='margin:0; padding-left:18px;'>");
            html.append("<li style='margin-bottom:6px;'><a href='https://cwe.mitre.org/data/definitions/").append(finding.getCweId().replace("CWE-", "")).append(".html' style='color:#1f6feb;'>MITRE CWE Database</a></li>");
            html.append("<li style='margin-bottom:6px;'><a href='https://owasp.org/www-project-web-security-testing-guide/' style='color:#1f6feb;'>OWASP Testing Guide</a></li>");
            html.append("<li style='margin-bottom:6px;'><a href='https://portswigger.net/web-security' style='color:#1f6feb;'>PortSwigger Web Security Academy</a></li>");
            html.append("</ul>");
        }

        html.append("</body></html>");
        refsPane.setText(html.toString());
        refsPane.setCaretPosition(0);

        JScrollPane scrollPane = new JScrollPane(refsPane);
        scrollPane.setBorder(BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT));
        scrollPane.getViewport().setBackground(Color.WHITE);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Apply syntax highlighting to request/response
     */
    private void applySyntaxHighlighting(JTextPane pane, String text, boolean isRequest) {
        StyledDocument doc = pane.getStyledDocument();

        Style defaultStyle = doc.addStyle("default", null);
        StyleConstants.setForeground(defaultStyle, new Color(212, 212, 212));
        StyleConstants.setFontFamily(defaultStyle, "Consolas");
        StyleConstants.setFontSize(defaultStyle, 12);

        Style headerStyle = doc.addStyle("header", null);
        StyleConstants.setForeground(headerStyle, new Color(86, 156, 214));
        StyleConstants.setFontFamily(headerStyle, "Consolas");
        StyleConstants.setFontSize(headerStyle, 12);
        StyleConstants.setBold(headerStyle, true);

        Style valueStyle = doc.addStyle("value", null);
        StyleConstants.setForeground(valueStyle, new Color(206, 145, 120));
        StyleConstants.setFontFamily(valueStyle, "Consolas");
        StyleConstants.setFontSize(valueStyle, 12);

        try {
            String[] lines = text.split("\n");
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                if (i == 0 || (line.contains(":") && !line.startsWith(" ") && !line.startsWith("\t"))) {
                    // Header line
                    int colonIndex = line.indexOf(":");
                    if (colonIndex > 0 && i > 0) {
                        doc.insertString(doc.getLength(), line.substring(0, colonIndex + 1), headerStyle);
                        doc.insertString(doc.getLength(), line.substring(colonIndex + 1) + "\n", valueStyle);
                    } else {
                        doc.insertString(doc.getLength(), line + "\n", headerStyle);
                    }
                } else {
                    doc.insertString(doc.getLength(), line + "\n", defaultStyle);
                }
            }
        } catch (BadLocationException e) {}
    }

    /**
     * Apply response highlighting with evidence patterns
     */
    private void applyResponseHighlighting(JTextPane pane, String text, Finding finding) {
        StyledDocument doc = pane.getStyledDocument();

        Style defaultStyle = doc.addStyle("default", null);
        StyleConstants.setForeground(defaultStyle, new Color(212, 212, 212));
        StyleConstants.setFontFamily(defaultStyle, "Consolas");
        StyleConstants.setFontSize(defaultStyle, 12);

        try {
            // First, insert all text
            doc.insertString(0, text, defaultStyle);

            // Define highlight styles
            Style evidenceStyle = doc.addStyle("evidence", null);
            StyleConstants.setBackground(evidenceStyle, new Color(255, 235, 59));
            StyleConstants.setForeground(evidenceStyle, Color.BLACK);
            StyleConstants.setBold(evidenceStyle, true);

            Style sensitiveStyle = doc.addStyle("sensitive", null);
            StyleConstants.setBackground(sensitiveStyle, new Color(255, 152, 0));
            StyleConstants.setForeground(sensitiveStyle, Color.WHITE);
            StyleConstants.setBold(sensitiveStyle, true);

            Style errorStyle = doc.addStyle("error", null);
            StyleConstants.setBackground(errorStyle, new Color(244, 67, 54));
            StyleConstants.setForeground(errorStyle, Color.WHITE);
            StyleConstants.setBold(errorStyle, true);

            // Highlight evidence
            if (finding.getEvidence() != null && !finding.getEvidence().isEmpty()) {
                String evidence = FindingHtmlRenderer.stripHtmlTags(finding.getEvidence());
                String[] words = evidence.split("\\s+");
                for (String word : words) {
                    if (word.length() > 4) {
                        highlightPattern(doc, text, word, evidenceStyle);
                    }
                }
            }

            // Highlight sensitive patterns
            String[] sensitivePatterns = {"password", "secret", "api_key", "apikey", "token", "authorization", "bearer", "credential"};
            for (String pattern : sensitivePatterns) {
                highlightPattern(doc, text, pattern, sensitiveStyle);
            }

            // Highlight error patterns
            String[] errorPatterns = {"error", "exception", "warning", "fatal", "denied", "failed"};
            for (String pattern : errorPatterns) {
                highlightPattern(doc, text, pattern, errorStyle);
            }

        } catch (BadLocationException e) {}
    }

    /**
     * Highlight pattern in document
     */
    private void highlightPattern(StyledDocument doc, String text, String pattern, Style style) {
        String lowerText = text.toLowerCase();
        String lowerPattern = pattern.toLowerCase();
        int index = 0;

        while ((index = lowerText.indexOf(lowerPattern, index)) != -1) {
            doc.setCharacterAttributes(index, pattern.length(), style, false);
            index += pattern.length();
        }
    }

    /**
     * Generate text report for clipboard
     */
    private String generateTextReport(Finding finding) {
        StringBuilder report = new StringBuilder();
        report.append("═══════════════════════════════════════════════════════════════\n");
        report.append("  VULNERABILITY REPORT\n");
        report.append("═══════════════════════════════════════════════════════════════\n\n");

        report.append(String.format("Type: %s\n", finding.getType()));
        report.append(String.format("Severity: %s\n", finding.getSeverity().toUpperCase()));
        report.append(String.format("CVSS Score: %.1f\n", finding.getCvssScore()));
        report.append(String.format("Priority: %s\n", finding.getPriority()));
        report.append(String.format("Confidence: %.0f%%\n", finding.getConfidence() * 100));
        if (finding.getCweId() != null) report.append(String.format("CWE: %s\n", finding.getCweId()));
        if (finding.getOwaspCategory() != null) report.append(String.format("OWASP: %s\n", finding.getOwaspCategory()));
        report.append("\n");

        if (finding.getAffectedUrl() != null && !finding.getAffectedUrl().isEmpty()) {
            report.append("Affected URL:\n").append(finding.getAffectedUrl()).append("\n\n");
        }

        report.append("Description:\n").append(FindingHtmlRenderer.stripHtmlTags(finding.getDescription())).append("\n\n");

        if (finding.getEvidence() != null && !finding.getEvidence().isEmpty()) {
            report.append("Evidence:\n").append(FindingHtmlRenderer.stripHtmlTags(finding.getEvidence())).append("\n\n");
        }

        if (finding.getRemediation() != null && !finding.getRemediation().isEmpty()) {
            report.append("Remediation:\n").append(FindingHtmlRenderer.stripHtmlTags(finding.getRemediation())).append("\n\n");
        }

        if (finding.getReferences() != null && !finding.getReferences().isEmpty()) {
            report.append("References:\n");
            for (String ref : finding.getReferences()) {
                report.append("  - ").append(ref).append("\n");
            }
        }

        report.append("\n═══════════════════════════════════════════════════════════════\n");
        report.append("  Generated by AppSecHunter\n");
        report.append("═══════════════════════════════════════════════════════════════\n");

        return report.toString();
    }

    /**
     * Send finding to repeater from dialog
     */
    private void sendFindingToRepeater(Finding finding, IHttpRequestResponse requestResponse, JDialog dialog) {
        try {
            String requestData = finding.getHttpRequest();
            if ((requestData == null || requestData.isEmpty()) && requestResponse != null && requestResponse.getRequest() != null) {
                requestData = new String(requestResponse.getRequest());
            }

            if (requestData == null || requestData.isEmpty()) {
                JOptionPane.showMessageDialog(dialog, I18n.t("findings.noRequestData"), I18n.t("findings.title.error"), JOptionPane.ERROR_MESSAGE);
                return;
            }

            IHttpService httpService = getHttpService(finding, requestResponse);
            if (httpService == null) {
                JOptionPane.showMessageDialog(dialog, I18n.t("findings.msg.cannotDetermineHost"), I18n.t("findings.title.error"), JOptionPane.ERROR_MESSAGE);
                return;
            }

            callbacks.sendToRepeater(httpService.getHost(), httpService.getPort(),
                httpService.getProtocol().equals("https"), requestData.getBytes(), finding.getType());

            JOptionPane.showMessageDialog(dialog, I18n.t("findings.msg.sentToRepeater"), I18n.t("findings.title.success"), JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(dialog, I18n.t("findings.msg.errorPrefix") + " " + e.getMessage(), I18n.t("findings.title.error"), JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Generate PoC for finding from dialog
     */
    private void generatePoCForFinding(Finding finding, IHttpRequestResponse requestResponse, JDialog dialog) {
        try {
            String poc = PoCGenerator.generatePoC(finding, requestResponse, helpers);
            showPoCDialog(finding, requestResponse, poc);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(dialog, I18n.t("findings.msg.pocError") + " " + e.getMessage(), I18n.t("findings.title.error"), JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Get HTTP service from finding or request/response
     */
    private IHttpService getHttpService(Finding finding, IHttpRequestResponse requestResponse) {
        if (requestResponse != null && requestResponse.getHttpService() != null) {
            return requestResponse.getHttpService();
        }

        if (finding.getAffectedUrl() != null && !finding.getAffectedUrl().isEmpty()) {
            try {
                java.net.URL url = new java.net.URL(finding.getAffectedUrl());
                final String protocol = url.getProtocol();
                final String host = url.getHost();
                final int port = url.getPort() == -1 ? (protocol.equals("https") ? 443 : 80) : url.getPort();

                return new IHttpService() {
                    @Override public String getHost() { return host; }
                    @Override public int getPort() { return port; }
                    @Override public String getProtocol() { return protocol; }
                };
            } catch (Exception e) {
                return null;
            }
        }

        return null;
    }

    /**
     * Create context menu for findings table
     */
    private JPopupMenu createContextMenu(int row) {
        JPopupMenu popup = new JPopupMenu();
        popup.setBackground(ColorScheme.BG_CARD);

        JMenuItem sendToRepeaterItem = new JMenuItem(I18n.t("findings.menu.sendToRepeater"));
        sendToRepeaterItem.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        sendToRepeaterItem.addActionListener(e -> sendToRepeater(row));
        popup.add(sendToRepeaterItem);

        JMenuItem generatePoCItem = new JMenuItem(I18n.t("findings.menu.generatePoC"));
        generatePoCItem.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        generatePoCItem.addActionListener(e -> generatePoC(row));
        popup.add(generatePoCItem);

        popup.addSeparator();

        JMenuItem viewDetailsItem = new JMenuItem(I18n.t("findings.menu.viewDetails"));
        viewDetailsItem.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        viewDetailsItem.addActionListener(e -> {
            if (row >= 0 && row < findings.size()) {
                IHttpRequestResponse reqRes = (row < requestResponses.size()) ? requestResponses.get(row) : null;
                showFindingDetailsDialog(findings.get(row), reqRes);
            }
        });
        popup.add(viewDetailsItem);

        popup.addSeparator();

        JMenuItem markFPItem = new JMenuItem(I18n.t("findings.menu.markFalsePositive"));
        markFPItem.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        markFPItem.addActionListener(e -> markAsFalsePositive());
        popup.add(markFPItem);

        return popup;
    }

    /**
     * Generate PoC for finding (with loading dialog)
     */
    private void generatePoC(int row) {
        if (row < 0 || row >= findings.size()) {
            JOptionPane.showMessageDialog(this,
                I18n.t("findings.msg.noFindingSelected"),
                I18n.t("findings.title.cannotGeneratePoC"),
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        Finding finding = findings.get(row);
        IHttpRequestResponse requestResponse = (row < requestResponses.size()) ? requestResponses.get(row) : null;

        // Show loading dialog
        JDialog loadingDialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), I18n.t("findings.dialog.generatingPoC.title"), true);
        loadingDialog.setSize(300, 100);
        loadingDialog.setLocationRelativeTo(this);
        loadingDialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);

        JPanel loadingPanel = new JPanel(new BorderLayout(10, 10));
        loadingPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        loadingPanel.add(new JLabel(I18n.t("findings.msg.generatingPoC")), BorderLayout.CENTER);
        loadingDialog.add(loadingPanel);

        // Generate PoC in background thread
        new Thread(() -> {
            try {
                String poc = PoCGenerator.generatePoC(finding, requestResponse, helpers);

                SwingUtilities.invokeLater(() -> {
                    loadingDialog.dispose();
                    showPoCDialog(finding, requestResponse, poc);
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    loadingDialog.dispose();
                    JOptionPane.showMessageDialog(FindingsPanel.this,
                        I18n.t("findings.msg.pocFailed") + " " + e.getMessage(),
                        I18n.t("findings.title.error"),
                        JOptionPane.ERROR_MESSAGE);
                });
            }
        }).start();

        loadingDialog.setVisible(true);
    }

    /**
     * Show PoC dialog with Send to Repeater/Intruder buttons
     */
    private void showPoCDialog(Finding finding, IHttpRequestResponse requestResponse, String poc) {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this), I18n.t("findings.dialog.poc.title") + " " + finding.getType(), false);
        dialog.setSize(900, 650);
        dialog.setLocationRelativeTo(this);

        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
        contentPanel.setBackground(ColorScheme.BG_CARD);
        contentPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JLabel titleLabel = new JLabel(I18n.t("findings.poc.heading") + " - " + finding.getType());
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        titleLabel.setForeground(ColorScheme.PRIMARY_BLUE);
        titleLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

        JTextArea pocArea = new JTextArea(poc);
        pocArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        pocArea.setEditable(true);
        pocArea.setLineWrap(true);
        pocArea.setWrapStyleWord(true);
        pocArea.setBackground(ColorScheme.BG_LIGHT);
        pocArea.setForeground(ColorScheme.TEXT_DARK);
        pocArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        pocArea.setCaretPosition(0);

        JScrollPane scrollPane = new JScrollPane(pocArea);
        scrollPane.setBorder(BorderFactory.createLineBorder(ColorScheme.BORDER_LIGHT));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        buttonPanel.setBackground(ColorScheme.BG_CARD);

        // Send to Repeater button
        if (finding.getHttpRequest() != null && !finding.getHttpRequest().isEmpty()) {
            JButton repeaterButton = I18nUI.text(new JButton("📤 Send to Repeater"), "findings.menu.sendToRepeater");
            repeaterButton.setFont(new Font("Segoe UI", Font.BOLD, 12));
            repeaterButton.setBackground(ColorScheme.PRIMARY_BLUE);
            repeaterButton.setForeground(Color.WHITE);
            repeaterButton.setFocusPainted(false);
            repeaterButton.setBorder(BorderFactory.createEmptyBorder(8, 15, 8, 15));
            repeaterButton.addActionListener(e -> {
                try {
                    byte[] request = finding.getHttpRequest().getBytes();

                    // Get HTTP service - either from requestResponse or parse from URL
                    IHttpService httpService = null;
                    if (requestResponse != null) {
                        httpService = requestResponse.getHttpService();
                    } else if (finding.getAffectedUrl() != null && !finding.getAffectedUrl().isEmpty()) {
                        // Parse URL to create HTTP service
                        java.net.URL url = new java.net.URL(finding.getAffectedUrl());
                        String protocol = url.getProtocol();
                        String host = url.getHost();
                        int port = url.getPort();
                        if (port == -1) {
                            port = protocol.equals("https") ? 443 : 80;
                        }

                        final String finalProtocol = protocol;
                        final String finalHost = host;
                        final int finalPort = port;

                        httpService = new IHttpService() {
                            @Override
                            public String getHost() { return finalHost; }

                            @Override
                            public int getPort() { return finalPort; }

                            @Override
                            public String getProtocol() { return finalProtocol; }
                        };
                    }

                    if (httpService == null) {
                        throw new Exception("Cannot determine target host/port");
                    }

                    callbacks.sendToRepeater(
                        httpService.getHost(),
                        httpService.getPort(),
                        httpService.getProtocol().equals("https"),
                        request,
                        finding.getType()
                    );
                    JOptionPane.showMessageDialog(dialog, I18n.t("findings.msg.sentToRepeater"), I18n.t("findings.title.success"), JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(dialog, I18n.t("findings.msg.repeaterFailed") + " " + ex.getMessage(), I18n.t("findings.title.error"), JOptionPane.ERROR_MESSAGE);
                }
            });
            buttonPanel.add(repeaterButton);

            // Send to Intruder button
            JButton intruderButton = I18nUI.text(new JButton("Send to Intruder"), "findings.btn.sendToIntruder");
            intruderButton.setFont(new Font("Segoe UI", Font.BOLD, 12));
            intruderButton.setBackground(ColorScheme.WARNING_ORANGE);
            intruderButton.setForeground(Color.WHITE);
            intruderButton.setFocusPainted(false);
            intruderButton.setBorder(BorderFactory.createEmptyBorder(8, 15, 8, 15));
            intruderButton.addActionListener(e -> {
                try {
                    byte[] request = finding.getHttpRequest().getBytes();

                    // Get HTTP service - either from requestResponse or parse from URL
                    IHttpService httpService = null;
                    if (requestResponse != null) {
                        httpService = requestResponse.getHttpService();
                    } else if (finding.getAffectedUrl() != null && !finding.getAffectedUrl().isEmpty()) {
                        // Parse URL to create HTTP service
                        java.net.URL url = new java.net.URL(finding.getAffectedUrl());
                        String protocol = url.getProtocol();
                        String host = url.getHost();
                        int port = url.getPort();
                        if (port == -1) {
                            port = protocol.equals("https") ? 443 : 80;
                        }

                        final String finalProtocol = protocol;
                        final String finalHost = host;
                        final int finalPort = port;

                        httpService = new IHttpService() {
                            @Override
                            public String getHost() { return finalHost; }

                            @Override
                            public int getPort() { return finalPort; }

                            @Override
                            public String getProtocol() { return finalProtocol; }
                        };
                    }

                    if (httpService == null) {
                        throw new Exception("Cannot determine target host/port");
                    }

                    callbacks.sendToIntruder(
                        httpService.getHost(),
                        httpService.getPort(),
                        httpService.getProtocol().equals("https"),
                        request
                    );
                    JOptionPane.showMessageDialog(dialog, I18n.t("findings.msg.sentToIntruder"), I18n.t("findings.title.success"), JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(dialog, I18n.t("findings.msg.intruderFailed") + " " + ex.getMessage(), I18n.t("findings.title.error"), JOptionPane.ERROR_MESSAGE);
                }
            });
            buttonPanel.add(intruderButton);
        }

        JButton copyButton = I18nUI.text(new JButton("📋 Copy to Clipboard"), "findings.btn.copyToClipboard");
        copyButton.setFont(new Font("Segoe UI", Font.BOLD, 12));
        copyButton.setBackground(ColorScheme.SUCCESS_GREEN);
        copyButton.setForeground(Color.WHITE);
        copyButton.setFocusPainted(false);
        copyButton.setBorder(BorderFactory.createEmptyBorder(8, 15, 8, 15));
        copyButton.addActionListener(e -> {
            java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(poc);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            JOptionPane.showMessageDialog(dialog, I18n.t("findings.msg.pocCopied"), I18n.t("findings.title.success"), JOptionPane.INFORMATION_MESSAGE);
        });

        JButton closeButton = I18nUI.text(new JButton("Close"), "findings.btn.close");
        closeButton.setFont(new Font("Segoe UI", Font.BOLD, 12));
        closeButton.setBackground(ColorScheme.BG_HOVER);
        closeButton.setForeground(ColorScheme.TEXT_DARK);
        closeButton.setFocusPainted(false);
        closeButton.setBorder(BorderFactory.createEmptyBorder(8, 15, 8, 15));
        closeButton.addActionListener(e -> dialog.dispose());

        buttonPanel.add(copyButton);
        buttonPanel.add(closeButton);

        contentPanel.add(titleLabel, BorderLayout.NORTH);
        contentPanel.add(scrollPane, BorderLayout.CENTER);
        contentPanel.add(buttonPanel, BorderLayout.SOUTH);

        dialog.add(contentPanel);
        dialog.setVisible(true);
    }

    /**
     * Send finding to Burp Repeater
     */
    private void sendToRepeater(int row) {
        if (row < 0 || row >= findings.size()) {
            JOptionPane.showMessageDialog(this,
                I18n.t("findings.msg.noFindingSelected"),
                I18n.t("findings.title.cannotSendToRepeater"),
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        Finding finding = findings.get(row);
        IHttpRequestResponse requestResponse = (row < requestResponses.size()) ? requestResponses.get(row) : null;

        // Try to get request from Finding object first
        String requestData = finding.getHttpRequest();
        if (requestData == null || requestData.isEmpty()) {
            // Fallback to requestResponse if available
            if (requestResponse == null || requestResponse.getRequest() == null) {
                JOptionPane.showMessageDialog(this,
                    I18n.t("findings.msg.noRequestForFinding"),
                    I18n.t("findings.title.cannotSendToRepeater"),
                    JOptionPane.WARNING_MESSAGE);
                return;
            }
            requestData = new String(requestResponse.getRequest());
        }

        try {
            byte[] request = requestData.getBytes();

            // Get HTTP service - either from requestResponse or parse from URL
            IHttpService httpService = null;
            if (requestResponse != null) {
                httpService = requestResponse.getHttpService();
            } else if (finding.getAffectedUrl() != null && !finding.getAffectedUrl().isEmpty()) {
                // Parse URL to create HTTP service
                try {
                    java.net.URL url = new java.net.URL(finding.getAffectedUrl());
                    String protocol = url.getProtocol();
                    String host = url.getHost();
                    int port = url.getPort();
                    if (port == -1) {
                        port = protocol.equals("https") ? 443 : 80;
                    }

                    final String finalProtocol = protocol;
                    final String finalHost = host;
                    final int finalPort = port;

                    // Create IHttpService implementation
                    httpService = new IHttpService() {
                        @Override
                        public String getHost() { return finalHost; }

                        @Override
                        public int getPort() { return finalPort; }

                        @Override
                        public String getProtocol() { return finalProtocol; }
                    };
                } catch (Exception urlEx) {
                    throw new Exception("Cannot parse URL: " + finding.getAffectedUrl());
                }
            }

            if (httpService == null) {
                JOptionPane.showMessageDialog(this,
                    I18n.t("findings.msg.cannotDetermineHostPort"),
                    I18n.t("findings.title.error"),
                    JOptionPane.ERROR_MESSAGE);
                return;
            }

            // Send to Repeater
            callbacks.sendToRepeater(
                httpService.getHost(),
                httpService.getPort(),
                httpService.getProtocol().equals("https"),
                request,
                finding.getType()
            );

            JOptionPane.showMessageDialog(this,
                I18n.t("findings.msg.sentToRepeaterSuccess"),
                I18n.t("findings.title.success"),
                JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                I18n.t("findings.msg.repeaterFailed") + " " + ex.getMessage(),
                I18n.t("findings.title.error"),
                JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Mark selected finding as false positive
     */
    private void markAsFalsePositive() {
        int selectedRow = findingsTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this, I18n.t("findings.msg.selectFirst"));
            return;
        }

        Finding finding = findings.get(selectedRow);

        int result = JOptionPane.showConfirmDialog(this,
            I18n.t("findings.msg.confirmFalsePositive", finding.getType()),
            I18n.t("findings.title.confirmFalsePositive"),
            JOptionPane.YES_NO_OPTION);

        if (result == JOptionPane.YES_OPTION) {
            String reason = JOptionPane.showInputDialog(this,
                    I18n.t("findings.msg.falsePositiveReason"),
                    I18n.t("findings.title.falsePositiveNote"), JOptionPane.QUESTION_MESSAGE);
            finding.setFalsePositive(true);
            // Persist so the RAG + ambient learning loop stop suggesting this class here.
            if (finding.getDbId() > 0 && dbManager != null) {
                try {
                    dbManager.markAsFalsePositive(finding.getDbId(), reason);
                } catch (Exception ex) {
                    System.err.println("[FindingsPanel] markAsFalsePositive DB error: " + ex.getMessage());
                }
            }
            // Update table color or remove row
            tableModel.removeRow(selectedRow);
            findings.remove(selectedRow);

            JOptionPane.showMessageDialog(this, I18n.t("findings.msg.markedFalsePositive"));
        }
    }
    
    /**
     * Export findings to clipboard
     */
    private void exportFindings() {
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(this, I18n.t("findings.msg.noFindingsToExport"));
            return;
        }
        
        StringBuilder export = new StringBuilder();
        export.append("AppSecHunter - Findings Report\n");
        export.append("=====================================\n\n");
        
        for (int i = 0; i < findings.size(); i++) {
            Finding finding = findings.get(i);
            export.append("[").append(i + 1).append("] ").append(finding.getType()).append("\n");
            export.append("Severity: ").append(finding.getSeverity()).append("\n");
            export.append("Confidence: ").append(finding.getConfidence()).append("\n");
            export.append("Description: ").append(finding.getDescription()).append("\n");
            export.append("\n");
        }
        
        // Copy to clipboard
        java.awt.datatransfer.StringSelection selection = 
            new java.awt.datatransfer.StringSelection(export.toString());
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);

        JOptionPane.showMessageDialog(this, I18n.t("findings.msg.exportedToClipboard"));
    }
    
    /**
     * Truncate string
     */
    private String truncate(String str, int maxLength) {
        if (str == null) return "";
        if (str.length() <= maxLength) return str;
        return str.substring(0, maxLength) + "...";
    }
}

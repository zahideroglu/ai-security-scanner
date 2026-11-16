package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.*;
import java.awt.image.BufferedImage;

/**
 * Icons - Programmatically generated icons for the extension
 * No external image files needed - all icons are drawn at runtime
 *
 * @author Zahid Eroglu
 */
public class Icons {

    // Icon sizes
    public static final int SMALL = 16;
    public static final int MEDIUM = 20;
    public static final int LARGE = 24;

    /**
     * Get scan/search icon
     */
    public static Icon getScanIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.PRIMARY_BLUE);
            g.setStroke(new BasicStroke(2f));
            int r = s / 3;
            g.drawOval(2, 2, r * 2, r * 2);
            g.drawLine(r + 4, r + 4, s - 3, s - 3);
        });
    }

    /**
     * Get settings/gear icon
     */
    public static Icon getSettingsIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.TEXT_DARK);
            g.setStroke(new BasicStroke(1.5f));
            int cx = s / 2;
            int cy = s / 2;
            int outerR = s / 2 - 2;
            int innerR = s / 4;

            // Draw gear teeth
            for (int i = 0; i < 8; i++) {
                double angle = Math.PI * 2 * i / 8;
                int x1 = (int) (cx + innerR * Math.cos(angle));
                int y1 = (int) (cy + innerR * Math.sin(angle));
                int x2 = (int) (cx + outerR * Math.cos(angle));
                int y2 = (int) (cy + outerR * Math.sin(angle));
                g.drawLine(x1, y1, x2, y2);
            }
            g.drawOval(cx - innerR, cy - innerR, innerR * 2, innerR * 2);
        });
    }

    /**
     * Get play icon
     */
    public static Icon getPlayIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.SUCCESS_GREEN);
            int[] xPoints = {4, s - 4, 4};
            int[] yPoints = {2, s / 2, s - 2};
            g.fillPolygon(xPoints, yPoints, 3);
        });
    }

    /**
     * Get stop icon
     */
    public static Icon getStopIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.ERROR_RED);
            g.fillRect(3, 3, s - 6, s - 6);
        });
    }

    /**
     * Get refresh icon
     */
    public static Icon getRefreshIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.PRIMARY_BLUE);
            g.setStroke(new BasicStroke(2f));
            int margin = 3;
            g.drawArc(margin, margin, s - margin * 2, s - margin * 2, 45, 270);
            // Arrow head
            int cx = s / 2 + 3;
            int cy = margin + 2;
            g.drawLine(cx, cy, cx + 4, cy);
            g.drawLine(cx, cy, cx, cy + 4);
        });
    }

    /**
     * Get save icon
     */
    public static Icon getSaveIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.SUCCESS_GREEN);
            g.fillRoundRect(2, 2, s - 4, s - 4, 3, 3);
            g.setColor(ColorScheme.BG_CARD);
            g.fillRect(s / 4, 2, s / 2, s / 3);
            g.fillRect(s / 4, s / 2, s / 2, s / 3);
        });
    }

    /**
     * Get delete/trash icon
     */
    public static Icon getDeleteIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.ERROR_RED);
            g.setStroke(new BasicStroke(1.5f));
            // Lid
            g.drawLine(3, 4, s - 3, 4);
            g.drawLine(s / 2 - 2, 2, s / 2 + 2, 2);
            g.drawLine(s / 2 - 2, 2, s / 2 - 2, 4);
            g.drawLine(s / 2 + 2, 2, s / 2 + 2, 4);
            // Body
            g.drawRoundRect(4, 5, s - 8, s - 7, 2, 2);
            // Lines
            g.drawLine(s / 2 - 2, 7, s / 2 - 2, s - 4);
            g.drawLine(s / 2 + 2, 7, s / 2 + 2, s - 4);
        });
    }

    /**
     * Get connection/plug icon
     */
    public static Icon getConnectionIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.PRIMARY_BLUE);
            g.setStroke(new BasicStroke(2f));
            // Plug prongs
            g.drawLine(s / 4, 2, s / 4, s / 2 - 2);
            g.drawLine(s * 3 / 4, 2, s * 3 / 4, s / 2 - 2);
            // Plug body
            g.fillRoundRect(s / 6, s / 2 - 2, s * 2 / 3, s / 3, 3, 3);
            // Cord
            g.drawLine(s / 2, s / 2 + s / 3, s / 2, s - 2);
        });
    }

    /**
     * Get warning icon
     */
    public static Icon getWarningIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.WARNING_ORANGE);
            int[] xPoints = {s / 2, 2, s - 2};
            int[] yPoints = {2, s - 2, s - 2};
            g.fillPolygon(xPoints, yPoints, 3);
            g.setColor(Color.WHITE);
            g.fillRect(s / 2 - 1, s / 3, 2, s / 3);
            g.fillRect(s / 2 - 1, s * 2 / 3 + 1, 2, 2);
        });
    }

    /**
     * Get error icon
     */
    public static Icon getErrorIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.ERROR_RED);
            g.fillOval(2, 2, s - 4, s - 4);
            g.setColor(Color.WHITE);
            g.setStroke(new BasicStroke(2f));
            g.drawLine(s / 3, s / 3, s * 2 / 3, s * 2 / 3);
            g.drawLine(s * 2 / 3, s / 3, s / 3, s * 2 / 3);
        });
    }

    /**
     * Get success/check icon
     */
    public static Icon getSuccessIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.SUCCESS_GREEN);
            g.fillOval(2, 2, s - 4, s - 4);
            g.setColor(Color.WHITE);
            g.setStroke(new BasicStroke(2f));
            g.drawLine(s / 4, s / 2, s / 2 - 1, s * 2 / 3);
            g.drawLine(s / 2 - 1, s * 2 / 3, s * 3 / 4, s / 3);
        });
    }

    /**
     * Get info icon
     */
    public static Icon getInfoIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.PRIMARY_BLUE);
            g.fillOval(2, 2, s - 4, s - 4);
            g.setColor(Color.WHITE);
            g.setFont(new Font("SansSerif", Font.BOLD, s * 2 / 3));
            FontMetrics fm = g.getFontMetrics();
            String text = "i";
            int x = (s - fm.stringWidth(text)) / 2;
            int y = (s + fm.getAscent() - fm.getDescent()) / 2;
            g.drawString(text, x, y);
        });
    }

    /**
     * Get copy icon
     */
    public static Icon getCopyIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.TEXT_DARK);
            g.setStroke(new BasicStroke(1.5f));
            // Back rectangle
            g.drawRoundRect(4, 2, s - 8, s - 6, 2, 2);
            // Front rectangle
            g.setColor(ColorScheme.BG_CARD);
            g.fillRoundRect(2, 4, s - 8, s - 6, 2, 2);
            g.setColor(ColorScheme.TEXT_DARK);
            g.drawRoundRect(2, 4, s - 8, s - 6, 2, 2);
        });
    }

    /**
     * Get send icon
     */
    public static Icon getSendIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.PRIMARY_BLUE);
            int[] xPoints = {2, s - 2, 2};
            int[] yPoints = {3, s / 2, s - 3};
            g.fillPolygon(xPoints, yPoints, 3);
        });
    }

    /**
     * Get target icon
     */
    public static Icon getTargetIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.ERROR_RED);
            g.setStroke(new BasicStroke(1.5f));
            int cx = s / 2;
            int cy = s / 2;
            g.drawOval(cx - s / 3, cy - s / 3, s * 2 / 3, s * 2 / 3);
            g.drawOval(cx - s / 6, cy - s / 6, s / 3, s / 3);
            g.fillOval(cx - 2, cy - 2, 4, 4);
        });
    }

    /**
     * Get vulnerability/shield icon
     */
    public static Icon getVulnIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.WARNING_ORANGE);
            // Shield shape
            int[] xPoints = {s / 2, 2, 2, s / 2, s - 2, s - 2};
            int[] yPoints = {2, 4, s / 2, s - 2, s / 2, 4};
            g.fillPolygon(xPoints, yPoints, 6);
            // Exclamation mark
            g.setColor(Color.WHITE);
            g.fillRect(s / 2 - 1, s / 4, 2, s / 3);
            g.fillRect(s / 2 - 1, s * 2 / 3, 2, 2);
        });
    }

    /**
     * Get list/findings icon
     */
    public static Icon getListIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.TEXT_DARK);
            g.setStroke(new BasicStroke(1.5f));
            int y1 = s / 4;
            int y2 = s / 2;
            int y3 = s * 3 / 4;
            // Bullets
            g.fillOval(3, y1 - 2, 4, 4);
            g.fillOval(3, y2 - 2, 4, 4);
            g.fillOval(3, y3 - 2, 4, 4);
            // Lines
            g.drawLine(10, y1, s - 3, y1);
            g.drawLine(10, y2, s - 3, y2);
            g.drawLine(10, y3, s - 3, y3);
        });
    }

    /**
     * Get AI/brain icon
     */
    public static Icon getAIIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.PURPLE);
            // Brain shape (simplified)
            g.fillOval(3, 3, s / 2 - 1, s - 6);
            g.fillOval(s / 2 - 1, 3, s / 2 - 1, s - 6);
            // Nodes
            g.setColor(Color.WHITE);
            g.fillOval(s / 4, s / 3, 3, 3);
            g.fillOval(s * 3 / 4 - 3, s / 3, 3, 3);
            g.fillOval(s / 2 - 1, s / 2, 3, 3);
        });
    }

    /**
     * Get database icon
     */
    public static Icon getDatabaseIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.PRIMARY_BLUE);
            // Top ellipse
            g.fillOval(3, 2, s - 6, s / 4);
            // Body
            g.fillRect(3, s / 8, s - 6, s * 3 / 4);
            // Bottom ellipse
            g.fillOval(3, s - s / 4 - 2, s - 6, s / 4);
            // Lines
            g.setColor(ColorScheme.BG_CARD);
            g.drawLine(3, s / 3, s - 3, s / 3);
            g.drawLine(3, s * 2 / 3, s - 3, s * 2 / 3);
        });
    }

    /**
     * Get clear/broom icon
     */
    public static Icon getClearIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.WARNING_ORANGE);
            g.setStroke(new BasicStroke(1.5f));
            // Handle
            g.drawLine(s / 2, 2, s / 2, s / 2);
            // Bristles
            g.fillRoundRect(3, s / 2, s - 6, s / 2 - 2, 3, 3);
        });
    }

    /**
     * Create a generic icon with custom drawing
     */
    private static Icon createIcon(int size, IconPainter painter) {
        BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();

        // Enable anti-aliasing for smoother lines
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);

        // Draw the icon
        painter.paint(g, size);

        g.dispose();
        return new ImageIcon(image);
    }

    /**
     * Functional interface for icon painting
     */
    @FunctionalInterface
    private interface IconPainter {
        void paint(Graphics2D g, int size);
    }

    /**
     * Get icon for button text label (replaces emoji)
     */
    public static String getTextIcon(String type) {
        switch (type.toLowerCase()) {
            case "scan": return "[>]";
            case "stop": return "[X]";
            case "save": return "[S]";
            case "delete": return "[D]";
            case "refresh": return "[R]";
            case "settings": return "[*]";
            case "connection": return "[C]";
            case "copy": return "[=]";
            case "send": return "[>]";
            case "warning": return "[!]";
            case "error": return "[X]";
            case "success": return "[V]";
            case "info": return "[i]";
            case "ai": return "[AI]";
            default: return "[ ]";
        }
    }

    /**
     * Get shield icon with custom color
     */
    public static Icon getShieldIcon(int size, Color color) {
        return createIcon(size, (g, s) -> {
            g.setColor(color);
            // Shield shape
            int[] xPoints = {s / 2, 2, 2, s / 2, s - 2, s - 2};
            int[] yPoints = {2, 4, s / 2, s - 2, s / 2, 4};
            g.fillPolygon(xPoints, yPoints, 6);
        });
    }

    /**
     * Get circle icon with custom color (for severity indicators)
     */
    public static Icon getCircleIcon(int size, Color color) {
        return createIcon(size, (g, s) -> {
            g.setColor(color);
            g.fillOval(1, 1, s - 2, s - 2);
        });
    }

    /**
     * Get response/document icon
     */
    public static Icon getResponseIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.SUCCESS_GREEN);
            g.setStroke(new BasicStroke(1.5f));
            // Document outline
            g.drawRoundRect(2, 2, s - 4, s - 4, 2, 2);
            // Lines
            g.drawLine(4, s / 3, s - 4, s / 3);
            g.drawLine(4, s / 2, s - 6, s / 2);
            g.drawLine(4, s * 2 / 3, s - 4, s * 2 / 3);
        });
    }

    /**
     * Get link/reference icon
     */
    public static Icon getLinkIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.PRIMARY_BLUE);
            g.setStroke(new BasicStroke(2f));
            // Chain links
            int linkW = s / 3;
            int linkH = s / 2;
            g.drawRoundRect(2, s / 4, linkW, linkH, 3, 3);
            g.drawRoundRect(s - linkW - 2, s / 4, linkW, linkH, 3, 3);
            // Connector
            g.drawLine(linkW + 2, s / 2, s - linkW - 2, s / 2);
        });
    }

    /**
     * Get retest/cycle icon
     */
    public static Icon getRetestIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.SUCCESS_GREEN);
            g.setStroke(new BasicStroke(2f));
            int margin = 3;
            // Top arrow
            g.drawArc(margin, margin, s - margin * 2, s - margin * 2, 45, 180);
            int ax1 = s * 3 / 4;
            int ay1 = margin + 2;
            g.drawLine(ax1, ay1, ax1 + 4, ay1 + 2);
            g.drawLine(ax1, ay1, ax1 - 2, ay1 + 4);

            // Bottom arrow
            g.drawArc(margin, margin, s - margin * 2, s - margin * 2, 225, 180);
            int ax2 = s / 4;
            int ay2 = s - margin - 2;
            g.drawLine(ax2, ay2, ax2 - 4, ay2 - 2);
            g.drawLine(ax2, ay2, ax2 + 2, ay2 - 4);
        });
    }

    /**
     * Get check/verified icon
     */
    public static Icon getCheckIcon(int size, Color color) {
        return createIcon(size, (g, s) -> {
            g.setColor(color);
            g.setStroke(new BasicStroke(2.5f));
            // Checkmark
            g.drawLine(s / 5, s / 2, s * 2 / 5, s * 3 / 4);
            g.drawLine(s * 2 / 5, s * 3 / 4, s * 4 / 5, s / 4);
        });
    }

    /**
     * Get cross/X icon
     */
    public static Icon getCrossIcon(int size, Color color) {
        return createIcon(size, (g, s) -> {
            g.setColor(color);
            g.setStroke(new BasicStroke(2.5f));
            // X shape
            g.drawLine(s / 4, s / 4, s * 3 / 4, s * 3 / 4);
            g.drawLine(s * 3 / 4, s / 4, s / 4, s * 3 / 4);
        });
    }

    /**
     * Get pending/clock icon
     */
    public static Icon getPendingIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.WARNING_ORANGE);
            g.setStroke(new BasicStroke(1.5f));
            // Clock circle
            g.drawOval(2, 2, s - 4, s - 4);
            // Clock hands
            int cx = s / 2;
            int cy = s / 2;
            g.drawLine(cx, cy, cx, cy - s / 4);
            g.drawLine(cx, cy, cx + s / 5, cy + s / 6);
        });
    }

    /**
     * Get statistics/chart icon
     */
    public static Icon getStatsIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.PRIMARY_BLUE);
            // Bars
            g.fillRect(3, s * 2 / 3, s / 5, s / 3 - 2);
            g.fillRect(s / 3, s / 3, s / 5, s * 2 / 3 - 2);
            g.fillRect(s * 2 / 3, s / 2, s / 5, s / 2 - 2);
        });
    }

    /**
     * Get globe/world icon - for domain scanning and SSRF
     */
    public static Icon getGlobeIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.SUCCESS_GREEN);
            g.setStroke(new BasicStroke(1.5f));
            int margin = 2;
            int diameter = s - margin * 2;
            // Outer circle (globe)
            g.drawOval(margin, margin, diameter, diameter);
            // Horizontal line (equator)
            g.drawLine(margin, s / 2, s - margin, s / 2);
            // Vertical ellipse (meridian)
            g.drawOval(s / 3, margin, s / 3, diameter);
            // Top latitude line
            g.drawArc(margin + 2, margin, diameter - 4, s / 2, 0, -180);
            // Bottom latitude line
            g.drawArc(margin + 2, s / 2, diameter - 4, s / 2 - margin, 0, 180);
        });
    }

    /**
     * Get code/brackets icon - for XSS testing
     */
    public static Icon getCodeIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.WARNING_ORANGE);
            g.setStroke(new BasicStroke(2f));
            // Left bracket <
            g.drawLine(s / 3, s / 4, s / 6, s / 2);
            g.drawLine(s / 6, s / 2, s / 3, s * 3 / 4);
            // Right bracket >
            g.drawLine(s * 2 / 3, s / 4, s * 5 / 6, s / 2);
            g.drawLine(s * 5 / 6, s / 2, s * 2 / 3, s * 3 / 4);
            // Slash /
            g.drawLine(s / 2 + 2, s / 4 + 2, s / 2 - 2, s * 3 / 4 - 2);
        });
    }

    /**
     * Get user/person icon - for IDOR testing
     */
    public static Icon getUserIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.PRIMARY_BLUE);
            // Head
            int headSize = s / 3;
            g.fillOval(s / 2 - headSize / 2, 2, headSize, headSize);
            // Body
            g.fillArc(s / 6, s / 2, s * 2 / 3, s / 2, 0, 180);
        });
    }

    /**
     * Get key icon - for JWT and authentication testing
     */
    public static Icon getKeyIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.WARNING_ORANGE);
            g.setStroke(new BasicStroke(2f));
            // Key head (circle)
            int headSize = s / 3;
            g.drawOval(2, s / 2 - headSize / 2, headSize, headSize);
            g.fillOval(4, s / 2 - headSize / 4, headSize / 2, headSize / 2);
            // Key shaft
            g.drawLine(2 + headSize, s / 2, s - 3, s / 2);
            // Key teeth
            g.drawLine(s - 5, s / 2, s - 5, s / 2 + 4);
            g.drawLine(s - 8, s / 2, s - 8, s / 2 + 3);
        });
    }

    /**
     * Get lock icon - for security testing
     */
    public static Icon getLockIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.SUCCESS_GREEN);
            g.setStroke(new BasicStroke(1.5f));
            // Shackle
            g.drawArc(s / 4, 2, s / 2, s / 2, 0, 180);
            // Body
            g.fillRoundRect(s / 6, s / 2, s * 2 / 3, s / 2 - 2, 3, 3);
            // Keyhole
            g.setColor(ColorScheme.BG_CARD);
            g.fillOval(s / 2 - 2, s / 2 + 2, 4, 4);
            g.fillRect(s / 2 - 1, s / 2 + 5, 2, 4);
        });
    }

    /**
     * Get bug icon - for vulnerability scanning
     */
    public static Icon getBugIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.ERROR_RED);
            g.setStroke(new BasicStroke(1.5f));
            // Body
            g.fillOval(s / 4, s / 3, s / 2, s / 2);
            // Head
            g.fillOval(s / 3, s / 5, s / 3, s / 4);
            // Legs
            g.drawLine(s / 4, s / 2, 2, s / 3);
            g.drawLine(s / 4, s * 2 / 3, 2, s * 3 / 4);
            g.drawLine(s * 3 / 4, s / 2, s - 2, s / 3);
            g.drawLine(s * 3 / 4, s * 2 / 3, s - 2, s * 3 / 4);
            // Antennae
            g.drawLine(s / 3, s / 5, s / 5, 2);
            g.drawLine(s * 2 / 3, s / 5, s * 4 / 5, 2);
        });
    }

    /**
     * Get network icon - for network-related tests
     */
    public static Icon getNetworkIcon(int size) {
        return createIcon(size, (g, s) -> {
            g.setColor(ColorScheme.PRIMARY_BLUE);
            g.setStroke(new BasicStroke(1.5f));
            // Center node
            g.fillOval(s / 2 - 3, s / 2 - 3, 6, 6);
            // Surrounding nodes
            int nodeSize = 4;
            g.fillOval(s / 4 - nodeSize / 2, s / 4 - nodeSize / 2, nodeSize, nodeSize);
            g.fillOval(s * 3 / 4 - nodeSize / 2, s / 4 - nodeSize / 2, nodeSize, nodeSize);
            g.fillOval(s / 4 - nodeSize / 2, s * 3 / 4 - nodeSize / 2, nodeSize, nodeSize);
            g.fillOval(s * 3 / 4 - nodeSize / 2, s * 3 / 4 - nodeSize / 2, nodeSize, nodeSize);
            // Connections
            g.drawLine(s / 2, s / 2, s / 4, s / 4);
            g.drawLine(s / 2, s / 2, s * 3 / 4, s / 4);
            g.drawLine(s / 2, s / 2, s / 4, s * 3 / 4);
            g.drawLine(s / 2, s / 2, s * 3 / 4, s * 3 / 4);
        });
    }
}

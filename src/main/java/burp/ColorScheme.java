package burp;

import java.awt.Color;
import javax.swing.UIManager;

/**
 * Color Scheme - Automatic theme detection (Light/Dark mode)
 * Adapts to Burp Suite's current theme setting
 *
 * @author Zahid Eroglu
 */
public class ColorScheme {

    // Theme detection flag
    private static boolean isDarkMode = detectDarkMode();

    // Primary Colors (same for both themes)
    public static Color PRIMARY_BLUE = new Color(33, 150, 243);
    public static Color SUCCESS_GREEN = new Color(76, 175, 80);
    public static Color WARNING_ORANGE = new Color(255, 152, 0);
    public static Color ERROR_RED = new Color(244, 67, 54);
    public static Color PURPLE = new Color(156, 39, 176);

    // Background Colors - Auto-detected
    public static Color BG_DARK;
    public static Color BG_CARD;
    public static Color BG_HOVER;
    public static Color BG_LIGHT;

    // Text Colors - Auto-detected
    public static Color TEXT_PRIMARY;
    public static Color TEXT_SECONDARY;
    public static Color TEXT_DISABLED;
    public static Color TEXT_DARK;

    // Border Colors - Auto-detected
    public static Color BORDER_LIGHT;
    public static Color BORDER_DARK;
    public static Color BORDER_DARKER;

    // Chat Message Colors
    public static Color CHAT_USER_BG;
    public static Color CHAT_QWEN_BG;
    public static Color CHAT_SYSTEM_BG;
    public static Color CHAT_VULN_BG;

    // Console Colors (log / request / response / code areas) - Auto-detected.
    // Adaptive: follows the active theme instead of being hardcoded dark.
    public static Color CONSOLE_BG;
    public static Color CONSOLE_FG;

    // Table Colors - Auto-detected (findings table, matrix, etc.)
    public static Color TABLE_BG;
    public static Color TABLE_BG_ALT;
    public static Color TABLE_SELECTION_BG;
    public static Color TABLE_SELECTION_FG;
    public static Color TABLE_HEADER_BG;
    public static Color TABLE_HEADER_FG;
    public static Color TABLE_GRID;

    // Stage/state strip colors (Keşif/Hipotez/… progress strip). bg + matching readable fg.
    public static Color STATE_IDLE_BG, STATE_IDLE_FG;
    public static Color STATE_RUNNING_BG, STATE_RUNNING_FG;
    public static Color STATE_DONE_BG, STATE_DONE_FG;
    public static Color STATE_FAIL_BG, STATE_FAIL_FG;

    // Severity Colors (same for both themes for visibility)
    public static final Color SEVERITY_CRITICAL = new Color(156, 39, 176);
    public static final Color SEVERITY_HIGH = new Color(244, 67, 54);
    public static final Color SEVERITY_MEDIUM = new Color(255, 152, 0);
    public static final Color SEVERITY_LOW = new Color(33, 150, 243);
    public static final Color SEVERITY_INFO = new Color(120, 120, 120);

    // Static initializer
    static {
        applyTheme();
    }

    /**
     * Detect if dark mode is enabled
     */
    private static boolean detectDarkMode() {
        try {
            // Try to get background color from UIManager
            Color bgColor = UIManager.getColor("Panel.background");
            if (bgColor != null) {
                // Calculate luminance - if low, it's dark mode
                double luminance = (0.299 * bgColor.getRed() +
                                   0.587 * bgColor.getGreen() +
                                   0.114 * bgColor.getBlue()) / 255;
                return luminance < 0.5;
            }

            // Try to check look and feel name
            String lafName = UIManager.getLookAndFeel().getName().toLowerCase();
            if (lafName.contains("dark") || lafName.contains("nimbus")) {
                return true;
            }

            // Default to dark mode for Burp Suite
            return true;
        } catch (Exception e) {
            // Default to dark mode
            return true;
        }
    }

    /**
     * Apply theme colors based on mode
     */
    private static void applyTheme() {
        if (isDarkMode) {
            applyDarkTheme();
        } else {
            applyLightTheme();
        }
    }

    /**
     * Apply dark theme colors
     */
    private static void applyDarkTheme() {
        // Background Colors (Dark Theme)
        BG_DARK = new Color(30, 30, 30);
        BG_CARD = new Color(45, 45, 45);
        BG_HOVER = new Color(55, 55, 55);
        BG_LIGHT = new Color(35, 35, 35);

        // Text Colors (Dark Theme)
        TEXT_PRIMARY = new Color(255, 255, 255);
        TEXT_SECONDARY = new Color(180, 180, 180);
        TEXT_DISABLED = new Color(120, 120, 120);
        TEXT_DARK = new Color(220, 220, 220);

        // Border Colors (Dark Theme)
        BORDER_LIGHT = new Color(70, 70, 70);
        BORDER_DARK = new Color(70, 70, 70);
        BORDER_DARKER = new Color(50, 50, 50);

        // Chat Message Colors (Dark Theme)
        CHAT_USER_BG = new Color(33, 150, 243, 30);
        CHAT_QWEN_BG = new Color(76, 175, 80, 30);
        CHAT_SYSTEM_BG = new Color(120, 120, 120, 30);
        CHAT_VULN_BG = new Color(244, 67, 54, 30);

        // Console (Dark Theme) - classic terminal look
        CONSOLE_BG = new Color(0x252526);
        CONSOLE_FG = new Color(0xE0E0E0);

        // Table (Dark Theme)
        TABLE_BG = new Color(60, 63, 65);
        TABLE_BG_ALT = new Color(50, 53, 55);
        TABLE_SELECTION_BG = new Color(75, 110, 175);
        TABLE_SELECTION_FG = new Color(240, 240, 240);
        TABLE_HEADER_BG = new Color(45, 48, 50);
        TABLE_HEADER_FG = new Color(200, 200, 200);
        TABLE_GRID = new Color(80, 83, 85);

        // State strip (Dark Theme)
        STATE_IDLE_BG = new Color(0x33373B);   STATE_IDLE_FG = new Color(0xE0E0E0);
        STATE_RUNNING_BG = new Color(0x4A5A20); STATE_RUNNING_FG = new Color(0xF0F0F0);
        STATE_DONE_BG = new Color(0x2E5D34);    STATE_DONE_FG = new Color(0xDCEFDC);
        STATE_FAIL_BG = new Color(0x6B2E2E);    STATE_FAIL_FG = new Color(0xF0DCDC);
    }

    /**
     * Apply light theme colors
     */
    private static void applyLightTheme() {
        // Background Colors (Light Theme)
        BG_DARK = new Color(250, 250, 250);
        BG_CARD = new Color(255, 255, 255);
        BG_HOVER = new Color(240, 240, 240);
        BG_LIGHT = new Color(248, 248, 248);

        // Text Colors (Light Theme)
        TEXT_PRIMARY = new Color(33, 33, 33);
        TEXT_SECONDARY = new Color(97, 97, 97);
        TEXT_DISABLED = new Color(158, 158, 158);
        TEXT_DARK = new Color(66, 66, 66);

        // Border Colors (Light Theme)
        BORDER_LIGHT = new Color(224, 224, 224);
        BORDER_DARK = new Color(189, 189, 189);
        BORDER_DARKER = new Color(158, 158, 158);

        // Chat Message Colors (Light Theme)
        CHAT_USER_BG = new Color(33, 150, 243, 40);
        CHAT_QWEN_BG = new Color(76, 175, 80, 40);
        CHAT_SYSTEM_BG = new Color(158, 158, 158, 40);
        CHAT_VULN_BG = new Color(244, 67, 54, 40);

        // Console (Light Theme) - light code surface, dark ink
        CONSOLE_BG = new Color(0xF8F9FA);
        CONSOLE_FG = new Color(0x282A2E);

        // Table (Light Theme)
        TABLE_BG = new Color(255, 255, 255);
        TABLE_BG_ALT = new Color(0xF6F8FA);
        TABLE_SELECTION_BG = new Color(0xCCE4FF);
        TABLE_SELECTION_FG = new Color(0x14283C);
        TABLE_HEADER_BG = new Color(0xEEF0F2);
        TABLE_HEADER_FG = new Color(0x3C424A);
        TABLE_GRID = new Color(0xE0E0E0);

        // State strip (Light Theme) - soft alert tints with readable ink
        STATE_IDLE_BG = new Color(0xE9ECEF);    STATE_IDLE_FG = new Color(0x5A626C);
        STATE_RUNNING_BG = new Color(0xFFF3CD);  STATE_RUNNING_FG = new Color(0x856404);
        STATE_DONE_BG = new Color(0xD4EDDA);     STATE_DONE_FG = new Color(0x155724);
        STATE_FAIL_BG = new Color(0xF8D7DA);     STATE_FAIL_FG = new Color(0x721C24);
    }

    /**
     * Force refresh theme detection
     */
    public static void refreshTheme() {
        isDarkMode = detectDarkMode();
        applyTheme();
    }

    /**
     * Manually set dark mode
     */
    public static void setDarkMode(boolean dark) {
        isDarkMode = dark;
        applyTheme();
    }

    /**
     * Check if dark mode is active
     */
    public static boolean isDarkMode() {
        return isDarkMode;
    }

    /**
     * Get severity color
     */
    public static Color getSeverityColor(String severity) {
        if (severity == null) return SEVERITY_INFO;

        switch (severity.toLowerCase()) {
            case "critical":
                return SEVERITY_CRITICAL;
            case "high":
                return SEVERITY_HIGH;
            case "medium":
                return SEVERITY_MEDIUM;
            case "low":
                return SEVERITY_LOW;
            default:
                return SEVERITY_INFO;
        }
    }

    /**
     * Get chat message color based on sender
     */
    public static Color getChatColor(String sender) {
        if (sender == null) return CHAT_SYSTEM_BG;

        switch (sender.toLowerCase()) {
            case "user":
                return CHAT_USER_BG;
            case "assistant":
            case "qwen":
                return CHAT_QWEN_BG;
            case "vuln":
                return CHAT_VULN_BG;
            default:
                return CHAT_SYSTEM_BG;
        }
    }

    /**
     * Get contrasting text color for a background
     */
    public static Color getContrastingTextColor(Color background) {
        double luminance = (0.299 * background.getRed() +
                           0.587 * background.getGreen() +
                           0.114 * background.getBlue()) / 255;
        return luminance > 0.5 ? new Color(33, 33, 33) : new Color(255, 255, 255);
    }
}

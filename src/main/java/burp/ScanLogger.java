package burp;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Append-only scan activity logger. Mirrors everything the user sees in the
 * Detection Engine log pane (stages, agent reasoning, findings) plus the
 * active-test table (every probe sent + its result) to a daily file under
 * {@code ~/.appsechunter/logs/scan-YYYY-MM-DD.log}.
 *
 * <p>Purpose: while the engine is being stabilised, persist every run so it can
 * be reviewed after the fact (false positives, agent loops, timeouts). On by
 * default. Thread-safe; logging must never throw into a running scan.</p>
 *
 * @author Zahid Eroglu
 */
public final class ScanLogger {

    private static final ScanLogger INSTANCE = new ScanLogger();
    public static ScanLogger get() { return INSTANCE; }

    private final Object lock = new Object();
    private final SimpleDateFormat ts = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
    private final SimpleDateFormat day = new SimpleDateFormat("yyyy-MM-dd");

    private File dir;
    private PrintWriter out;
    private String openDay;
    private volatile boolean enabled = true;

    private ScanLogger() {
        try {
            dir = new File(System.getProperty("user.home"), ".appsechunter/logs");
            if (!dir.exists() && !dir.mkdirs() && !dir.isDirectory()) {
                enabled = false;
            }
        } catch (Exception e) {
            enabled = false;
        }
    }

    /** Directory where logs are written (may be null if init failed). */
    public File dir() { return dir; }

    /** Absolute path of today's log file, for surfacing to the user. */
    public String currentFilePath() {
        if (dir == null) return "(devre dışı)";
        return new File(dir, "scan-" + day.format(new Date()) + ".log").getAbsolutePath();
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean b) { enabled = b; }

    /**
     * Append one tagged line. {@code tag} identifies the run/target (may be null/empty).
     * Never throws — a logging failure must not abort the scan.
     */
    public void log(String tag, String line) {
        if (!enabled) return;
        synchronized (lock) {
            try {
                rollIfNeeded();
                if (out == null) return;
                String prefix = (tag == null || tag.isEmpty()) ? " " : " [" + tag + "] ";
                out.println(ts.format(new Date()) + prefix + (line == null ? "" : line));
                out.flush();
            } catch (Exception ignore) {
                // logging must never break a scan
            }
        }
    }

    /** Write a visible run-boundary banner so the file is navigable. */
    public void banner(String tag, String title) {
        log(tag, "");
        log(tag, "═══════════════ " + title + " ═══════════════");
    }

    private void rollIfNeeded() throws Exception {
        String today = day.format(new Date());
        if (out != null && today.equals(openDay)) return;
        closeQuietly();
        if (dir == null) return;
        File f = new File(dir, "scan-" + today + ".log");
        out = new PrintWriter(new FileWriter(f, true), false);
        openDay = today;
    }

    private void closeQuietly() {
        if (out != null) {
            try { out.flush(); out.close(); } catch (Exception ignore) {}
            out = null;
        }
    }
}

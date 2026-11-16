package burp;

import java.sql.*;
import java.util.*;
import org.json.*;

/**
 * Database Manager - SQLite database operations with proper connection handling
 * 
 * @author Zahid Eroglu
 */
public class DatabaseManager {
    
    private static final String DB_FILE = System.getProperty("user.home") + 
                                         "/.burp_ai_scanner.db";
    private Connection connection;
    private static final Object lock = new Object();
    
    /**
     * Initialize database
     */
    public void initialize() throws Exception {
        // Explicitly load SQLite JDBC driver
        Class.forName("org.sqlite.JDBC");
        
        synchronized (lock) {
            if (connection == null || connection.isClosed()) {
                // Use WAL mode and busy timeout to prevent locking issues
                String url = "jdbc:sqlite:" + DB_FILE + "?journal_mode=WAL&busy_timeout=30000";
                connection = DriverManager.getConnection(url);
                
                // Enable foreign keys and set pragmas for better performance
                try (Statement stmt = connection.createStatement()) {
                    stmt.execute("PRAGMA foreign_keys = ON");
                    stmt.execute("PRAGMA synchronous = NORMAL");
                    stmt.execute("PRAGMA cache_size = 10000");
                    stmt.execute("PRAGMA temp_store = MEMORY");
                }
                
                createTables();
            }
        }
    }
    
    /**
     * Create tables
     */
    private void createTables() throws SQLException {
        Statement stmt = connection.createStatement();
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS scan_tabs (" +
            "tab_id TEXT PRIMARY KEY, " +
            "url TEXT, " +
            "method TEXT, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        );
        
        // Conversations table
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS conversations (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "tab_id TEXT, " +
            "sender TEXT, " +
            "message TEXT, " +
            "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        );
        
        // Findings table
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS findings (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "tab_id TEXT, " +
            "type TEXT, " +
            "severity TEXT, " +
            "confidence REAL, " +
            "description TEXT, " +
            "evidence TEXT, " +
            "exploitation TEXT, " +
            "remediation TEXT, " +
            "url TEXT, " +
            "request TEXT, " +
            "response TEXT, " +
            "is_false_positive INTEGER DEFAULT 0, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
            "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        );

        // Add columns if they don't exist (for existing databases)
        try {
            stmt.execute("ALTER TABLE findings ADD COLUMN url TEXT");
        } catch (SQLException e) {
            // Column already exists
        }
        try {
            stmt.execute("ALTER TABLE findings ADD COLUMN request TEXT");
        } catch (SQLException e) {
            // Column already exists
        }
        try {
            stmt.execute("ALTER TABLE findings ADD COLUMN response TEXT");
        } catch (SQLException e) {
            // Column already exists
        }
        try {
            stmt.execute("ALTER TABLE findings ADD COLUMN fp_reason TEXT");
        } catch (SQLException e) {
            // Column already exists
        }

        // Scan requests table
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS scan_requests (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "url TEXT, " +
            "method TEXT, " +
            "request TEXT, " +
            "response TEXT, " +
            "prompt TEXT, " +
            "result TEXT, " +
            "duration INTEGER, " +
            "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        );

        // Dynamic test results table
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS dynamic_test_results (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "url TEXT, " +
            "test_type TEXT, " +
            "finding_type TEXT, " +
            "severity TEXT, " +
            "description TEXT, " +
            "evidence TEXT, " +
            "exploitation TEXT, " +
            "remediation TEXT, " +
            "duration INTEGER, " +
            "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        );

        stmt.close();
    }
    
    /**
     * Save scan result
     */
    public void saveScanResult(String url, String method, String request, 
                               String response, String prompt, ScanResult result, 
                               long duration) throws SQLException {
        
        String sql = "INSERT INTO scan_requests (url, method, request, response, prompt, result, duration) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?)";
        
        PreparedStatement stmt = connection.prepareStatement(sql);
        stmt.setString(1, url);
        stmt.setString(2, method);
        stmt.setString(3, truncate(request, 10000));
        stmt.setString(4, truncate(response, 10000));
        stmt.setString(5, prompt);
        stmt.setString(6, result.toJSON());
        stmt.setLong(7, duration);
        
        stmt.executeUpdate();
        stmt.close();
    }
    
    /**
     * Save conversation message
     */
    public void saveConversation(String tabId, String sender, String message) throws SQLException {
        String sql = "INSERT INTO conversations (tab_id, sender, message) VALUES (?, ?, ?)";

        PreparedStatement stmt = connection.prepareStatement(sql);
        stmt.setString(1, tabId);
        stmt.setString(2, sender);
        stmt.setString(3, message);

        stmt.executeUpdate();
        stmt.close();
    }

    // Overloaded method for Conversation object
    public void saveConversation(Conversation conv) throws SQLException {
        saveConversation("default", conv.getSender(), conv.getMessage());
    }

    /**
     * Get conversation history
     */
    public List<Conversation> getConversationHistory(String tabId) throws SQLException {
        List<Conversation> history = new ArrayList<>();
        
        String sql = "SELECT sender, message, timestamp FROM conversations " +
                    "WHERE tab_id = ? ORDER BY timestamp";
        
        PreparedStatement stmt = connection.prepareStatement(sql);
        stmt.setString(1, tabId);
        
        ResultSet rs = stmt.executeQuery();
        while (rs.next()) {
            history.add(new Conversation(
                rs.getString("sender"),
                rs.getString("message"),
                rs.getTimestamp("timestamp").toString()
            ));
        }
        
        rs.close();
        stmt.close();
        
        return history;
    }
    
    /**
     * Save finding (overloaded - without request/response)
     */
    public void saveFinding(String tabId, Finding finding) throws SQLException {
        saveFinding(tabId, finding, null, null);
    }

    /**
     * Save finding with request and response data
     */
    public void saveFinding(String tabId, Finding finding, String request, String response) throws SQLException {
        String sql = "INSERT INTO findings (tab_id, type, severity, confidence, " +
                    "description, evidence, exploitation, remediation, url, request, response) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        PreparedStatement stmt = connection.prepareStatement(sql);
        stmt.setString(1, tabId);
        stmt.setString(2, finding.getType());
        stmt.setString(3, finding.getSeverity());
        stmt.setDouble(4, finding.getConfidence());
        stmt.setString(5, finding.getDescription());
        stmt.setString(6, finding.getEvidence());
        stmt.setString(7, finding.getExploitation());
        stmt.setString(8, finding.getRemediation());
        stmt.setString(9, finding.getAffectedUrl());
        stmt.setString(10, truncate(request, 50000)); // Truncate large requests
        stmt.setString(11, truncate(response, 50000)); // Truncate large responses

        stmt.executeUpdate();
        stmt.close();
    }
    
    /**
     * Save to the findings table and return the generated row id (-1 on failure).
     * Unifies the store that getRecentFindings/getRecentFalsePositives (and thus the
     * RAG + learning loop) read from, and gives the UI an id to mark FP against.
     */
    public int saveFindingReturningId(String tabId, Finding finding, String request, String response) {
        String sql = "INSERT INTO findings (tab_id, type, severity, confidence, " +
                    "description, evidence, exploitation, remediation, url, request, response) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, tabId);
            stmt.setString(2, finding.getType());
            stmt.setString(3, finding.getSeverity());
            stmt.setDouble(4, finding.getConfidence());
            stmt.setString(5, finding.getDescription());
            stmt.setString(6, finding.getEvidence());
            stmt.setString(7, finding.getExploitation());
            stmt.setString(8, finding.getRemediation());
            stmt.setString(9, finding.getAffectedUrl());
            stmt.setString(10, truncate(request, 50000));
            stmt.setString(11, truncate(response, 50000));
            stmt.executeUpdate();
            try (ResultSet keys = stmt.getGeneratedKeys()) {
                if (keys.next()) return keys.getInt(1);
            }
        } catch (SQLException e) {
            // best-effort: return -1 below
        }
        return -1;
    }

    /**
     * Mark finding as false positive
     */
    public void markAsFalsePositive(int findingId, String reason) throws SQLException {
        String sql = "UPDATE findings SET is_false_positive = 1, fp_reason = ? WHERE id = ?";

        PreparedStatement stmt = connection.prepareStatement(sql);
        stmt.setString(1, reason != null ? reason : "");
        stmt.setInt(2, findingId);

        stmt.executeUpdate();
        stmt.close();
    }
    
    /**
     * Get scan statistics
     */
    public Map<String, Integer> getStatistics() throws SQLException {
        Map<String, Integer> stats = new HashMap<>();

        Statement stmt = connection.createStatement();

        ResultSet rs = stmt.executeQuery("SELECT COUNT(*) as total FROM scan_requests");
        if (rs.next()) stats.put("total_scans", rs.getInt("total"));

        rs = stmt.executeQuery("SELECT COUNT(*) as total FROM findings WHERE is_false_positive = 0");
        if (rs.next()) stats.put("total_findings", rs.getInt("total"));

        // Use LOWER() for case-insensitive matching
        rs = stmt.executeQuery("SELECT COUNT(*) as total FROM findings WHERE LOWER(severity) = 'critical' AND is_false_positive = 0");
        if (rs.next()) stats.put("critical", rs.getInt("total"));

        rs = stmt.executeQuery("SELECT COUNT(*) as total FROM findings WHERE LOWER(severity) = 'high' AND is_false_positive = 0");
        if (rs.next()) stats.put("high", rs.getInt("total"));

        // Also count medium and low for completeness
        rs = stmt.executeQuery("SELECT COUNT(*) as total FROM findings WHERE LOWER(severity) = 'medium' AND is_false_positive = 0");
        if (rs.next()) stats.put("medium", rs.getInt("total"));

        rs = stmt.executeQuery("SELECT COUNT(*) as total FROM findings WHERE LOWER(severity) = 'low' AND is_false_positive = 0");
        if (rs.next()) stats.put("low", rs.getInt("total"));

        stmt.close();

        return stats;
    }

    /**
     * Get recent findings
     */
    public List<Finding> getRecentFindings(int limit) throws SQLException {
        List<Finding> findings = new ArrayList<>();

        String sql = "SELECT * FROM findings WHERE is_false_positive = 0 " +
                    "ORDER BY timestamp DESC LIMIT ?";

        PreparedStatement stmt = connection.prepareStatement(sql);
        stmt.setInt(1, limit);

        ResultSet rs = stmt.executeQuery();
        while (rs.next()) {
            Finding finding = new Finding(
                rs.getString("type"),
                rs.getString("severity"),
                rs.getDouble("confidence"),
                rs.getString("description"),
                rs.getString("url") != null ? rs.getString("url") : "",
                rs.getString("evidence"),
                rs.getString("exploitation"),
                rs.getString("remediation")
            );
            finding.setHttpRequest(rs.getString("request"));
            finding.setHttpResponse(rs.getString("response"));
            findings.add(finding);
        }

        rs.close();
        stmt.close();

        return findings;
    }

    public List<Finding> getRecentFalsePositives(int limit) throws SQLException {
        List<Finding> findings = new ArrayList<>();

        String sql = "SELECT * FROM findings WHERE is_false_positive = 1 " +
                    "ORDER BY timestamp DESC LIMIT ?";

        PreparedStatement stmt = connection.prepareStatement(sql);
        stmt.setInt(1, limit);

        ResultSet rs = stmt.executeQuery();
        while (rs.next()) {
            Finding finding = new Finding(
                rs.getString("type"),
                rs.getString("severity"),
                rs.getDouble("confidence"),
                rs.getString("description"),
                rs.getString("url") != null ? rs.getString("url") : "",
                rs.getString("evidence"),
                rs.getString("exploitation"),
                rs.getString("remediation")
            );
            finding.setFalsePositive(true);
            finding.setHttpRequest(rs.getString("request"));
            finding.setHttpResponse(rs.getString("response"));
            findings.add(finding);
        }

        rs.close();
        stmt.close();

        return findings;
    }

    /**
     * Export session data
     */
    public String exportSessionData() throws Exception {
        JSONObject data = new JSONObject();
        
        // Export scan results
        JSONArray scans = new JSONArray();
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(
            "SELECT * FROM scan_requests ORDER BY timestamp DESC LIMIT 100"
        );
        
        while (rs.next()) {
            JSONObject scan = new JSONObject();
            scan.put("url", rs.getString("url"));
            scan.put("method", rs.getString("method"));
            scan.put("result", rs.getString("result"));
            scan.put("timestamp", rs.getString("timestamp"));
            scans.put(scan);
        }
        
        data.put("scans", scans);
        
        stmt.close();
        return data.toString();
    }
    
    /**
     * Save dynamic test finding
     */
    public void saveDynamicTestFinding(String url, String testType, String findingType,
                                      String severity, String description, String evidence,
                                      String exploitation, String remediation, long duration) {
        try {
            PreparedStatement pstmt = connection.prepareStatement(
                "INSERT INTO dynamic_test_results " +
                "(url, test_type, finding_type, severity, description, evidence, exploitation, remediation, duration) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            );

            pstmt.setString(1, truncate(url, 500));
            pstmt.setString(2, testType);
            pstmt.setString(3, findingType);
            pstmt.setString(4, severity);
            pstmt.setString(5, truncate(description, 10000));
            pstmt.setString(6, truncate(evidence, 10000));
            pstmt.setString(7, truncate(exploitation, 10000));
            pstmt.setString(8, truncate(remediation, 10000));
            pstmt.setLong(9, duration);

            pstmt.executeUpdate();
            pstmt.close();

        } catch (SQLException e) {
            System.err.println("Error saving dynamic test finding: " + e.getMessage());
        }
    }

    /**
     * Get recent dynamic test results
     */
    public List<Map<String, Object>> getRecentDynamicTests(int limit) {
        List<Map<String, Object>> results = new ArrayList<>();

        try {
            PreparedStatement pstmt = connection.prepareStatement(
                "SELECT * FROM dynamic_test_results " +
                "ORDER BY timestamp DESC LIMIT ?"
            );
            pstmt.setInt(1, limit);

            ResultSet rs = pstmt.executeQuery();

            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("id", rs.getInt("id"));
                row.put("url", rs.getString("url"));
                row.put("test_type", rs.getString("test_type"));
                row.put("finding_type", rs.getString("finding_type"));
                row.put("severity", rs.getString("severity"));
                row.put("description", rs.getString("description"));
                row.put("evidence", rs.getString("evidence"));
                row.put("exploitation", rs.getString("exploitation"));
                row.put("remediation", rs.getString("remediation"));
                row.put("duration", rs.getLong("duration"));
                row.put("timestamp", rs.getTimestamp("timestamp"));
                results.add(row);
            }

            rs.close();
            pstmt.close();

        } catch (SQLException e) {
            System.err.println("Error getting dynamic tests: " + e.getMessage());
        }

        return results;
    }

    /**
     * Get dynamic test statistics
     */
    public Map<String, Object> getDynamicTestStats() {
        Map<String, Object> stats = new HashMap<>();

        try {
            Statement stmt = connection.createStatement();

            // Total tests
            ResultSet rs = stmt.executeQuery(
                "SELECT COUNT(*) as total FROM dynamic_test_results"
            );
            if (rs.next()) {
                stats.put("total_tests", rs.getInt("total"));
            }
            rs.close();

            // By severity
            rs = stmt.executeQuery(
                "SELECT severity, COUNT(*) as count FROM dynamic_test_results " +
                "GROUP BY severity"
            );
            Map<String, Integer> bySeverity = new HashMap<>();
            while (rs.next()) {
                bySeverity.put(rs.getString("severity"), rs.getInt("count"));
            }
            stats.put("by_severity", bySeverity);
            rs.close();

            // By test type
            rs = stmt.executeQuery(
                "SELECT test_type, COUNT(*) as count FROM dynamic_test_results " +
                "GROUP BY test_type"
            );
            Map<String, Integer> byTestType = new HashMap<>();
            while (rs.next()) {
                byTestType.put(rs.getString("test_type"), rs.getInt("count"));
            }
            stats.put("by_test_type", byTestType);
            rs.close();

            stmt.close();

        } catch (SQLException e) {
            System.err.println("Error getting dynamic test stats: " + e.getMessage());
        }

        return stats;
    }

    /**
     * Clear all data from database (delete all records from all tables)
     */
    public void clearAllData() throws SQLException {
        Statement stmt = connection.createStatement();

        // Delete all records from each table
        stmt.execute("DELETE FROM findings");
        stmt.execute("DELETE FROM scan_requests");
        stmt.execute("DELETE FROM dynamic_test_results");
        stmt.execute("DELETE FROM conversations");

        // Reset auto-increment counters
        stmt.execute("DELETE FROM sqlite_sequence WHERE name IN ('findings', 'scan_requests', 'dynamic_test_results', 'conversations')");

        stmt.close();
    }

    /**
     * Close database
     */
    public void close() throws SQLException {
        synchronized (lock) {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        }
    }

    /**
     * Truncate string
     */
    private String truncate(String str, int maxLength) {
        if (str == null) return "";
        if (str.length() <= maxLength) return str;
        return str.substring(0, maxLength);
    }
}

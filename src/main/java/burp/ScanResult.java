package burp;

import org.json.*;
import java.util.*;

/**
 * ScanResult Model - Wrapper for scan results
 * 
 * @author Zahid Eroglu
 */
public class ScanResult {
    
    private List<Finding> findings;
    private String summary;
    private String rawResponse;
    
    public ScanResult(List<Finding> findings, String summary, String rawResponse) {
        this.findings = findings;
        this.summary = summary;
        this.rawResponse = rawResponse;
    }
    
    /**
     * Convert to JSON string
     */
    public String toJSON() {
        JSONObject json = new JSONObject();
        
        JSONArray findingsArray = new JSONArray();
        for (Finding finding : findings) {
            findingsArray.put(finding.toJSON());
        }
        
        json.put("findings", findingsArray);
        json.put("summary", summary);
        json.put("rawResponse", rawResponse);
        
        return json.toString();
    }
    
    /**
     * Create from JSON string
     */
    public static ScanResult fromJSON(String jsonString) {
        JSONObject json = new JSONObject(jsonString);
        
        List<Finding> findings = new ArrayList<>();
        JSONArray findingsArray = json.getJSONArray("findings");
        for (int i = 0; i < findingsArray.length(); i++) {
            findings.add(Finding.fromJSON(findingsArray.getJSONObject(i)));
        }
        
        return new ScanResult(
            findings,
            json.getString("summary"),
            json.optString("rawResponse", "")
        );
    }
    
    // Getters and Setters
    public List<Finding> getFindings() { return findings; }
    public void setFindings(List<Finding> findings) { this.findings = findings; }
    
    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }
    
    public String getRawResponse() { return rawResponse; }
    public void setRawResponse(String rawResponse) { this.rawResponse = rawResponse; }
    
    public int getFindingCount() {
        return findings.size();
    }
    
    public boolean hasVulnerabilities() {
        return !findings.isEmpty();
    }

    // Alias method for compatibility
    public String getResponse() { return summary; }
}

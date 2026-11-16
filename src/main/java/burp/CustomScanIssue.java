package burp;

import java.net.URL;

/**
 * Custom Scan Issue - Creates Burp Suite issues from findings
 * 
 * @author Zahid Eroglu
 */
public class CustomScanIssue implements IScanIssue {
    
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private Finding finding;
    private IExtensionHelpers helpers;
    
    public CustomScanIssue(IHttpService httpService, URL url, 
                          IHttpRequestResponse[] httpMessages,
                          Finding finding, IExtensionHelpers helpers) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.finding = finding;
        this.helpers = helpers;
    }
    
    @Override
    public URL getUrl() {
        return url;
    }
    
    @Override
    public String getIssueName() {
        return "[AI Scanner] " + finding.getType();
    }
    
    @Override
    public int getIssueType() {
        return 0; // Extension generated
    }
    
    @Override
    public String getSeverity() {
        String severity = finding.getEffectiveSeverity();

        // Map to Burp severity values
        switch (severity.toLowerCase()) {
            case "critical":
            case "high":
                return "High";
            case "medium":
                return "Medium";
            case "low":
                return "Low";
            default:
                return "Information";
        }
    }
    
    @Override
    public String getConfidence() {
        switch (finding.getConfidenceTier()) {
            case CONFIRMED: return "Certain";
            case FIRM:      return "Firm";
            default:        return "Tentative";
        }
    }
    
    @Override
    public String getIssueBackground() {
        return "<p>This vulnerability was detected by AI Security Scanner using Qwen AI model.</p>" +
               "<p>The scanner uses advanced AI to analyze HTTP traffic and identify security vulnerabilities.</p>";
    }
    
    @Override
    public String getRemediationBackground() {
        return null;
    }
    
    @Override
    public String getIssueDetail() {
        StringBuilder detail = new StringBuilder();

        detail.append("<p><b>").append(htmlEncode(finding.getType())).append("</b></p>");

        detail.append("<table>");
        detail.append("<tr>");
        detail.append("<td><b>Severity:</b></td><td><b>").append(htmlEncode(finding.getEffectiveSeverity().toUpperCase())).append("</b></td>");
        detail.append("<td>&nbsp;&nbsp;<b>CVSS Score:</b></td><td>").append(finding.getEffectiveCvss()).append("</td>");
        detail.append("</tr>");
        detail.append("<tr>");
        detail.append("<td><b>Priority:</b></td><td>").append(htmlEncode(finding.getPriority())).append("</td>");
        detail.append("<td>&nbsp;&nbsp;<b>Confidence:</b></td><td>").append(String.format("%.0f%%", finding.getConfidence() * 100)).append("</td>");
        detail.append("</tr>");
        detail.append("</table>");

        if (finding.getAffectedUrl() != null && !finding.getAffectedUrl().isEmpty()) {
            detail.append("<p><b>Affected URL:</b> ").append(htmlEncode(finding.getAffectedUrl())).append("</p>");
        }

        detail.append("<p><b>Description</b></p>");
        detail.append("<p>").append(htmlEncode(finding.getDescription())).append("</p>");

        if (finding.getEvidence() != null && !finding.getEvidence().isEmpty()) {
            detail.append("<p><b>Evidence</b></p>");
            detail.append("<pre>").append(htmlEncode(finding.getEvidence())).append("</pre>");
        }

        if (finding.getExploitation() != null && !finding.getExploitation().isEmpty()) {
            detail.append("<p><b>Exploitation</b></p>");
            detail.append("<p>").append(htmlEncode(finding.getExploitation())).append("</p>");
        }

        detail.append("<p><b>Classification</b></p>");
        detail.append("<table>");
        if (finding.getCweId() != null && !finding.getCweId().isEmpty()) {
            detail.append("<tr><td><b>CWE ID:</b></td><td>").append(htmlEncode(finding.getCweId())).append("</td></tr>");
        }
        if (finding.getOwaspCategory() != null && !finding.getOwaspCategory().isEmpty()) {
            detail.append("<tr><td><b>OWASP:</b></td><td>").append(htmlEncode(finding.getOwaspCategory())).append("</td></tr>");
        }
        detail.append("</table>");

        if (finding.getReferences() != null && !finding.getReferences().isEmpty()) {
            detail.append("<p><b>References</b></p>");
            detail.append("<ul>");
            for (String ref : finding.getReferences()) {
                detail.append("<li><a href='").append(htmlEncode(ref)).append("'>")
                      .append(htmlEncode(ref)).append("</a></li>");
            }
            detail.append("</ul>");
        }

        java.util.List<String> vsteps = finding.getVerificationSteps();
        if (vsteps != null && !vsteps.isEmpty()) {
            detail.append("<p><b>Verification Steps (confidence: ")
                  .append(finding.getConfidenceTier()).append(")</b></p>");
            detail.append("<ul>");
            for (String vs : vsteps) detail.append("<li>").append(htmlEncode(vs)).append("</li>");
            detail.append("</ul>");
        }

        return detail.toString();
    }

    @Override
    public String getRemediationDetail() {
        if (finding.getRemediation() == null || finding.getRemediation().isEmpty()) {
            return null;
        }

        StringBuilder remediation = new StringBuilder();
        remediation.append("<p><b>Remediation</b></p>");
        remediation.append("<p>").append(htmlEncode(finding.getRemediation())).append("</p>");

        if (finding.getReferences() != null && !finding.getReferences().isEmpty()) {
            remediation.append("<p><b>Additional Resources</b></p>");
            remediation.append("<ul>");
            for (String ref : finding.getReferences()) {
                remediation.append("<li><a href='").append(htmlEncode(ref)).append("'>")
                           .append(htmlEncode(ref)).append("</a></li>");
            }
            remediation.append("</ul>");
        }

        return remediation.toString();
    }
    
    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }
    
    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
    
    /**
     * HTML encode string
     */
    private String htmlEncode(String str) {
        if (str == null) return "";
        return str.replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace("\"", "&quot;")
                  .replace("'", "&#x27;")
                  .replace("\n", "<br>");
    }
}

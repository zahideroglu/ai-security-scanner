package burp;

import java.net.URL;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Filter Engine - Filters requests based on scope and exclusions
 * 
 * @author Zahid Eroglu
 */
public class FilterEngine {
    
    private IBurpExtenderCallbacks callbacks;
    private Settings settings;
    
    // Static file extensions
    private static final Set<String> STATIC_EXTENSIONS = new HashSet<>(Arrays.asList(
        ".js", ".mjs", ".css", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".avif",
        ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map", ".mp4", ".mp3", ".pdf", ".zip"
    ));
    
    // CDN patterns
    private static final List<Pattern> CDN_PATTERNS = Arrays.asList(
        Pattern.compile(".*cdn\\..*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*cloudflare\\..*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*cloudfront\\..*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*akamai\\..*", Pattern.CASE_INSENSITIVE)
    );
    
    // Analytics patterns
    private static final List<Pattern> ANALYTICS_PATTERNS = Arrays.asList(
        Pattern.compile(".*google-analytics\\..*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*googletagmanager\\..*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*hotjar\\..*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*mixpanel\\..*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*amplitude\\..*", Pattern.CASE_INSENSITIVE)
    );
    
    // Social media patterns
    private static final List<Pattern> SOCIAL_PATTERNS = Arrays.asList(
        Pattern.compile(".*facebook\\..*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*twitter\\..*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*linkedin\\..*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*instagram\\..*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*pinterest\\..*", Pattern.CASE_INSENSITIVE)
    );
    
    public FilterEngine(IBurpExtenderCallbacks callbacks, Settings settings) {
        this.callbacks = callbacks;
        this.settings = settings;
    }
    
    /**
     * Check if request should be scanned
     */
    public boolean shouldScan(IHttpRequestResponse message) {
        IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(message);
        URL url = requestInfo.getUrl();
        
        // Check scope
        if (settings.isUseBurpScope() && !callbacks.isInScope(url)) {
            return false;
        }
        
        // Check static files
        if (settings.isExcludeStatic() && isStaticFile(url)) {
            return false;
        }
        
        // Check CDN
        if (settings.isExcludeCDN() && isCDN(url)) {
            return false;
        }
        
        // Check analytics
        if (settings.isExcludeAnalytics() && isAnalytics(url)) {
            return false;
        }
        
        // Check social media
        if (settings.isExcludeSocial() && isSocialMedia(url)) {
            return false;
        }
        
        // Check OPTIONS
        if (settings.isExcludeOptions() && requestInfo.getMethod().equals("OPTIONS")) {
            return false;
        }
        
        // Check WebSocket
        if (settings.isExcludeWebSocket() && url.getProtocol().startsWith("ws")) {
            return false;
        }
        
        // Check custom exclusions
        if (matchesCustomExclusion(url)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Check if URL is a static file
     */
    private boolean isStaticFile(URL url) {
        String path = url.getPath().toLowerCase();
        for (String ext : STATIC_EXTENSIONS) {
            if (path.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if URL is from CDN
     */
    private boolean isCDN(URL url) {
        String host = url.getHost().toLowerCase();
        for (Pattern pattern : CDN_PATTERNS) {
            if (pattern.matcher(host).matches()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if URL is analytics
     */
    private boolean isAnalytics(URL url) {
        String host = url.getHost().toLowerCase();
        for (Pattern pattern : ANALYTICS_PATTERNS) {
            if (pattern.matcher(host).matches()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if URL is social media
     */
    private boolean isSocialMedia(URL url) {
        String host = url.getHost().toLowerCase();
        for (Pattern pattern : SOCIAL_PATTERNS) {
            if (pattern.matcher(host).matches()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check custom exclusions
     */
    private boolean matchesCustomExclusion(URL url) {
        String path = url.getPath();
        List<String> exclusions = settings.getCustomExclusions();
        
        if (exclusions == null || exclusions.isEmpty()) {
            return false;
        }
        
        for (String exclusion : exclusions) {
            if (path.contains(exclusion)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Update settings
     */
    public void updateSettings(Settings settings) {
        this.settings = settings;
    }
}

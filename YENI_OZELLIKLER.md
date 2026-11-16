# 🎯 Yeni Özellikler - AI Security Scanner v2.0

## 📋 İçindekiler

1. [AI-Powered Exploit Generator (PoC Creator)](#1-ai-powered-exploit-generator-poc-creator)
2. [AI Report Generator](#2-ai-report-generator)
3. [Smart Retest System](#3-smart-retest-system)
4. [AI Fuzzing Engine](#4-ai-fuzzing-engine)
5. [Multi-Session Testing](#5-multi-session-testing)

---

## 1. 🎯 AI-Powered Exploit Generator (PoC Creator)

### Ne İşe Yarar?
Bulunan her zafiyet için otomatik olarak profesyonel exploit kodu üretir. Artık manuel olarak exploit yazmaya gerek yok!

### Özellikler
- ✅ **Python Exploit Script**: Çalışır durumda Python exploit kodu
- ✅ **cURL Commands**: Kopyala-yapıştır cURL komutları
- ✅ **Burp Suite Repeater Template**: Direkt Burp Repeater'a import edilebilir
- ✅ **Executive Summary**: Yöneticiler için özet
- ✅ **Impact Analysis**: CVSS skorları ve etki analizi
- ✅ **Remediation Steps**: Düzeltme önerileri

### Nasıl Kullanılır?

#### Otomatik Kullanım
Extension zaten bir zafiyet bulduğunda otomatik olarak PoC üretir. Findings panel'inde zafiyet detaylarını görebilirsiniz.

#### Manuel Kullanım (Kod İçinden)
```java
// Finding nesnesi ve request'i kullanarak PoC üret
String poc = PoCGenerator.generatePoC(finding, requestResponse, helpers);
System.out.println(poc);
```

### Örnek Çıktı
```markdown
# 🤖 AI-Generated PoC

## Executive Summary
SQL Injection vulnerability allows attackers to manipulate database queries...

## Python Exploit Script
```python
import requests

url = "https://target.com/api/users"
payload = {"user_id": "1' OR '1'='1"}
response = requests.post(url, json=payload)
print(response.text)
```

## cURL Command
```bash
curl -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"1' OR '1'='1"}'
```

## 🔄 Burp Suite Repeater Template
[Raw HTTP request here...]
```

---

## 2. 📊 AI Report Generator

### Ne İşe Yarar?
Tüm bulguları profesyonel bir pentest raporuna dönüştürür. Saatlerce süren rapor yazma işini dakikalara indirir!

### Özellikler
- ✅ **Executive Summary**: AI tarafından oluşturulan yönetici özeti
- ✅ **Methodology**: Test metodolojisi
- ✅ **Findings Summary**: Zafiyet özeti ve istatistikler
- ✅ **Detailed Findings**: Her zafiyet için detaylı açıklama
- ✅ **Risk Assessment Matrix**: Risk matrisi
- ✅ **Remediation Roadmap**: Düzeltme yol haritası
- ✅ **Multiple Formats**: Markdown, HTML, PDF desteği

### Nasıl Kullanılır?

```java
// Report Generator oluştur
AIReportGenerator reportGen = new AIReportGenerator(
    aiClient,
    databaseManager,
    stdout,
    stderr
);

// Bulguları topla
List<Finding> findings = getAllFindings();

// Report options ayarla
AIReportGenerator.ReportOptions options = new AIReportGenerator.ReportOptions();
options.targetName = "Example Corp Web Application";
options.assessorName = "Zahid Eroglu";
options.outputPath = "/path/to/report";
options.format = "html"; // markdown, html, pdf

// Rapor üret
String reportPath = reportGen.generateReport(findings, options);
System.out.println("Report saved to: " + reportPath);
```

### Rapor Formatları

#### 1. Markdown (.md)
```java
options.format = "markdown";
```
- GitHub, GitLab gibi platformlarda görüntüleme
- Version control ile takip

#### 2. HTML (.html)
```java
options.format = "html";
```
- Web tarayıcısında görüntüleme
- Print-friendly CSS
- "Print to PDF" ile PDF'e çevirme

#### 3. PDF (.pdf)
```java
options.format = "pdf";
```
- Şu an HTML olarak kaydeder (tarayıcıdan PDF'e çevirebilirsiniz)
- Gelecek sürümde direkt PDF desteği gelecek

### Rapor Bölümleri

1. **Title Page**: Hedef, tarih, hazırlayan
2. **Executive Summary**: AI tarafından oluşturulan özet
3. **Methodology**: Test yaklaşımı
4. **Findings Summary**: Tablo ve grafikler
5. **Detailed Findings**: Her bulgu için:
   - Description
   - Evidence
   - Exploitation
   - Business Impact
   - CVSS Score
   - Remediation
6. **Risk Assessment Matrix**: Görsel risk matrisi
7. **Remediation Roadmap**: Önceliklendirilmiş düzeltme planı
8. **Appendix**: Referanslar ve kaynaklar

---

## 3. 🔄 Smart Retest System

### Ne İşe Yarar?
Düzeltilen zafiyetleri otomatik olarak re-test eder. Developer'ın düzeltmesi gerçekten işe yaradı mı? AI kontrol eder!

### Workflow

```
1. Zafiyet bulundu → Finding oluşturuldu
2. Developer düzeltti → "Mark for Retest" butonu
3. Pentester → "Retest" butonu
4. AI → Aynı testi tekrar çalıştırır
5. Sonuç → ✅ "Fixed" veya ❌ "Still Vulnerable"
```

### Nasıl Kullanılır?

#### 1. Retest Manager Oluştur
```java
RetestManager retestManager = new RetestManager(
    callbacks,
    helpers,
    aiClient,
    dbManager,
    stdout,
    stderr
);
```

#### 2. Zafiyet için Retest İşaretle
```java
// Finding ve original request'i kullanarak retest işaretle
String retestId = retestManager.markForRetest(
    finding,
    originalRequest,
    "Developer claims SQL injection fixed"
);

System.out.println("Retest ID: " + retestId);
```

#### 3. Retest Çalıştır
```java
// Tek bir retest
RetestResult result = retestManager.executeRetest(retestId);

if (result.stillVulnerable) {
    System.out.println("❌ Still vulnerable!");
} else {
    System.out.println("✅ Fixed!");
}
```

#### 4. Toplu Retest (Bulk Retest)
```java
// Bekleyen tüm retestleri çalıştır
Map<String, RetestResult> results = retestManager.executeBulkRetest();

// Sonuçları göster
for (RetestResult result : results.values()) {
    System.out.println(result.finding.getType() + ": " + result.status);
}
```

#### 5. Retest İstatistikleri
```java
RetestStatistics stats = retestManager.getStatistics();
System.out.println("Total: " + stats.totalItems);
System.out.println("Fixed: " + stats.fixed);
System.out.println("Still Vulnerable: " + stats.stillVulnerable);
System.out.println("Pending: " + stats.pending);
System.out.println("Fix Rate: " + stats.getFixRate() + "%");
```

#### 6. Retest Raporu Oluştur
```java
String report = retestManager.generateRetestReport();
System.out.println(report);
```

### AI Analiz
Retest sırasında AI:
- Response'daki hata mesajlarını analiz eder
- Payload'ın hala yansıtılıp yansıtılmadığını kontrol eder
- Güvenlik kontrollerinin düzgün çalışıp çalışmadığını değerlendirir
- Bypass yollarını arar

---

## 4. 🧪 AI Fuzzing Engine

### Ne İşe Yarar?
Her parametre için context-aware (bağlam farkında) fuzzing payloadları üretir. Artık "blind" fuzzing değil, **intelligent fuzzing**!

### Özellikler
- ✅ **Context Detection**: Parametre tipini otomatik tespit eder
- ✅ **AI Payload Generation**: Her context için özel payloadlar
- ✅ **Backend Detection**: PHP, Java, Python, Node.js tespiti
- ✅ **Database Detection**: MySQL, PostgreSQL, MongoDB, MSSQL tespiti
- ✅ **Smart Injection**: Payload'ları parametre formatına uygun şekilde enjekte eder

### Context Types
- `email`: Email parametreleri
- `url`: URL parametreleri
- `id`: Numeric ID'ler
- `xml`: XML içeriği
- `json`: JSON içeriği
- `file`: Dosya yolları
- `command`: Komut parametreleri
- `search`: Arama sorguları

### Nasıl Kullanılır?

#### 1. Fuzzing Engine Oluştur
```java
AIFuzzingEngine fuzzEngine = new AIFuzzingEngine(
    callbacks,
    helpers,
    aiClient,
    stdout,
    stderr
);
```

#### 2. Smart Payloadlar Üret
```java
// Parametre için payloadlar üret
List<FuzzPayload> payloads = fuzzEngine.generateSmartPayloads(
    baseRequest,
    "email"  // parameter name
);

System.out.println("Generated " + payloads.size() + " payloads");

// Payload'ları göster
for (FuzzPayload payload : payloads) {
    System.out.println("[" + payload.type + "] " + payload.payload);
}
```

#### 3. Fuzzing Çalıştır
```java
// Payloadları kullanarak fuzzing yap
List<FuzzResult> results = fuzzEngine.executeFuzzing(
    baseRequest,
    "email",
    payloads
);

// İlginç sonuçları göster
for (FuzzResult result : results) {
    if (result.isInteresting) {
        System.out.println("🎯 INTERESTING: " + result.reason);
        System.out.println("    Payload: " + result.payload.payload);
        System.out.println("    Status: " + result.statusCode);
        System.out.println("    Duration: " + result.duration + "ms");
    }
}
```

### Örnek: Email Parametresi Fuzzing

Parametre: `email=user@example.com`

**AI Context Analysis:**
```
Type: email
Format: email
Backend: PHP
Database: MySQL
```

**Generated Payloads:**
```
[XSS] test@example.com<script>alert(1)</script>
[SQL] admin'@'example.com
[SSTI] {{7*7}}@example.com
[SSRF] test@169.254.169.254
[CMD] test@example.com;whoami
[XSS] <img src=x onerror=alert(1)>@test.com
[SQL] test@example.com' OR '1'='1
[NoSQL] test@example.com{"$gt": ""}
```

### Örnek: ID Parametresi Fuzzing

Parametre: `user_id=123`

**AI Context Analysis:**
```
Type: id
Format: numeric
Backend: Java
Database: PostgreSQL
```

**Generated Payloads:**
```
[SQL] 1' OR '1'='1
[SQL] 1' UNION SELECT NULL--
[IDOR] 124
[IDOR] 122
[SQL] 1'; DROP TABLE users--
[Auth] -1
[Auth] 0
[SQL] 1' AND '1'='1
```

---

## 5. 🎭 Multi-Session Testing (Role-Based)

### Ne İşe Yarar?
Farklı kullanıcı rolleriyle otomatik authorization testi yapar. IDOR, privilege escalation gibi authorization buglarını bulur!

### Test Tipleri

1. **Cross-User IDOR**: User A'nın kaynağına User B erişebiliyor mu?
2. **Privilege Escalation**: Normal user admin endpoint'e erişebiliyor mu?
3. **Horizontal Authorization Bypass**: Aynı seviye kullanıcılar birbirinin verisine erişebiliyor mu?
4. **Vertical Authorization Bypass**: Authentication olmadan protected endpoint'e erişilebiliyor mu?
5. **Session Fixation**: Session fixation zafiyeti var mı?

### Nasıl Kullanılır?

#### 1. Multi-Session Tester Oluştur
```java
MultiSessionTester sessionTester = new MultiSessionTester(
    callbacks,
    helpers,
    aiClient,
    stdout,
    stderr
);
```

#### 2. Session'ları Ekle

**Manuel Olarak:**
```java
// Admin session
Map<String, String> adminTokens = new HashMap<>();
adminTokens.put("Cookie", "session_id=admin_abc123; role=admin");
adminTokens.put("Authorization", "Bearer eyJhbGc...");

String adminSessionId = sessionTester.addSession(
    "Admin",
    "Administrator account",
    adminTokens
);

// Normal user session
Map<String, String> userTokens = new HashMap<>();
userTokens.put("Cookie", "session_id=user_xyz789; role=user");

String userSessionId = sessionTester.addSession(
    "Normal User",
    "Regular user account",
    userTokens
);

// Guest session
Map<String, String> guestTokens = new HashMap<>();
guestTokens.put("Cookie", "session_id=guest_def456");

String guestSessionId = sessionTester.addSession(
    "Guest",
    "Guest account",
    guestTokens
);
```

**Request'ten Otomatik:**
```java
// Request'ten tokenları otomatik çıkar
String sessionId = sessionTester.addSessionFromRequest(
    "Admin",
    "Admin session from intercepted request",
    adminRequest  // IHttpRequestResponse
);
```

#### 3. Multi-Session Test Çalıştır
```java
// Tüm testleri çalıştır
List<SessionTestResult> results = sessionTester.executeMultiSessionTest(baseRequest);

// Sonuçları göster
for (SessionTestResult result : results) {
    if (result.vulnerable) {
        System.out.println("🔴 VULNERABILITY FOUND!");
        System.out.println("    Test: " + result.testType);
        System.out.println("    Severity: " + result.severity);
        System.out.println("    Evidence: " + result.evidence);
        System.out.println("    Remediation: " + result.remediation);
    }
}
```

### Örnek Senaryolar

#### Senaryo 1: IDOR Testi
```
Original Request: GET /api/users/123
Session: User A (ID: 123)

Test:
1. User B ile aynı endpoint'i test et
2. Response'u karşılaştır
3. User B, User A'nın verisini görebiliyor mu?

Result: ❌ VULNERABLE - User B can access User A's data
```

#### Senaryo 2: Privilege Escalation
```
Original Request: GET /admin/users/delete/123
Session: Admin

Test:
1. Normal user ile aynı endpoint'i test et
2. Status code kontrol et
3. Normal user admin endpoint'e erişebiliyor mu?

Result: ✅ SECURE - Normal user gets 403 Forbidden
```

#### Senaryo 3: Vertical Authorization Bypass
```
Original Request: GET /api/profile
Session: Authenticated User

Test:
1. Tüm auth tokenları kaldır
2. Request'i unauthenticated olarak gönder
3. Protected endpoint'e erişilebiliyor mu?

Result: ❌ VULNERABLE - Authentication not enforced
```

### Burp Suite Context Menu'den Kullanım

Extension, Burp Suite'e sağ tık menüsü ekler:

1. **"🎭 Multi-Session Test"**: Otomatik çoklu session testi
2. **"Add Session from Request"**: Request'ten session ekle
3. **"Manage Sessions"**: Session'ları yönet

---

## 🚀 Hızlı Başlangıç

### 1. Extension'ı Yükle
```bash
cd /Users/administrator/Downloads/Burp\ exteniton/ai-security-scanner
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.8.0_241.jdk/Contents/Home
./gradlew build
```

Extension JAR: `build/libs/ai-security-scanner.jar`

### 2. Burp Suite'e Ekle
1. Burp Suite → Extender → Extensions
2. Add → Select File → `ai-security-scanner.jar`
3. ✅ Extension yüklendi!

### 3. API Key Ayarla
1. AppSecHunter tab → Settings
2. API URL ve API Key gir
3. Test Connection

### 4. İlk Tarama
1. Proxy'den bir request yakala
2. Sağ tık → "🔍 Scan with AppSecHunter"
3. Sonuçları "Findings" sekmesinde gör

---

## 📝 Kod Örnekleri

### Tüm Özellikleri Birlikte Kullanma

```java
// 1. Normal tarama yap
scanManager.scanRequest(requestResponse);

// 2. Zafiyetler bulundu, exploit üret
for (Finding finding : findings) {
    String poc = PoCGenerator.generatePoC(finding, requestResponse, helpers);
    System.out.println(poc);
}

// 3. Fuzzing yap
AIFuzzingEngine fuzzEngine = new AIFuzzingEngine(callbacks, helpers, aiClient, stdout, stderr);
List<FuzzPayload> payloads = fuzzEngine.generateSmartPayloads(requestResponse, "email");
List<FuzzResult> fuzzResults = fuzzEngine.executeFuzzing(requestResponse, "email", payloads);

// 4. Multi-session test
MultiSessionTester sessionTester = new MultiSessionTester(callbacks, helpers, aiClient, stdout, stderr);
sessionTester.addSessionFromRequest("Admin", "Admin session", adminRequest);
sessionTester.addSessionFromRequest("User", "User session", userRequest);
List<SessionTestResult> sessionResults = sessionTester.executeMultiSessionTest(requestResponse);

// 5. Retest için işaretle
RetestManager retestManager = new RetestManager(callbacks, helpers, aiClient, dbManager, stdout, stderr);
for (Finding finding : findings) {
    String retestId = retestManager.markForRetest(finding, requestResponse, "Needs verification");
}

// 6. Rapor oluştur
AIReportGenerator reportGen = new AIReportGenerator(aiClient, dbManager, stdout, stderr);
AIReportGenerator.ReportOptions options = new AIReportGenerator.ReportOptions(
    "My Web App",
    "Zahid Eroglu",
    "/tmp/security_report",
    "html"
);
String reportPath = reportGen.generateReport(findings, options);

System.out.println("Report saved: " + reportPath);
```

---

## 🎯 En İyi Pratikler

### 1. PoC Generator
- ✅ Her zafiyeti bulduğunda otomatik PoC üret
- ✅ PoC'yi Burp Repeater'da test et
- ✅ Client'a sunmadan önce doğrula

### 2. Report Generator
- ✅ Test sonunda her zaman rapor üret
- ✅ Executive Summary'yi client seviyesine göre özelleştir
- ✅ HTML formatını tercih et (PDF'e kolay çevrilir)

### 3. Retest System
- ✅ Her critical/high bulguyu retest için işaretle
- ✅ Developer düzeltmeden sonra hemen retest yap
- ✅ Retest sonuçlarını dokümante et

### 4. Fuzzing Engine
- ✅ Her önemli parametreyi fuzzla
- ✅ Context-aware payloadları kullan
- ✅ İlginç sonuçları manuel olarak doğrula

### 5. Multi-Session Testing
- ✅ En az 2-3 farklı role ile test yap
- ✅ Admin, User, Guest session'larını hazırla
- ✅ Her endpoint'i multi-session ile test et

---

## 🐛 Sorun Giderme

### Build Hataları
```bash
# JDK 8 kullandığınızdan emin olun
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.8.0_241.jdk/Contents/Home
./gradlew clean build
```

### AI API Bağlantı Hataları
- API URL'yi kontrol et
- API Key'i doğrula
- Network bağlantısını test et

### Extension Yüklenmiyor
- Burp Suite versiyonunu kontrol et (2.x gerekli)
- Extension output'u kontrol et (Extender → Errors)
- JAR dosyasının doğru yerde olduğunu kontrol et

---

## 📞 Destek

**Yazar**: Zahid Eroglu
**Version**: 2.0
**License**: MIT

### Sorularınız için:
1. GitHub Issues açın
2. Extension output'u paylaşın (Extender → Output)
3. Hatanın tekrar üretilme adımlarını yazın

---

## 🔥 Gelecek Özellikler (Roadmap)

- [ ] AI Security Co-Pilot (Chat Interface)
- [ ] AI Chain Attack Generator
- [ ] API Discovery & Analysis
- [ ] Subdomain & Asset Discovery
- [ ] Visual Bug Detector
- [ ] WAF Rule Generator
- [ ] Compliance Checker (OWASP/PCI-DSS/GDPR)
- [ ] Training Mode (CTF-Style)

---

**Happy Hacking! 🎯**

*"Bu extension pentester'ların işini %80 hızlandırır!" - Zahid Eroglu*

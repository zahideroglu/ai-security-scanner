# 🚀 Yeni Özellikler v3.0 - Kullanım Kılavuzu

## 📋 İçindekiler

1. [API Chain Attack Detector](#1-api-chain-attack-detector)
2. [Compliance Checker (OWASP, PCI-DSS, GDPR, HIPAA, SOC2)](#2-compliance-checker)
3. [AI Security Co-Pilot (Geliştirilmiş)](#3-ai-security-co-pilot)
4. [Passive Reconnaissance Engine](#4-passive-reconnaissance-engine)
5. [Mobile API Security Module](#5-mobile-api-security-module)
6. [Hızlı Başlangıç](#hızlı-başlangıç)
7. [Kod Örnekleri](#kod-örnekleri)

---

## 1. API Chain Attack Detector

### 🎯 Ne İşe Yarar?

API endpoint'leri arasındaki mantıksal bağlantıları tespit edip, chain attack senaryoları oluşturur. Modern web uygulamalarındaki en tehlikeli ve gözden kaçan zafiyet tiplerini bulur.

### ⛓️ Tespit Edilen Chain Türleri

1. **User Registration → Privilege Escalation**
   - Kullanıcı oluştur → Email doğrulamayı atla → Admin yetkisi al

2. **Shopping Cart → Price Manipulation**
   - Ürün ekle → Discount kodu kötüye kullan → Fiyat manipüle et

3. **Password Reset → Account Takeover**
   - Şifre sıfırlama iste → Token tahmin et/yeniden kullan → Hesap ele geçir

4. **IDOR → Admin Access**
   - IDOR bul → Kullanıcı ID'leri say → Admin bulaştır

5. **API Key Leak → Data Exfiltration**
   - API key sızdır → Yetkisiz erişim → Veri çal

### 💻 Kullanım

#### Java Kodu İle

```java
// 1. Chain Attack Detector oluştur
ChainAttackDetector chainDetector = new ChainAttackDetector(
    callbacks,
    helpers,
    stdout,
    stderr
);

// 2. HTTP trafiğini analiz et (her request için)
for (IHttpRequestResponse request : trafficHistory) {
    chainDetector.analyzeEndpoint(request);
}

// 3. Attack chain'leri keşfet
List<ChainAttackDetector.APIChain> chains = chainDetector.discoverChains();

// 4. Sonuçları göster
stdout.println("✅ Bulunan Chain'ler: " + chains.size());
for (ChainAttackDetector.APIChain chain : chains) {
    stdout.println("\n🔗 " + chain.name);
    stdout.println("   Severity: " + chain.severity);
    stdout.println("   Steps: " + chain.steps.size());
    stdout.println("   Scenario:\n" + chain.attackScenario);
}

// 5. Bir chain'i çalıştır (execute)
if (!chains.isEmpty()) {
    ChainAttackDetector.APIChain chain = chains.get(0);
    ChainAttackDetector.ChainAttackResult result = chainDetector.executeChain(chain);

    if (result.successful) {
        stdout.println("⚠️ ZAFIYET DOĞRULANDI!");
        stdout.println("Impact: " + result.impact);
        stdout.println("Remediation: " + result.remediation);
    }
}
```

#### Burp Context Menu'den

```
1. Proxy History'den birkaç request seç (en az 5-10 request)
2. Sağ tık → "🔗 Discover Attack Chains"
3. Extension output'u kontrol et
4. Bulunan chain'leri görüntüle ve execute et
```

### 📊 Çıktı Örneği

```
============================================
🔗 Chain: User Registration → Privilege Escalation
============================================
Severity: Critical
Steps: 3

Attack Scenario:
1. Create new user account
2. Skip or bypass email verification
3. Modify role parameter to gain admin privileges
4. Access admin endpoints

Impact:
Attacker can create admin accounts without verification,
leading to full application compromise

Remediation:
1. Enforce mandatory email verification before account activation
2. Never accept role/privilege parameters from client
3. Implement server-side role assignment logic
4. Add rate limiting on registration endpoints
```

---

## 2. Compliance Checker

### 🎯 Ne İşe Yarar?

Uygulamanızı OWASP Top 10, PCI-DSS, GDPR, HIPAA ve SOC2 standartlarına göre değerlendirir. Compliance gap analysis yapar.

### ✅ Desteklenen Standartlar

- **OWASP Top 10 2021**: A01-A10 tüm kategoriler
- **PCI-DSS**: Payment Card Industry standartları
- **GDPR**: Veri koruma ve gizlilik
- **HIPAA**: Sağlık verisi güvenliği
- **SOC2**: Güvenlik, availability, confidentiality

### 💻 Kullanım

```java
// 1. Compliance Checker oluştur
ComplianceChecker complianceChecker = new ComplianceChecker(
    callbacks,
    helpers,
    stdout,
    stderr
);

// 2. HTTP trafiğini topla
List<IHttpRequestResponse> traffic = new ArrayList<>();
// ... traffic'i doldur (Proxy history, Scanner sonuçları, vs)

// 3. Compliance check çalıştır
ComplianceChecker.ComplianceReport report = complianceChecker.runComplianceCheck(
    ComplianceChecker.Standard.OWASP_TOP10,
    traffic
);

// 4. Sonuçları göster
stdout.println("\n========== COMPLIANCE REPORT ==========");
stdout.println("Standard: " + report.standard);
stdout.println("Score: " + String.format("%.1f%%", report.complianceScore));
stdout.println("Level: " + report.getComplianceLevel());
stdout.println("\nSummary:");
stdout.println("  ✅ Passed: " + report.passed);
stdout.println("  ❌ Failed: " + report.failed);
stdout.println("  ⚠️ Partial: " + report.partial);
stdout.println("  ⏭️ Not Tested: " + report.notTested);

stdout.println("\n========== DETAILED FINDINGS ==========");
for (ComplianceChecker.ComplianceCheck check : report.checks) {
    if (check.status.equals("FAIL") || check.status.equals("PARTIAL")) {
        stdout.println("\n❌ " + check.requirement);
        stdout.println("   Status: " + check.status);
        stdout.println("   Severity: " + check.severity);
        stdout.println("   Evidence: " + check.evidence);
        stdout.println("   Remediation:\n" + check.remediation);
    }
}
```

### 📊 Örnek Rapor

```
========== COMPLIANCE REPORT ==========
Standard: OWASP_TOP10
Score: 72.5%
Level: Good

Summary:
  ✅ Passed: 5
  ❌ Failed: 2
  ⚠️ Partial: 3
  ⏭️ Not Tested: 0

========== DETAILED FINDINGS ==========

❌ A01:2021 - Broken Access Control
   Status: FAIL
   Severity: Critical
   Evidence: 15 endpoints lack proper access control
   Remediation:
   1. Implement proper authorization checks on all sensitive endpoints
   2. Use random, unpredictable identifiers (UUIDs)
   3. Verify user permissions before returning data

⚠️ A02:2021 - Cryptographic Failures
   Status: PARTIAL
   Severity: Critical
   Evidence: 3 requests use unencrypted HTTP
   Remediation:
   1. Use TLS 1.2+ for all communications
   2. Encrypt sensitive data at rest
```

### 🔄 Tüm Standartları Kontrol Et

```java
// Her standart için check yap
for (ComplianceChecker.Standard standard : ComplianceChecker.Standard.values()) {
    ComplianceChecker.ComplianceReport report =
        complianceChecker.runComplianceCheck(standard, traffic);

    stdout.println(standard + ": " +
        String.format("%.1f%%", report.complianceScore) +
        " (" + report.getComplianceLevel() + ")");
}
```

---

## 3. AI Security Co-Pilot

### 🎯 Ne İşe Yarar?

ChatGPT-style konuşma arayüzü ile akıllı güvenlik testi asistanı. Doğal dilde komutları anlar ve context-aware yanıtlar verir.

### 🤖 Desteklenen İntentler

1. **SCAN_REQUEST**: "Test this endpoint for SQLi"
2. **ANALYSIS_REQUEST**: "Analyze this response"
3. **EXPLOITATION**: "Generate PoC exploit"
4. **REMEDIATION**: "How to fix XSS?"
5. **CHAIN_ATTACK**: "Find attack chains"
6. **COMPLIANCE_CHECK**: "Check OWASP compliance"
7. **PASSIVE_RECON**: "What technology is this?"
8. **MOBILE_TEST**: "Test mobile API"
9. **REPORT_REQUEST**: "Generate report"
10. **QUESTION**: "What is CSRF?"

### 💻 Kullanım

```java
// 1. AI Co-Pilot oluştur
AISecurityCoPilot copilot = new AISecurityCoPilot(
    callbacks,
    helpers,
    qwenClient,
    stdout,
    stderr
);

// 2. Kullanıcı mesajını işle
String userMessage = "Test this endpoint for SQL injection";
IHttpRequestResponse currentRequest = getSelectedRequest();

AISecurityCoPilot.CoPilotResponse response = copilot.chat(
    userMessage,
    currentRequest
);

// 3. Yanıtı göster
stdout.println("\n🤖 AI Co-Pilot:");
stdout.println(response.message);

// 4. Önerilen aksiyonlar
if (!response.suggestedActions.isEmpty()) {
    stdout.println("\n💡 Suggested Actions:");
    for (String action : response.suggestedActions) {
        stdout.println("  • " + action);
    }
}

// 5. Hızlı yanıtlar (Quick Replies)
if (!response.quickReplies.isEmpty()) {
    stdout.println("\n⚡ Quick Replies:");
    for (String reply : response.quickReplies) {
        stdout.println("  • " + reply);
    }
}

// 6. Aksiyonları çalıştır
for (String action : response.suggestedActions) {
    if (action.startsWith("start_scan:")) {
        String testType = action.substring("start_scan:".length());
        // Taramayı başlat
    } else if (action.equals("generate_poc")) {
        // PoC üret
    } else if (action.equals("discover_chains")) {
        // Chain discovery başlat
    }
}
```

### 💬 Örnek Konuşmalar

#### Örnek 1: Zafiyet Testi

```
User: Test this endpoint for SQL injection and XSS

🤖 AI Co-Pilot:
🔍 I'll test this endpoint for vulnerabilities. Let me analyze...

📋 Test Plan:
• Focus: SQL Injection, XSS
• Comprehensive security scan
• Including: Parameter fuzzing, header injection

⏳ Starting scan...

💡 Suggested Actions:
  • start_scan:SQLi_XSS

⚡ Quick Replies:
  • Also test for SSRF
  • Check authorization too
  • Run full test suite
```

#### Örnek 2: Soru-Cevap

```
User: What is CSRF and how do I test for it?

🤖 AI Co-Pilot:
CSRF (Cross-Site Request Forgery) is an attack that forces users to execute
unwanted actions on a web application where they're authenticated.

🎯 How it works:
1. Victim logs into vulnerable site
2. Attacker tricks victim into visiting malicious site
3. Malicious site sends forged request to vulnerable site
4. Request executes using victim's credentials

🔍 How to test:
1. Find state-changing operations (POST, PUT, DELETE)
2. Remove anti-CSRF tokens
3. Try request from different origin
4. Check if operation succeeds

⚡ Quick Replies:
  • Show me an example
  • Test current request for CSRF
  • How to fix CSRF?
```

#### Örnek 3: Chain Attack Discovery

```
User: Find attack chains in this API

🤖 AI Co-Pilot:
⛓️ I'll discover attack chains in the API.

🔍 Analyzing endpoint relationships...

I'll look for:
• User Registration → Privilege Escalation chains
• Cart → Price Manipulation chains
• Password Reset → Account Takeover chains
• IDOR → Admin Access chains
• Token Leak → Data Exfiltration chains

⏳ Starting chain discovery...

💡 Suggested Actions:
  • discover_chains

⚡ Quick Replies:
  • Show discovered chains
  • Execute chain attack
  • Explain chain risks
```

---

## 4. Passive Reconnaissance Engine

### 🎯 Ne İşe Yarar?

Ek request göndermeden, sadece mevcut HTTP trafiğini analiz ederek:
- Teknoloji stack tespiti
- Güvenlik header kontrolü
- API key/secret sızdırması
- CVE taraması
- 3rd-party servis tespiti

### 🔍 Tespit Edilen Bilgiler

- **Technology Stack**: Web server, framework, CMS, libraries
- **Security Headers**: CSP, HSTS, X-Frame-Options, vb.
- **Cookies**: HttpOnly, Secure, SameSite kontrolü
- **Sensitive Data**: API keys, emails, paths
- **Third-party Services**: Analytics, CDN, social media
- **Cloud Provider**: AWS, Azure, GCP
- **Known Vulnerabilities**: Version bazlı CVE matching

### 💻 Kullanım

```java
// 1. Recon Engine oluştur
PassiveReconEngine reconEngine = new PassiveReconEngine(
    callbacks,
    helpers,
    stdout,
    stderr
);

// 2. Request'i analiz et
IHttpRequestResponse request = getSelectedRequest();
PassiveReconEngine.ReconResult result = reconEngine.analyze(request);

// 3. Sonuçları göster
stdout.println("\n========== PASSIVE RECONNAISSANCE ==========");
stdout.println("Target: " + result.targetUrl);
stdout.println("Scan Date: " + result.scanDate);

// Technology Stack
stdout.println("\n🖥️ Technology Stack:");
if (result.webServer != null) {
    stdout.println("  Web Server: " + result.webServer);
}
if (result.programmingLanguage != null) {
    stdout.println("  Language: " + result.programmingLanguage);
}
if (!result.frameworks.isEmpty()) {
    stdout.println("  Frameworks: " + String.join(", ", result.frameworks));
}
if (result.cloudProvider != null) {
    stdout.println("  Cloud: " + result.cloudProvider);
}
if (result.cdn != null) {
    stdout.println("  CDN: " + result.cdn);
}

// Security Headers
stdout.println("\n🛡️ Security Headers:");
stdout.println("  Present: " + result.securityHeaders.size());
stdout.println("  Missing: " + result.missingHeaders.size());
for (String missing : result.missingHeaders) {
    stdout.println("    ⚠️ " + missing);
}

// Exposed Information
if (!result.apiKeys.isEmpty()) {
    stdout.println("\n🔑 CRITICAL - API Keys Exposed:");
    for (String key : result.apiKeys) {
        stdout.println("    🚨 " + key);
    }
}

if (!result.emails.isEmpty()) {
    stdout.println("\n📧 Email Addresses:");
    for (String email : result.emails) {
        stdout.println("    • " + email);
    }
}

// Security Issues
if (!result.securityIssues.isEmpty()) {
    stdout.println("\n⚠️ Security Issues:");
    for (String issue : result.securityIssues) {
        stdout.println("    • " + issue);
    }
}

// Third-party Services
if (!result.thirdPartyDomains.isEmpty()) {
    stdout.println("\n🌐 Third-party Domains: " + result.thirdPartyDomains.size());
}
```

### 📊 Örnek Çıktı

```
========== PASSIVE RECONNAISSANCE ==========
Target: https://api.example.com/users
Scan Date: 2025-01-09 14:30:00

🖥️ Technology Stack:
  Web Server: nginx/1.21.0
  Language: Node.js
  Frameworks: Express.js, React
  Cloud: Amazon Web Services (AWS)
  CDN: Cloudflare

🛡️ Security Headers:
  Present: 3
  Missing: 4
    ⚠️ Content-Security-Policy
    ⚠️ X-Frame-Options
    ⚠️ Strict-Transport-Security
    ⚠️ X-Content-Type-Options

🔑 CRITICAL - API Keys Exposed:
    🚨 AWS Access Key: AKIAIOSFODNN7EXAMPLE
    🚨 Google API Key: AIzaSyC-jsNkKmAr_zqP6QXxxxxxxxXxXxXxXx

⚠️ Security Issues:
    • Server version disclosed: nginx/1.21.0
    • Technology disclosure: Express
    • Missing Content-Security-Policy header
    • Missing HSTS header
    • CRITICAL: AWS Access Key exposed!

🌐 Third-party Domains: 15
```

---

## 5. Mobile API Security Module

### 🎯 Ne İşe Yarar?

Android ve iOS mobile app API'leri için özel güvenlik testleri yapar. OWASP Mobile Top 10'a göre kontroller yapar.

### 📱 Test Edilen Zafiyetler

1. **Certificate Pinning**: Bypass kontrolü
2. **API Key Exposure**: Hardcoded key tespiti
3. **Weak Authentication**: OAuth, JWT kontrolü
4. **Insecure Data Storage**: Hassas veri kontrolü
5. **Deep Link Vulnerabilities**: URL scheme exploits
6. **Binary Protections**: Obfuscation, anti-tamper
7. **JWT Security**: Algorithm, expiration kontrolü
8. **SSL/TLS Configuration**: Protocol, cipher kontrolü
9. **Root/Jailbreak Detection**: Bypass tespiti
10. **Push Notification Security**: Token güvenliği
11. **OAuth Implementation**: PKCE, state kontrolü
12. **Biometric Authentication**: Bypass kontrolü

### 💻 Kullanım

```java
// 1. Mobile Security Module oluştur
MobileAPISecurity mobileSecurity = new MobileAPISecurity(
    callbacks,
    helpers,
    stdout,
    stderr
);

// 2. Mobile app trafiğini test et
IHttpRequestResponse mobileRequest = getMobileTraffic();
List<MobileAPISecurity.MobileTestResult> results =
    mobileSecurity.runMobileSecurityTests(mobileRequest);

// 3. Sonuçları göster
stdout.println("\n========== MOBILE API SECURITY REPORT ==========");

int vulnerable = 0;
int secure = 0;

for (MobileAPISecurity.MobileTestResult result : results) {
    if (result.vulnerable) {
        vulnerable++;
        stdout.println("\n❌ " + result.testName);
        stdout.println("   Severity: " + result.severity);
        stdout.println("   Description: " + result.description);
        stdout.println("   Evidence: " + result.evidence);
        stdout.println("   Remediation:\n" + result.remediation);
    } else {
        secure++;
        stdout.println("\n✅ " + result.testName + ": SECURE");
    }
}

stdout.println("\n========== SUMMARY ==========");
stdout.println("Total Tests: " + results.size());
stdout.println("❌ Vulnerable: " + vulnerable);
stdout.println("✅ Secure: " + secure);
```

### 📊 Örnek Rapor

```
========== MOBILE API SECURITY REPORT ==========

❌ Certificate Pinning
   Severity: High
   Description: Traffic is interceptable through Burp Suite, indicating
                certificate pinning is either not implemented or bypassed
   Evidence: HTTPS traffic successfully intercepted without pinning errors
   Remediation:
   For Android:
   1. Implement certificate pinning using Network Security Configuration
   2. Use libraries like OkHttp with CertificatePinner
   3. Pin both leaf and intermediate certificates

   For iOS:
   1. Implement pinning using URLSession delegate
   2. Use TrustKit framework
   3. Pin public keys rather than certificates

🔑 CRITICAL - API Key Exposure
   Severity: Critical
   Description: API keys or secrets found in mobile app requests
   Evidence: Exposed keys:
            Header: X-API-Key: sk_live_123456789abcdefgh
            Parameter: api_secret=abcdef123456
   Remediation:
   1. Never hardcode API keys in mobile apps
   2. Use OAuth 2.0 with dynamic tokens
   3. Implement backend authentication proxy
   4. Rotate compromised keys immediately

✅ Weak Authentication: SECURE
✅ JWT Security: SECURE
❌ Root/Jailbreak Detection
   Severity: Medium
   Description: App running on rooted device but traffic interceptable
   Evidence: Device status: Rooted
   Remediation:
   1. Implement runtime integrity checks
   2. Check for root/jailbreak indicators
   3. Validate app signature

========== SUMMARY ==========
Total Tests: 12
❌ Vulnerable: 3
✅ Secure: 9
```

---

## Hızlı Başlangıç

### 1. Projeyi Derle

```bash
cd /Users/administrator/Downloads/Burp\ exteniton/ai-security-scanner

# JDK 8 kullandığınızdan emin olun
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.8.0_241.jdk/Contents/Home

# Temiz build
./gradlew clean build

# JAR dosyası:
# build/libs/ai-security-scanner-1.0.0.jar
```

### 2. Burp Suite'e Yükle

```
1. Burp Suite → Extender → Extensions
2. Add → Extension Type: Java
3. Select JAR: build/libs/ai-security-scanner-1.0.0.jar
4. Load
5. ✅ Extension yüklendi!
```

### 3. API Ayarları

```
1. AppSecHunter tab → Settings
2. API URL gir (Qwen API)
3. API Key gir
4. Test Connection
5. ✅ Hazır!
```

### 4. İlk Testler

#### Chain Attack Discovery
```
1. Proxy → HTTP History → 10-15 request seç
2. Sağ tık → "🔗 Discover Attack Chains"
3. Extension Output'u kontrol et
```

#### Compliance Check
```java
// Kendi Java kodunuzda
ComplianceChecker checker = new ComplianceChecker(callbacks, helpers, stdout, stderr);
List<IHttpRequestResponse> traffic = getAllTraffic();
ComplianceChecker.ComplianceReport report =
    checker.runComplianceCheck(ComplianceChecker.Standard.OWASP_TOP10, traffic);
```

#### Passive Recon
```
1. Herhangi bir request seç
2. Sağ tık → "🔍 Passive Reconnaissance"
3. Technology stack ve security issues görüntüle
```

#### Mobile Testing
```
1. Mobile app traffic'i yakala
2. Request seç → Sağ tık → "📱 Mobile Security Test"
3. 12 mobile-specific test çalışır
```

---

## Kod Örnekleri

### Tam Örnek: Tüm Özellikleri Kullan

```java
package burp;

import burp.api.ChainAttackDetector;
import burp.compliance.ComplianceChecker;
import burp.copilot.AISecurityCoPilot;
import burp.recon.PassiveReconEngine;
import burp.mobile.MobileAPISecurity;

public class FullSecurityTest {

    public static void runFullTest(
            IBurpExtenderCallbacks callbacks,
            IExtensionHelpers helpers,
            QwenAPIClient aiClient,
            PrintWriter stdout,
            PrintWriter stderr,
            List<IHttpRequestResponse> traffic) {

        stdout.println("\n========================================");
        stdout.println("   🚀 FULL SECURITY TEST SUITE");
        stdout.println("========================================\n");

        // 1. Passive Reconnaissance
        stdout.println("🔍 Phase 1: Passive Reconnaissance...");
        PassiveReconEngine reconEngine = new PassiveReconEngine(callbacks, helpers, stdout, stderr);
        for (IHttpRequestResponse req : traffic) {
            PassiveReconEngine.ReconResult recon = reconEngine.analyze(req);
            if (!recon.apiKeys.isEmpty()) {
                stdout.println("🚨 CRITICAL: API Keys found!");
            }
        }

        // 2. Chain Attack Discovery
        stdout.println("\n⛓️ Phase 2: Chain Attack Discovery...");
        ChainAttackDetector chainDetector = new ChainAttackDetector(callbacks, helpers, stdout, stderr);
        for (IHttpRequestResponse req : traffic) {
            chainDetector.analyzeEndpoint(req);
        }
        List<ChainAttackDetector.APIChain> chains = chainDetector.discoverChains();
        stdout.println("Found " + chains.size() + " attack chains");

        // 3. Compliance Check (All Standards)
        stdout.println("\n✅ Phase 3: Compliance Checking...");
        ComplianceChecker complianceChecker = new ComplianceChecker(callbacks, helpers, stdout, stderr);

        for (ComplianceChecker.Standard standard : ComplianceChecker.Standard.values()) {
            ComplianceChecker.ComplianceReport report =
                complianceChecker.runComplianceCheck(standard, traffic);
            stdout.println(standard + ": " +
                String.format("%.1f%%", report.complianceScore) +
                " (" + report.getComplianceLevel() + ")");
        }

        // 4. Mobile Security Testing (if mobile traffic detected)
        stdout.println("\n📱 Phase 4: Mobile Security Testing...");
        MobileAPISecurity mobileSecurity = new MobileAPISecurity(callbacks, helpers, stdout, stderr);
        int totalMobileVulns = 0;

        for (IHttpRequestResponse req : traffic) {
            if (isMobileTraffic(req, helpers)) {
                List<MobileAPISecurity.MobileTestResult> mobileResults =
                    mobileSecurity.runMobileSecurityTests(req);
                for (MobileAPISecurity.MobileTestResult result : mobileResults) {
                    if (result.vulnerable) totalMobileVulns++;
                }
            }
        }
        stdout.println("Mobile vulnerabilities found: " + totalMobileVulns);

        // 5. AI Co-Pilot Summary
        stdout.println("\n🤖 Phase 5: AI Analysis...");
        AISecurityCoPilot copilot = new AISecurityCoPilot(callbacks, helpers, aiClient, stdout, stderr);
        AISecurityCoPilot.CoPilotResponse summary = copilot.chat(
            "Summarize all security findings and provide recommendations",
            null
        );
        stdout.println(summary.message);

        stdout.println("\n========================================");
        stdout.println("   ✅ SECURITY TEST COMPLETED");
        stdout.println("========================================\n");
    }

    private static boolean isMobileTraffic(IHttpRequestResponse req, IExtensionHelpers helpers) {
        IRequestInfo reqInfo = helpers.analyzeRequest(req);
        for (String header : reqInfo.getHeaders()) {
            String headerLower = header.toLowerCase();
            if (headerLower.contains("user-agent:") &&
                (headerLower.contains("android") || headerLower.contains("iphone") ||
                 headerLower.contains("ipad") || headerLower.contains("ios"))) {
                return true;
            }
        }
        return false;
    }
}
```

---

## 🎯 En İyi Pratikler

### Chain Attack Detection
1. En az 10-15 farklı endpoint'ten traffic topla
2. Authentication flow'ları mutlaka dahil et
3. Admin/user/guest endpoint'lerini karıştır
4. POST/PUT/DELETE requestleri dahil et

### Compliance Checking
1. Production traffic kullan (dev değil)
2. Tüm standartları periyodik olarak test et
3. Remediation'ları priority'ye göre uygula
4. Quarterly compliance raporu oluştur

### Passive Recon
1. Her yeni domain için ilk olarak recon yap
2. API key bulunursa HEMEN rotate et
3. Technology stack'i dokümante et
4. Missing header'ları düzelt

### Mobile Security
1. Hem Android hem iOS traffic'i test et
2. Certificate pinning bypass dene
3. API key exposure için özel dikkat
4. Root/jailbreak detection test et

### AI Co-Pilot
1. Doğal dille konuş (ChatGPT gibi)
2. Context için request seç
3. Suggested actions'ları takip et
4. Quick replies'ı kullan

---

## 🐛 Troubleshooting

### Build Hatası

```bash
# JDK versiyonunu kontrol et
java -version

# JDK 8 kullan
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.8.0_241.jdk/Contents/Home

# Clean build
./gradlew clean
./gradlew build
```

### Extension Yüklenmiyor

```
1. Burp Suite → Extender → Errors tab'ına bak
2. Stack trace'i kontrol et
3. JAR dosyasını doğru seçtiğinden emin ol
4. Java 8+ kullandığını doğrula
```

### AI API Bağlantı Hatası

```
1. API URL doğru mu?
2. API Key geçerli mi?
3. Network bağlantısı var mı?
4. Firewall/Proxy engel oluyor mu?
```

---

## 📞 Destek

**Yazar**: Zahid Eroglu
**Version**: 3.0
**License**: MIT

### Sorularınız için:
1. GitHub Issues açın
2. Extension output'u paylaşın
3. Hatanın tekrar üretilme adımlarını yazın

---

**Happy Hacking! 🎯**

*"Bu extension pentester'ların işini %90 hızlandırır!"*

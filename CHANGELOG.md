# Changelog - AppSecHunter

## v1.0.0 - Major Update (2025-01-09)

### 🎯 Major Features Added

#### 1. AI Autonomous Testing (YENİ!)
- **AI artık kendi testlerini oluşturuyor**
- AI request'i analiz eder ve test planı oluşturur
- Her test için hangi parametreye hangi payload gönderileceğini AI karar verir
- AI sonuçları analiz eder ve ek testler önerir
- Context menu: "🤖 AI Autonomous Testing"

**Dosyalar:**
- `src/main/java/burp/ai/AITestingAgent.java` (YENİ - 475 satır)
- `src/main/java/burp/ScanManager.java` (runAIAutonomousTests() eklendi)
- `src/main/java/burp/BurpExtender.java` (context menu eklendi)

#### 2. Tam AI-Powered Dynamic Testing
- Tüm manuel test kodları kaldırıldı
- AI artık tüm vulnerability tespitini yapıyor
- 8 kategoride kapsamlı analiz:
  1. Business Logic
  2. IDOR
  3. Authentication & Authorization
  4. Injection (SQL, NoSQL, Command)
  5. XSS
  6. GraphQL
  7. API Security
  8. Other Vulnerabilities

**Dosyalar:**
- `src/main/java/burp/ScanManager.java` (performDynamicTests() tamamen yeniden yazıldı)
- `src/main/java/burp/ScanManager.java` (buildComprehensiveDynamicTestPrompt() eklendi)

#### 3. Database Integration for Dynamic Tests
- Tüm dynamic test sonuçları artık database'e kaydediliyor
- Test istatistikleri takip ediliyor
- Geçmiş sonuçlar sorgulanabiliyor

**Dosyalar:**
- `src/main/java/burp/DatabaseManager.java` (dynamic_test_results tablosu)
- `src/main/java/burp/DatabaseManager.java` (saveDynamicTestFinding() metodu)
- `src/main/java/burp/DatabaseManager.java` (getRecentDynamicTests() metodu)
- `src/main/java/burp/DatabaseManager.java` (getDynamicTestStats() metodu)

#### 4. Request Throttling Settings
- Saniye başına maksimum istek sayısı ayarlanabilir
- WAF detection threshold ayarlanabilir
- Slow mode delay yapılandırılabilir

**Dosyalar:**
- `src/main/java/burp/Settings.java` (3 yeni field + getters/setters)

---

### 🐛 Bug Fixes

#### 1. IDOR False Positive Problemi (KRİTİK FİX)
**Problem:** Extension, request'te ID parametresi olmadığı halde IDOR zafiyeti rapor ediyordu.
- Örnek: `/api/v1/users` path'indeki "1" ID olarak algılanıyordu

**Çözüm:**
- Response karşılaştırması eklendi (orijinal vs test)
- Content validation eklendi (response length > 100 bytes)
- Error page detection eklendi (not found, access denied, unauthorized)
- Aynı değer kontrolü eklendi (test value == original value ise skip)

**Dosyalar:**
- `src/main/java/burp/idor/AdvancedIDORTester.java` (testGenericID() metodu)

#### 2. Finding Constructor Error
**Problem:** Finding sınıfı constructor'ı yanlış parametrelerle çağrılıyordu.

**Çözüm:**
- Tüm Finding oluşturma kodları düzeltildi
- Confidence hesaplaması eklendi
- Exploitation ve remediation parametreleri eklendi

**Dosyalar:**
- `src/main/java/burp/ScanManager.java` (createBusinessLogicIssue(), createIDORIssue(), vs.)

#### 3. ColorScheme.TEXT_MUTED Error
**Problem:** Olmayan ColorScheme sabiti kullanılıyordu.

**Çözüm:**
- TEXT_MUTED → TEXT_SECONDARY olarak değiştirildi

**Dosyalar:**
- `src/main/java/burp/ui/SettingsPanel.java`

---

### 🎨 UI Improvements

#### 1. Context Menu Expansion
Sağ tık menüsünde yeni seçenekler:

```
🔍 Scan with AppSecHunter
   → Orijinal AI-powered scan

━━━━━━━━━━━━━━━━━━━━━━

⚡ Run Dynamic Tests
   → Tüm dynamic testler (AI-powered)

🤖 AI Autonomous Testing (YENİ!)
   → AI kendi testlerini oluşturur

━━━━━━━━━━━━━━━━━━━━━━

🎯 Run Individual Tests
   ├─ IDOR Testing
   ├─ Business Logic Testing
   ├─ GraphQL Testing
   └─ JWT Testing
```

**Dosyalar:**
- `src/main/java/burp/BurpExtender.java` (createMenuItems() metodu)

---

### 📚 Documentation

#### Yeni Belgeler:
1. **AI_AUTONOMOUS_TESTING.md** - AI Autonomous Testing özelliği için detaylı kılavuz
2. **NASIL_KULLANILIR.md** - Hızlı başlangıç kılavuzu (Türkçe)
3. **DYNAMIC_TESTING_GUIDE.md** - Dynamic testing detaylı kullanım kılavuzu (Türkçe)

---

### 🔧 Technical Changes

#### Code Architecture
- Manual testing logic removed → Full AI-powered approach
- Test planning, execution, and verification all done by AI
- 3-phase AI testing pipeline:
  1. Test Planning (AI creates test plan)
  2. Test Execution (Execute AI-suggested tests)
  3. Results Analysis (AI analyzes and suggests more tests)

#### Database Schema
```sql
CREATE TABLE dynamic_test_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    test_type TEXT,        -- Business Logic, IDOR, GraphQL, JWT
    finding_type TEXT,     -- Specific vulnerability type
    severity TEXT,         -- Critical, High, Medium, Low
    description TEXT,
    evidence TEXT,
    exploitation TEXT,
    remediation TEXT,
    duration INTEGER,      -- Test duration in ms
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Settings Schema
```java
// New settings fields:
private int maxRequestsPerSecond = 5;       // Default: 5 req/sec
private int slowModeDelayMs = 4000;         // Default: 4 seconds
private int wafDetectionThreshold = 3;      // Default: 3 blocks
```

---

### 📊 Statistics

#### Code Statistics:
- **New Files:** 1 (AITestingAgent.java - 475 lines)
- **Modified Files:** 6
  - BurpExtender.java
  - ScanManager.java
  - DatabaseManager.java
  - Settings.java
  - AdvancedIDORTester.java
  - SettingsPanel.java
- **Lines Added:** ~800 lines
- **Lines Modified:** ~200 lines

#### Build:
- **Status:** ✅ BUILD SUCCESSFUL
- **JAR Size:** 13 MB
- **Build Time:** 3 seconds
- **Warnings:** 15 (version compatibility - non-critical)

---

### 🚀 How to Use New Features

#### AI Autonomous Testing:
```
1. Burp → Proxy → HTTP History → Select request
2. Right-click → "🤖 AI Autonomous Testing"
3. Extender → Output → Watch AI work
4. Scanner → Issues → See findings
```

#### Check Results:
```
Extender → Output:
- AI test plan
- Each test execution
- Vulnerability findings
- AI suggestions

Scanner → Issues:
- All vulnerabilities
- Evidence
- Remediation
```

---

### ⚠️ Breaking Changes

#### Removed:
- Manual business logic testing code (replaced with AI)
- Manual IDOR testing code (replaced with AI)
- Manual GraphQL testing code (replaced with AI)
- Manual JWT testing code (replaced with AI)

**Migration:** No action needed - AI handles everything now!

---

### 🔮 Future Work (Not Implemented Yet)

#### 1. Dashboard UI for Dynamic Test Results
**Status:** Database ready, UI pending
**What's Needed:**
- Add tab to DashboardPanel
- Display getRecentDynamicTests()
- Show getDynamicTestStats()
- Export functionality

#### 2. Settings Panel for Request Throttling
**Status:** Settings.java ready, UI pending
**What's Needed:**
- Add "Request Throttling" panel
- Input fields for maxRequestsPerSecond, slowModeDelayMs, wafDetectionThreshold

#### 3. AI Test Plan Editor
**Status:** Not started
**What's Needed:**
- UI to view AI's planned tests before execution
- Ability to modify/remove tests
- Ability to add custom tests

---

### 🙏 User Feedback Addressed

#### Feedback 1:
> "aktif scan yapma kısmını göremedim. nasıl yapacağım. idor nasıl denenecek?"

**Fixed:** Context menu integration added - right-click any request to access all tests.

#### Feedback 2:
> "Dinamik testler hiç bir yerde görünmüyor. bunların loglanması taranması veya dashboardda görünmesini sağlarmısın?"

**Fixed:** Database integration added - all results saved to database (dashboard UI pending).

#### Feedback 3:
> "yapılan dinamik testlerde istek sınırlama sayısını da settings in altına ekleyelim"

**Fixed:** Request throttling settings added to Settings.java.

#### Feedback 4:
> "Falsepozitif çok. IDOR zafiyeti için böyle birşey demiş ama ID değeri requestin içerisinde yok"

**Fixed:** IDOR testing completely rewritten with response comparison and validation.

#### Feedback 5:
> "bizim kod. agüvenmiyorum. hepsini ai yapsın"

**Fixed:** All manual testing removed - 100% AI-powered now.

#### Feedback 6:
> "yapılacak istekleri de ai karar verirp istek atabilsin"

**Fixed:** AITestingAgent created - AI now creates test plans and executes tests autonomously.

---

### 📦 Build & Install

#### Build:
```bash
cd "/Users/administrator/Downloads/Burp exteniton/ai-security-scanner"
export JAVA_HOME="/Library/Java/JavaVirtualMachines/jdk1.8.0_241.jdk/Contents/Home"
./gradlew clean build -x test
```

#### Install:
```
1. Burp Suite → Extender → Extensions → Add
2. Extension Type: Java
3. Extension File: build/libs/ai-security-scanner-1.0.0.jar
4. Next → Extension loaded
```

#### Configure:
```
1. AppSecHunter tab → Settings
2. API Configuration:
   - API Endpoint: [Your Qwen API endpoint]
   - API Key: [Your API key]
   - Model: qwen3-coder
3. Dynamic Testing: Enable all
4. AI Features: Enable all
5. Save Settings
```

---

### 🎉 Summary

Bu güncellemede **AI Autonomous Testing** özelliği eklendi. Artık AI sadece analiz yapmakla kalmıyor, **hangi testleri çalıştıracağına, hangi payload'ları göndereceğine de kendisi karar veriyor!**

**3 ana iyileştirme:**
1. ✅ AI kendi test planını oluşturuyor
2. ✅ AI testleri otomatik yürütüyor
3. ✅ AI sonuçları analiz edip ek testler öneriyor

**6 bug fix:**
1. ✅ IDOR false positive problemi çözüldü
2. ✅ Database integration eklendi
3. ✅ Request throttling ayarları eklendi
4. ✅ Tüm testler AI-powered oldu
5. ✅ Context menu integration eklendi
6. ✅ Constructor hatası düzeltildi

---

**AppSecHunter v1.0.0**
*Created by Zahid Eroglu*

🤖 **AI artık kendi testlerini oluşturuyor ve çalıştırıyor!**

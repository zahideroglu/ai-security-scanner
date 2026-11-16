# 🤖 AI Autonomous Testing - Kullanım Kılavuzu

## Yeni Özellik: AI'nın Kendi Testlerini Oluşturması

Bu özellik ile AI artık sadece analiz yapmakla kalmıyor, **hangi istekleri göndereceğine de kendisi karar veriyor!**

---

## 🎯 Nasıl Çalışır?

### 3 Aşamalı AI Süreci:

#### 1️⃣ Test Planlama (AI Planning)
AI, orijinal request'i analiz eder ve test planı oluşturur:
```json
{
  "tests": [
    {
      "description": "Test for IDOR by incrementing user ID",
      "attackType": "IDOR",
      "targetParameter": "user_id",
      "payload": "124",
      "expectedBehavior": "Access denied",
      "vulnerableIf": "Returns different user's data"
    },
    {
      "description": "Test for negative price",
      "attackType": "Business Logic",
      "targetParameter": "price",
      "payload": "-100",
      "expectedBehavior": "Reject negative price",
      "vulnerableIf": "Accepts negative price"
    }
  ]
}
```

#### 2️⃣ Test Yürütme (AI Execution)
AI'nın planladığı her test otomatik çalıştırılır:
- Parametreler AI'nın belirlediği payload'larla değiştirilir
- Request'ler gönderilir
- Response'lar toplanır

#### 3️⃣ Sonuç Analizi (AI Verification)
Her response AI tarafından analiz edilir:
- Zafiyet var mı?
- Severity nedir?
- Ek testler gerekli mi?

---

## 🚀 Kullanım

### Adım 1: Request Seç
```
Burp → Proxy → HTTP History → Bir request seçin
```

### Adım 2: AI Autonomous Testing Başlat
```
Request'e sağ tıklayın → "🤖 AI Autonomous Testing"
```

### Adım 3: Logları İzleyin
```
Extender → Output → AI'nın ne yaptığını görün
```

---

## 📊 Örnek Log Çıktısı

```
╔════════════════════════════════════════════╗
║   AI AUTONOMOUS TESTING MODE               ║
║   AI will decide what requests to send     ║
╚════════════════════════════════════════════╝

[1/3] AI analyzing request and planning tests...
[+] AI created test plan with 8 tests

[2/3] Executing AI-suggested tests...

[Test 1/8] Test for IDOR by incrementing user ID
[*] Attack Type: IDOR
[*] Target Parameter: user_id
[*] Payload: 124
[!] VULNERABILITY FOUND!
[!] Severity: High

[Test 2/8] Test for negative price manipulation
[*] Attack Type: Business Logic
[*] Target Parameter: price
[*] Payload: -100
[!] VULNERABILITY FOUND!
[!] Severity: Critical

[Test 3/8] Test for SQL injection in search
[*] Attack Type: SQL Injection
[*] Target Parameter: q
[*] Payload: ' OR '1'='1
[-] No vulnerability

...

[3/3] AI analyzing test results...

SUMMARY:
Found 3 critical vulnerabilities:
1. IDOR - User ID enumeration (High)
2. Business Logic - Negative price accepted (Critical)
3. JWT - Algorithm confusion possible (Critical)

[*] AI suggests additional tests:
    - Test for privilege escalation with modified JWT claims
    - Test for batch IDOR with multiple ID ranges
    - Test for race condition in price update
```

---

## 🆚 Fark: Normal Dynamic Tests vs AI Autonomous

### ⚡ Run Dynamic Tests (Mevcut)
- **AI rolü:** Sadece analiz yapar
- **Testler:** Sabit kod tarafından belirlenir
- **Payload'lar:** Önceden tanımlı
- **Örnek:** 50 adet standart IDOR payloadı

### 🤖 AI Autonomous Testing (YENİ)
- **AI rolü:** Plan yapar, test oluşturur, sonuçları analiz eder
- **Testler:** AI context'e göre karar verir
- **Payload'lar:** AI dinamik üretir
- **Örnek:** "Bu request'te user_id=123 var, 124'ü deneyelim"

---

## 💡 Kullanım Senaryoları

### Senaryo 1: API Endpoint Keşfi
```
Durum: Yeni bir API endpoint buldunuz
Aksiyon: AI Autonomous Testing çalıştırın
Sonuç: AI tüm parametreleri analiz eder ve context'e özel testler oluşturur
```

### Senaryo 2: Karmaşık İş Mantığı
```
Durum: E-ticaret checkout endpoint'i
Aksiyon: AI Autonomous Testing
Sonuç: AI fiyat, miktar, kupon gibi tüm parametreleri analiz eder
       Mantıklı kombinasyonlar dener (negatif fiyat + çoklu kupon)
```

### Senaryo 3: Özel Kimlik Doğrulama
```
Durum: Custom JWT implementasyonu
Aksiyon: AI Autonomous Testing
Sonuç: AI JWT structure'ını analiz eder
       Algoritma, claims, signature'a özel testler üretir
```

---

## ⚙️ Ayarlar

### Settings → Dynamic Testing
Tüm testleri etkinleştirmeniz önerilir:
- ✅ Business Logic Testing
- ✅ IDOR Testing
- ✅ GraphQL Testing
- ✅ JWT Testing
- ✅ WAF Detection

### Settings → AI Features
AI özellikleri MUTLAKA aktif olmalı:
- ✅ AI Context Analysis (teknoloji tespiti için)
- ✅ Smart Payload Generation (payload üretimi için)
- ✅ AI False Positive Filter (yanlış alarm için)

---

## 🔥 Pro Tips

### Tip 1: AI'ya Zaman Verin
- AI 3 farklı aşamada çalışır
- Her aşama 5-15 saniye sürebilir
- Toplam süre: 30-90 saniye (request karmaşıklığına göre)

### Tip 2: Extender Output'u İzleyin
- AI'nın ne düşündüğünü görebilirsiniz
- Hangi testleri planladığını görebilirsiniz
- Her testin sonucunu canlı takip edebilirsiniz

### Tip 3: Kompleks Request'lerde Kullanın
- AI Autonomous Testing en iyi kompleks request'lerde çalışır
- Basit GET request'ler için "Run Dynamic Tests" yeterli
- POST/PUT/PATCH gibi karmaşık body'li request'ler için idealdir

### Tip 4: AI'nın Önerilerini Takip Edin
- Test sonunda AI ek testler önerebilir
- Bu önerileri manuel test ederek daha derin analiz yapabilirsiniz

---

## 🛡️ Güvenlik Uyarıları

### ⚠️ AI Gerçek İstekler Gönderir!
```
Bu özellik AKTIF testingdir!
- Database'e yazma yapabilir
- Gerçek işlemler tetikleyebilir
- Para/kredi harcanabilir

✅ Sadece YETKİLİ olduğunuz sistemlerde kullanın
✅ Production'da dikkatli olun
✅ Önce test/staging ortamlarında deneyin
```

---

## 🔍 Troubleshooting

### "AI Autonomous Testing started but no output"
```
Çözüm:
1. Extender → Errors kontrol edin
2. Settings → API Configuration geçerli mi?
3. "Test Connection" ile API'yi test edin
```

### "AI test plan is empty"
```
Muhtemel neden:
- Request çok basit (parametre yok)
- AI test planı oluşturamadı
- API timeout oldu

Çözüm:
- Daha kompleks bir request seçin (parametreli)
- API timeout'u artırın (Settings → Timeout)
```

### "Too many API requests"
```
Her test için 3 API çağrısı yapılır:
1. Test planı oluşturma
2. Her response için zafiyet kontrolü
3. Final analiz

10 test = ~30 API call

Çözüm:
- API kredinizin yeterli olduğundan emin olun
- Çok fazla request seçmeyin (max 5-10)
```

---

## 📚 Teknik Detaylar

### AI Prompt Yapısı

#### Phase 1: Test Planning
```
INPUT:
- HTTP request (full)
- Request parameters
- Request method
- Content-Type

OUTPUT:
- JSON test plan
- 5-10 specific tests
- Attack type, parameter, payload for each
```

#### Phase 2: Vulnerability Verification
```
INPUT:
- Original response
- Test response
- Expected behavior

OUTPUT:
- YES/NO (vulnerable?)
- Confidence level
- Explanation
```

#### Phase 3: Results Analysis
```
INPUT:
- All test results
- Vulnerability list
- Context

OUTPUT:
- Summary
- Additional test suggestions
- Exploitation scenarios
```

---

## 🎓 En İyi Uygulamalar

### 1. Doğru Request'i Seçin
```
İYİ:
- POST /api/checkout (business logic)
- GET /api/users/123 (IDOR)
- POST /graphql (GraphQL)

KÖTÜ:
- GET /favicon.ico (parametre yok)
- GET /health (static response)
```

### 2. Context Menu'yu Doğru Kullanın
```
🔍 Scan with AppSecHunter
   → Genel tarama (hızlı)

⚡ Run Dynamic Tests
   → Tüm standart testler (orta hız)

🤖 AI Autonomous Testing
   → AI karar verir (yavaş ama kapsamlı)

🎯 Run Individual Tests
   → Sadece belirli test (hızlı)
```

### 3. Sonuçları Karşılaştırın
```
Önce: ⚡ Run Dynamic Tests çalıştırın
Sonra: 🤖 AI Autonomous Testing çalıştırın
Fark: AI farklı vulnerabilities bulabilir!
```

---

## 📞 Destek

### Log Dosyaları
- Extender → Output (AI kararları)
- Extender → Errors (hatalar)
- Scanner → Issues (bulgular)

### Yaygın Problemler
- API key geçersiz → Settings'i kontrol edin
- Timeout → Settings → API Timeout'u artırın
- False positives → Settings → AI False Positive Filter aktif edin

---

**AppSecHunter v1.0.0**
*Created by Zahid Eroglu*

🚀 **AI artık kendi testlerini oluşturuyor!**

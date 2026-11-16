# ⚡ Hızlı Başlangıç - Dynamic Testing

## 🚀 3 Adımda Başlayın

### 1️⃣ Ayarları Yapın

```
Burp → AppSecHunter tab → Settings

✓ API Endpoint: [Qwen API URL'nizi girin]
✓ API Key: [API anahtarınızı girin]
✓ Model: qwen3-coder

⚡ Dynamic Testing bölümünde TÜM checkbox'ları işaretleyin
🤖 AI Features bölümünde TÜM checkbox'ları işaretleyin

💾 Save Settings
```

### 2️⃣ Test Edin

```
Proxy → HTTP History → Bir request seçin
Sağ tıklayın → "⚡ Run Dynamic Tests"
```

### 3️⃣ Sonuçları Görün

```
Extender → Output  → Canlı test logları
Scanner → Issues   → Bulunan zaafiyetler
```

---

## 🎯 Ne Test Edilir?

### ✅ Business Logic (E-Ticaret için MUTLAKa aktif edin!)
- ❌ Negatif fiyat (-100 TL → Müşteri para alıyor!)
- ❌ Sıfır fiyat (0 TL'ye ürün satın alma)
- ❌ Miktar manipülasyonu (1000 adet, negatif, 0.5 adet)
- ❌ Çoklu kupon kullanımı (%50 + %30 = %80 indirim!)

### ✅ IDOR
- ❌ `/api/user/123` → `/api/user/124` (başka kullanıcının datası!)
- ❌ Base64, UUID, Hash manipülasyonu

### ✅ GraphQL
- ❌ Schema açığa çıkıyor mu?
- ❌ Batch query abuse (DoS)

### ✅ JWT
- ❌ Algorithm confusion (RS256 → HS256)
- ❌ None algorithm bypass
- ❌ Admin role injection

### ✅ WAF Detection
- ✓ Cloudflare, Akamai, AWS WAF otomatik tespit
- ✓ Tespit edilince otomatik yavaşlama

---

## 💡 IDOR Testi Örneği

**Senaryo:** API'de kullanıcı profili endpoint'i test ediyorsunuz.

```http
GET /api/users/1234 HTTP/1.1
Authorization: Bearer token123
```

**Yapılacak:**

1. Bu request'e sağ tıklayın
2. `🎯 Run Individual Tests` → `IDOR Testing`

**Ne Olur:**

Extension otomatik olarak şunları test eder:

```
GET /api/users/1235
GET /api/users/1233
GET /api/users/1
GET /api/users/9999
GET /api/users/1236
...
```

**Bulgu Örneği:**

```
[!] IDOR - Sequential ID Exposure
Severity: High
Confidence: 90%

Description:
User ID 1234 → 1235 değiştirildiğinde başka kullanıcının bilgileri görüntülendi.

Evidence:
Response contains:
{
  "id": 1235,
  "email": "baskasi@example.com",
  "phone": "+90xxxxxxxxx"
}

Exploitation:
1. Kendi user ID'nizi tespit edin (1234)
2. Diğer ID'leri deneyin (1235, 1236, ...)
3. Tüm kullanıcı database'i enumerate edilebilir

Remediation:
- UUID kullanın (sequential ID yerine)
- Authorization kontrolü ekleyin
- User sadece kendi ID'sine erişebilmeli
```

---

## 💡 Business Logic Testi Örneği

**Senaryo:** E-ticaret sitesinde checkout yapıyorsunuz.

```http
POST /api/checkout HTTP/1.1

{
  "product_id": 123,
  "price": 100.00,
  "quantity": 1,
  "coupon": "WELCOME10"
}
```

**Yapılacak:**

1. Bu request'e sağ tıklayın
2. `🎯 Run Individual Tests` → `Business Logic Testing`

**Ne Olur:**

Extension otomatik olarak şunları test eder:

```json
// Test 1: Negatif fiyat
{"price": -100.00}

// Test 2: Sıfır fiyat
{"price": 0}

// Test 3: Negatif miktar
{"quantity": -10}

// Test 4: Çoklu kupon
{"coupon": ["WELCOME10", "SAVE20", "FREE30"]}

// Test 5: Aşırı miktar
{"quantity": 999999}
```

**Bulgu Örneği:**

```
[!] Business Logic - Negative Price Accepted
Severity: CRITICAL
Confidence: 95%

Description:
Application accepts NEGATIVE price: -100.00
This causes financial loss where customers RECEIVE money instead of paying.

Attack Scenario:
1. Add product to cart (price: 1000 TL)
2. Intercept checkout request
3. Modify price to -1000
4. Complete purchase
5. Result: Customer receives 1000 TL instead of paying!

Remediation:
- Server-side price validation
- Never trust client-side price
- Fetch price from database
- if (price <= 0) reject_transaction()
```

---

## 🔥 Context Menu Özellikleri

Request'e sağ tıkladığınızda görünen menü:

```
🔍 Scan with AppSecHunter
   → AI-powered genel tarama (Qwen ile analiz)

━━━━━━━━━━━━━━━━━━━━━━

⚡ Run Dynamic Tests
   → TÜM dynamic testleri çalıştır
   (Business Logic + IDOR + GraphQL + JWT + WAF)

🎯 Run Individual Tests
   ├─ IDOR Testing
   ├─ Business Logic Testing
   ├─ GraphQL Testing
   └─ JWT Testing
```

---

## 📊 Log Çıktısı Örneği

```
======================================
[*] STARTING DYNAMIC TESTS
[*] URL: https://shop.example.com/api/checkout
======================================

[1/6] Running AI Context Analysis...
[+] Technology: PHP
[+] Framework: Laravel
[+] Database: MySQL
[!] WAF Detected: Cloudflare

[2/6] Running Business Logic Tests...
[*] Testing: Price manipulation, quantity abuse, coupon stacking
[!] CRITICAL: Negative price accepted (-100)
[!] CRITICAL: Multiple coupons can be stacked (150% total discount)
[!] HIGH: Quantity can be set to 0.5 (fractional purchase)
[+] Business Logic: 3 findings

[3/6] Running IDOR Tests...
[*] Testing: Sequential IDs, UUIDs, Base64, URL paths
[!] HIGH: Sequential user ID exposure (/user/123 → /user/124)
[+] IDOR: 1 findings

[4/6] Running GraphQL Tests...
[*] Testing: Introspection, batch abuse, depth attacks
[+] GraphQL: 0 findings (No GraphQL detected)

[5/6] Running JWT Tests...
[*] Testing: Algorithm confusion, none algorithm, claims
[!] CRITICAL: JWT accepts alg:none (no signature!)
[!] HIGH: Algorithm confusion possible (RS256 → HS256)
[+] JWT: 2 findings

[6/6] WAF Detection Summary...
[!] WAF Detected: Cloudflare
[*] Requests sent: 47
[*] Blocks detected: 3
[*] Auto-throttle activated: YES
[*] Current delay: 4.2 seconds between requests

======================================
[✓] DYNAMIC TESTS COMPLETE
[+] Total Findings: 6 findings
[+] Duration: 18750ms
======================================
```

---

## ⚠️ UYARI

**Dynamic Testing AKTIF testlerdir!**

- ✅ Sadece YETKİLİ olduğunuz sistemlerde kullanın
- ✅ Production'da dikkatli olun (gerçek işlemler tetikleyebilir)
- ✅ Önce staging/test ortamlarında deneyin

**İzinsiz test yapmak yasa dışıdır ve cezai sorumluluk gerektirir!**

---

## 🎓 Pro Tips

1. **E-ticaret sitesi test ediyorsanız:**
   - Business Logic Testing'i MUTLAKa aktif edin
   - Checkout, cart, coupon endpoint'lerini test edin

2. **API test ediyorsanız:**
   - IDOR Testing'i aktif edin
   - JWT varsa JWT Testing'i aktif edin
   - GraphQL varsa GraphQL Testing'i aktif edin

3. **AI Features'ı kullanın:**
   - Context Analysis: Teknolojiyi otomatik tespit eder
   - Smart Payloads: Tespit edilen teknolojiye özgü payloadlar
   - False Positive Filter: %80 daha az yanlış alarm

4. **WAF varsa:**
   - WAF Detection otomatik çalışır
   - Tespit edilince yavaşlar
   - Manuel müdahale gerekmez

---

**Detaylı bilgi için:** `DYNAMIC_TESTING_GUIDE.md` dosyasına bakın

**AppSecHunter v1.0.0**
*Created by Zahid Eroglu*

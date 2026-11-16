# 🚀 Dynamic Testing Kullanım Kılavuzu

## AppSecHunter - Dynamic Testing Özellikleri

Bu kılavuz, AppSecHunter extension'ının **Dynamic Testing (Aktif Tarama)** özelliklerinin nasıl kullanılacağını açıklar.

---

## 📋 İçindekiler

1. [Kurulum](#kurulum)
2. [Ayarları Yapılandırma](#ayarları-yapılandırma)
3. [Dynamic Testing Nasıl Çalıştırılır](#dynamic-testing-nasıl-çalıştırılır)
4. [Test Türleri](#test-türleri)
5. [Sonuçları Görüntüleme](#sonuçları-görüntüleme)
6. [Örnekler](#örnekler)

---

## 🔧 Kurulum

### 1. Extension'ı Yükleyin

```
1. Burp Suite'i açın
2. Extender → Extensions → Add
3. Extension Type: Java
4. Extension File: ai-security-scanner-1.0.0.jar seçin
5. "Next" → Extension yüklendi
```

### 2. API Key'i Yapılandırın

```
1. AppSecHunter tab'ını açın
2. Settings sekmesine gidin
3. API Configuration kısmında:
   - API Endpoint: Qwen API endpoint'inizi girin
   - API Key: API anahtarınızı girin
   - Model: qwen3-coder (önerilen)
4. "💾 Save Settings" butonuna tıklayın
```

---

## ⚙️ Ayarları Yapılandırma

### Dynamic Testing Özelliklerini Etkinleştirme

**Settings → ⚡ Dynamic Testing (Active Scanning)** bölümünde şu testleri etkinleştirin:

#### ✅ Business Logic Testing
- **Neler Test Edilir:**
  - ✓ Negatif fiyat manipülasyonu (örn: -100 TL)
  - ✓ Sıfır fiyat bypass'ı
  - ✓ Miktar manipülasyonu (negatif, sıfır, aşırı değerler)
  - ✓ Kupon/voucher stacking (çoklu kupon kullanımı)
  - ✓ Para birimi manipülasyonu
  - ✓ Vergi/indirim bypass'ı

#### ✅ IDOR Testing
- **Neler Test Edilir:**
  - ✓ Sequential ID'ler (1, 2, 3... → diğer kullanıcıların datası)
  - ✓ UUID pattern'leri
  - ✓ Base64 encoded ID'ler (decode → modify → encode)
  - ✓ Hash-based ID'ler (MD5, SHA1, SHA256)
  - ✓ URL path parametreleri (/user/123 → /user/124)

#### ✅ GraphQL Testing
- **Neler Test Edilir:**
  - ✓ Introspection query (schema açığa çıkıyor mu?)
  - ✓ Batch query abuse (DoS riski)
  - ✓ Depth attack (iç içe query'ler)
  - ✓ Field suggestion testing

#### ✅ JWT Testing
- **Neler Test Edilir:**
  - ✓ Algorithm confusion (RS256 → HS256)
  - ✓ None algorithm bypass
  - ✓ Claims manipulation (role: user → admin)
  - ✓ Signature validation bypass

#### ✅ WAF Detection & Evasion
- **Neler Yapılır:**
  - ✓ Otomatik WAF tespiti (Cloudflare, Akamai, AWS WAF, vb.)
  - ✓ WAF tespit edilince otomatik yavaşlama
  - ✓ Akıllı throttling (rate limiting)
  - ✓ Request imzalarını izleme

### AI Features (Opsiyonel ama Önerilen)

**Settings → 🤖 AI-Powered Features** bölümünde:

- ✅ **AI Context Analysis**: Hedef uygulamanın teknoloji stackini otomatik tespit eder
- ✅ **Smart Payload Generation**: Tespit edilen teknolojiye özgü payloadlar üretir
- ✅ **AI False Positive Filter**: Bulguları AI ile doğrular, false positive oranını %80 azaltır

---

## 🎯 Dynamic Testing Nasıl Çalıştırılır

### Yöntem 1: Tek Request Üzerinde Test (Önerilen)

```
1. Burp → Proxy → HTTP History'den bir request seçin
2. Request'e sağ tıklayın
3. Menüden seçin:

   ⚡ Run Dynamic Tests  → TÜM testleri çalıştırır

   VEYA

   🎯 Run Individual Tests → Sadece belirli bir testi çalıştırır:
      - IDOR Testing
      - Business Logic Testing
      - GraphQL Testing
      - JWT Testing
```

### Yöntem 2: Birden Fazla Request Üzerinde

```
1. HTTP History'den CTRL/CMD tuşuna basarak birden fazla request seçin
2. Sağ tıklayın → "⚡ Run Dynamic Tests"
3. Her request için ayrı ayrı testler çalışacaktır
```

### Yöntem 3: Target Site Map'ten

```
1. Target → Site map → Test etmek istediğiniz endpoint'i bulun
2. Sağ tıklayın → "⚡ Run Dynamic Tests"
```

---

## 📊 Sonuçları Görüntüleme

### 1. Extender Output'u İzleyin

Dynamic testler çalışırken **Extender → Output** sekmesinde canlı log görürsünüz:

```
======================================
[*] STARTING DYNAMIC TESTS
[*] URL: https://example.com/api/checkout
======================================

[1/6] Running AI Context Analysis...
[+] Technology: PHP
[+] Framework: Laravel
[+] Database: MySQL

[2/6] Running Business Logic Tests...
[*] Testing: Price manipulation, quantity abuse, coupon stacking
[+] Business Logic: 3 findings

[3/6] Running IDOR Tests...
[*] Testing: Sequential IDs, UUIDs, Base64, URL paths
[+] IDOR: 1 findings

[4/6] Running GraphQL Tests...
[+] GraphQL: 0 findings

[5/6] Running JWT Tests...
[+] JWT: 2 findings

[6/6] WAF Detection Summary...
[!] WAF Detected: Cloudflare

======================================
[✓] DYNAMIC TESTS COMPLETE
[+] Total Findings: 6 findings
[+] Duration: 12450ms
======================================
```

### 2. Burp Scanner Issues'da Görüntüleme

Tüm bulgular otomatik olarak **Burp Scanner → Issues** sekmesine eklenir:

```
Target → Issues → Filtreleyin:

- "Business Logic - Price Manipulation" (Critical)
- "IDOR - Sequential ID Exposure" (High)
- "JWT - Algorithm Confusion" (Critical)
```

Her bulgunun detayında:

- ✓ Açıklama
- ✓ Kanıt (Evidence)
- ✓ Exploit senaryosu
- ✓ Düzeltme önerileri

---

## 💡 Örnekler

### Örnek 1: E-Ticaret Uygulamasında Business Logic Testi

**Senaryo:** Sepet işlemlerinde fiyat manipülasyonu

```
1. Ürünü sepete ekleyin
2. Checkout request'ini yakalayın (Proxy → Intercept)
3. Request'e sağ tıklayın → "🎯 Run Individual Tests" → "Business Logic Testing"

Bulgular:
✓ Negatif fiyat kabul ediliyor (-100 TL)
  → Müşteri ödeme yapmak yerine para alıyor!

✓ Miktar olarak ondalıklı değer kabul ediliyor (0.5)
  → Yarım ürün satın alınabiliyor

✓ Birden fazla indirim kuponu uygulanabiliyor
  → %50 + %30 = %80 indirim
```

### Örnek 2: API'de IDOR Testi

**Senaryo:** Kullanıcı bilgilerini getiren endpoint

```
Request:
GET /api/users/1234 HTTP/1.1
Cookie: session=abc123

1. Bu request'i seçin
2. Sağ tıklayın → "🎯 Run Individual Tests" → "IDOR Testing"

Test edilen varyasyonlar:
✓ /api/users/1235
✓ /api/users/1233
✓ /api/users/1
✓ /api/users/9999

Bulgu:
→ ID değiştirilerek başka kullanıcıların bilgileri görüntülenebiliyor!
  Severity: High
  Evidence: User ID 1235'e ait email ve telefon açığa çıktı
```

### Örnek 3: JWT Token Testi

**Senaryo:** Admin paneline erişim

```
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

1. Admin endpoint request'ini seçin
2. "🎯 Run Individual Tests" → "JWT Testing"

Test edilen:
✓ Algorithm confusion (RS256 → HS256)
✓ None algorithm
✓ Role claim manipulation (user → admin)

Bulgu:
→ JWT imzası olmadan kabul ediliyor (alg: none)!
  Severity: Critical
  Exploitation: Token'ı alg:none yapıp admin rolü verilebilir
```

### Örnek 4: GraphQL Introspection

**Senaryo:** GraphQL endpoint keşfi

```
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{ users { id name } }"}

1. GraphQL request'ini seçin
2. "🎯 Run Individual Tests" → "GraphQL Testing"

Bulgu:
→ GraphQL introspection açık!
  Tüm schema, queries, mutations görüntülenebiliyor

  Örnek hassas field'ler:
  - User.password_hash
  - User.credit_card_number
  - Admin.secret_key
```

---

## 🛡️ Güvenlik Uyarıları

### ⚠️ DİKKAT

1. **Sadece YETKİLENDİRİLMİŞ hedeflerde kullanın**
   - Dynamic testler aktif olarak uygulamayı probe eder
   - İzinsiz test etmek yasa dışıdır

2. **Production ortamlarında dikkatli olun**
   - Business Logic testleri gerçek işlemler tetikleyebilir
   - Önce staging/test ortamlarında deneyin

3. **WAF Detection'a güvenin**
   - WAF tespit edilince otomatik yavaşlar
   - Ama yine de manuel kontrol edin

4. **Rate limiting**
   - Varsayılan: 5 request/saniye
   - WAF tespit edilince: 1 request/3-5 saniye
   - Settings'den ayarlanabilir

---

## 🔍 Troubleshooting

### "Dynamic tests started but no output"

```
Çözüm:
1. Extender → Output sekmesine bakın
2. Extender → Errors'de hata var mı kontrol edin
3. Settings → Dynamic Testing - tüm checkboxlar işaretli mi?
```

### "AI features not working"

```
Çözüm:
1. Settings → API Configuration'u kontrol edin
2. "🔌 Test Connection" butonuna basın
3. API key'iniz geçerli ve credit'iniz var mı?
```

### "Too many findings (false positives)"

```
Çözüm:
1. Settings → AI Features → "AI False Positive Filter" etkinleştirin
2. AI her bulguyu doğrulayarak false positive'leri filtreler
```

### "WAF blocking all requests"

```
Çözüm:
1. WAF otomatik tespit edilip yavaşlatılmalı
2. Manuel kontrol: Settings → WAF Evasion etkin mi?
3. Daha da yavaşlatmak için SmartThrottleManager ayarlarını değiştirin
```

---

## 📚 Detaylı Bilgi

### Business Logic Testing Detayları

**Test edilen senaryolar:**

1. **Price Manipulation (10+ test)**
   - Negatif fiyatlar: -1, -0.01, -100, -999999
   - Sıfır fiyat: 0, 0.00
   - Minimal fiyat: 0.01 (1000 TL ürün için)
   - Float precision: 19.999999999
   - Integer overflow: 2147483647, 2147483648
   - Çoklu fiyat parametreleri (conflict)
   - Para birimi manipülasyonu (USD → JPY)

2. **Quantity Manipulation (8+ test)**
   - Negatif miktar: -1, -100
   - Sıfır miktar
   - Aşırı miktar: 999999
   - Ondalıklı miktar: 0.5, 1.5
   - Integer overflow

3. **Coupon/Voucher Abuse (6+ test)**
   - Çoklu kupon (stacking)
   - Süresi dolmuş kupon
   - Bruteforce (WELCOME10, SAVE20, vb.)
   - Değer manipülasyonu

### IDOR Testing Detayları

**ID Pattern Tespiti:**

```java
Sequential: 1, 2, 3, 123, 456
→ Test: ±1, ±10, ±100

UUID: a1b2c3d4-e5f6-7890-...
→ Test: Random UUID üretimi

Base64: dXNlcjEyMw== (user123)
→ Test: Decode → Modify → Encode

MD5 Hash: 5f4dcc3b5aa765d61d8327deb882cf99
→ Test: Bilinen hash'ler, rainbow table

URL Path: /user/profile/123
→ Test: Path'teki tüm numeric değerler
```

---

## 🎓 Best Practices

### 1. Önce Manuel Test, Sonra Dynamic

```
1. Request'i manuel inceleyin
2. Parametreleri belirleyin
3. Dynamic testing ile otomatik test edin
4. Sonuçları manuel doğrulayın
```

### 2. Hedef Odaklı Test

```
E-ticaret için:
✓ Business Logic Testing (ön planda)
✓ IDOR Testing
- GraphQL Testing (varsa)

API için:
✓ IDOR Testing
✓ JWT Testing
✓ GraphQL Testing (varsa)
- Business Logic (gerekirse)
```

### 3. AI Features'ı Kullanın

```
AI Context Analysis ile:
→ PHP + MySQL tespit edildi
→ MySQL-specific SQL injection payloads
→ Laravel-specific exploits
→ Daha yüksek başarı oranı
```

### 4. Sonuçları Raporlayın

```
Burp Scanner Issues'dan:
1. HTML Report oluşturun
2. Müşteriye sunun
3. Remediation önerilerini ekleyin
```

---

## 📞 Destek

- **Extension Hataları:** Extender → Errors
- **Output Logları:** Extender → Output
- **Issue'lar:** Burp Scanner → Issues

---

**AppSecHunter v1.0.0**
*Created by Zahid Eroglu*

🔒 **Sadece yetkili test için kullanın!**

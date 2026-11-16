# 🛡️ AppSecHunter

<div align="center">

![Version](https://img.shields.io/badge/version-2.1-blue.svg)
![Java](https://img.shields.io/badge/Java-8-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Compatible-red.svg)

**Burp Suite için ajan-tabanlı, AI-hakemli güvenlik testi**

[İngilizce (English)](README.md) · **🇹🇷 Türkçe**

</div>

---

## 📋 Genel Bakış

**AppSecHunter**, hızlı ve deterministik bir OWASP tarama motorunu; triyaj, hakemlik (adjudication), erişim-kontrol matrisi ve yerleşik bir güvenlik asistanı için tam bir **ajan-tabanlı AI katmanıyla** birleştiren bir Burp Suite eklentisidir. **Bulut** (OpenAI-uyumlu) veya **yerel** AI modelleriyle (Ollama / LM Studio / llama.cpp) çalışır — böylece trafiğiniz makinenizden çıkmayabilir.

Araç, Burp'ün kendi tarayıcısının **iyi yapamadığı** alana odaklanır: **IDOR / BOLA / BAC (kırık erişim kontrolü)**.

> ⚠️ Aktif ve otonom tarama gerçek saldırı istekleri gönderir. **Yalnızca test etmeye yetkili olduğunuz sistemlerde** kullanın.

---

## ✨ Öne Çıkanlar

- 🔓 **Sahiplik-farkında IDOR/BOLA** (`OwnershipOracle`) — public-kaynak + kendi-verisi ayırt ediciler en büyük iki IDOR yanlış-pozitifini yok eder; yalnızca *kanıtlanmış çapraz-sahip sızıntısı* raporlanır. İç içe / dizi JSON id'lerini (`{"account":{"id":…}}`, `[{"orderId":…}]`) ve **write-IDOR**'u (idempotent PUT/PATCH + durum oracle'ı) da kapsar.
- 🔐 **Yetki Matrisi** — proxy geçmişinden rolleri otomatik keşfeder, rol × endpoint matrisi kurar ve üç `AccessOracle` kuralıyla BOLA/IDOR/yetki-yükseltme avlar. CSV/HTML dışa aktarım.
- 🎯 **Senaryo-tabanlı (ground-truth) BOLA/IDOR** — geçmişten **kanıtlanabilir bir sahiplik haritası** (`AccessModel`) kurup çapraz-sahip senaryolarını hem deterministik (`ScenarioAccessTester`) hem ajan-tabanlı (`AgentPentestEngine`) sürer. Sıfıra yakın yanlış-pozitif.
- 🧠 **AI Hakemliği** — her deterministik bulgu ve her matris ihlali rapordan önce AI tarafından değerlendirilir; çürütülenler FP-işaretlenir (silinmez). AI erişilemezse "fail-open" — tarama durmaz.
- 🚦 **WAF/FW farkında ("min istek, maks bulgu")** — tek global `SharedRateLimiter` tüm istekleri dakika-tavanı + jitter ile hunileştirir; host-başına reaktif WAF devre-kesici. Engellenmeyi tetikleyen istek yağmuru yerine daha az, daha akıllı istek.
- 🔑 **Gelişmiş login profilleri** — proxy geçmişinden yakala; karmaşık JSON login'lerde hangi gövde alanının `{user}`/`{pass}` olduğunu seçtiren eşleyiciler; gövde-taşımalı oturum otomatik yapılandırması; her tarama için **taze oturum** üretimi.
- 🤖 **Bulut veya yerel AI** — OpenAI-uyumlu uç nokta veya yerel model; preset'ler, model otomatik-keşfi, bağlantı testi.
- 🛰️ **Ambient Copilot** — proxy trafiğini pasif izler, endpoint'leri **LLM'siz** skorlar, canlı **Fırsatlar** akışı sunar; otonom arka-plan avcısı bütçeli çalışır.
- 🌍 **İki dilli arayüz (TR/EN)** ve 📦 **sıfır-konfig sır yönetimi** (env → `~/.appsechunter/secrets.json`).

---

## 🔬 Tespit Nasıl Çalışır

| Yaklaşım | Hız | Ne zaman |
|---|---|---|
| **Hızlı Aktif Tarama** (deterministik) | ~5–8 sn/endpoint | Modüller prob gönderir, deterministik sinyalle yargılar; AI her adayı rapordan önce değerlendirir |
| **Yetki Matrisi** | saniye–dakika | Rolleri otomatik keşfeder, her rol × endpoint kombinasyonunu test eder |
| **Senaryo BOLA/IDOR** | dakika (bütçeli) | Geçmişten sahiplik haritası; ground-truth nesnelerle çapraz-sahip erişimi kanıtlar |
| **Ajan-tabanlı BOLA** | uyarlanır, bütçeli | AI, sahiplik haritasıyla çok-adımlı çapraz-sahip senaryolarını sürer |
| **Ambient Copilot** (pasif) | anlık, LLM'siz | Trafiği izler, skorlar, siz çalışırken Fırsatlar sunar |

> **SQLi ve XSS bilinçli olarak KAPSANMAZ** — Burp bunları iyi yapıyor; AppSecHunter erişim-kontrol boşluğuna yoğunlaşır.

Kapsadığı OWASP modülleri (deterministik, opt-in katman): IDOR (A01), Access Control (A01), Misconfiguration (A05), Mass Assignment (A08), SSRF/Open Redirect (A10), CAPTCHA bypass, Brute Force (A07), File Upload (A04/A05). Her bulgu, kanıt üreten **B-serisi probları** (B01 hata zorlama, B02 HTTP metodu, B03 transport, B04 içerik keşfi, B05 param tahmini, B06 rate-limit tespiti) ile desteklenir.

---

## 🚀 Kurulum

**Gereksinimler:** Burp Suite (Community/Professional) · derleme için **JDK 8** (`tools.jar` gerekir, tek başına JRE yetmez) · AI için bulut API anahtarı **veya** yerel model sunucusu (`ollama serve`).

```bash
# JAVA_HOME gerçek bir JDK 8'i göstermeli (sistem JRE'si değil)
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk1.8.0_241.jdk/Contents/Home
./gradlew clean jar
# Çıktı: build/libs/appsechunter-2.1.jar
```

**Burp'e yükleme:** Extensions → Installed → Add → Extension type: Java → jar'ı seçin.

**Kimlik bilgileri** (asla kaynağa gömülmez; çalışma anında çözülür): `1)` ortam değişkenleri (`APPSEC_API_KEY`, `APPSEC_GW_*`) → `2)` `~/.appsechunter/secrets.json` → `3)` Settings → API alanı. Ayrıntı: `burp.SecretsProvider`.

---

## 🎮 Kullanım

1. **Settings → API Configuration** — sağlayıcı seç:
   - **Hosted API (API anahtarı)**: herhangi bir OpenAI-uyumlu uç nokta. **Preset** seç (OpenAI, OpenRouter, Groq, Together, DeepSeek) → temel URL otomatik dolar; anahtarını yapıştır, modeli seç, **Test Connection**.
   - **Local LLM**: preset seç (Ollama `:11434/v1`, LM Studio `:1234/v1`, llama.cpp `:8080/v1`), anahtar gerekmez.
   - **Enterprise Gateway** *(gelişmiş)*: Keycloak token-exchange → iç LLM gateway'iniz.
2. Hedefi Burp proxy'si üzerinden **gezin** (site haritası/geçmişi ambient triyajı ve rol keşfini besler).
3. Bir isteğe **sağ tık → AppSecHunter →**:
   - **Hepsini Tara — Tam Otomatik** *(önerilen)* — tek onay, sonra kampanya arka planda: playbook avı, AI site avı, oto yetki-matrisi, AI yüzey keşfi, ground-truth BOLA, ajan-tabanlı BOLA.
   - **Tara — Sadece bu istek (hızlı)** — seçili istek için hızlı deterministik tarama + AI playbook.
   - **Add Session (rol ekle — opsiyonel)**.
4. İlerlemeyi **Detection**'da izle; bulgular **Findings** ve Burp **Issues**'ta; rol × endpoint ızgarası **Yetki Matrisi**'nde; Fırsatlar/asistan **Copilot**'ta.

---

## 🔧 Yapılandırma

- **AI Sağlayıcı:** Hosted API (`hosted`) · Local LLM (`local`) · Enterprise Gateway (`gateway`).
- **Detection Engine:** hızlı model, max token, rate-limit (`maxRequestsPerMinute` vars. 100, `maxRequestsPerSecond` vars. 3, paralel prob 2, ajan eşzamanlılık 2), max endpoint (vars. 40). **Varsayılan AI-odaklı**: deterministik modül yağmuru ve dizin brute-force KAPALI; erişim-kontrol katmanı her zaman çalışır.
- **Yetki Matrisi:** otomatik rol-keşfi, AccessOracle kuralları (V1/V2/V3), mutasyon-metodu onayı, OpenAPI spec yolu.

---

## 🔐 Güvenlik ve Gizlilik
- **Yerel modelle** hiçbir tarama verisi makinenizden çıkmaz.
- Sonuçlar yerelde (SQLite) saklanır; API anahtarları Burp tercihlerinde tutulur.
- Aktif taramayı yalnızca **yetkili hedeflerde** çalıştırın.

---

## 📜 Lisans
MIT Lisansı — © Zahid Eroğlu. Bkz. [LICENSE](LICENSE).

## 👨‍💻 Yazar
**Zahid Eroğlu**

---

<div align="center">

**Zahid Eroğlu tarafından ❤️ ile yapıldı** — işinize yaradıysa bir ⭐ bırakın

</div>

package burp.i18n;

import java.util.HashMap;
import java.util.Map;

/**
 * Tiny self-contained i18n catalog (Turkish / English). Every user-facing string lives here
 * keyed by a stable id; {@link #t(String)} returns it in the current language.
 *
 * <p>Design notes:
 * <ul>
 *   <li>The catalog is held in code (not a {@code .properties} resource) so it always
 *       loads from the Burp fat-jar regardless of classloader quirks.</li>
 *   <li>Missing/empty translations fall back to Turkish, then to the key itself — so a
 *       half-migrated UI never shows blanks.</li>
 *   <li>Switching is live: see {@link I18nUI#relocalize(java.awt.Component)}.</li>
 * </ul>
 *
 * @author Zahid Eroglu
 */
public final class I18n {

    public enum Lang { TR, EN }

    private static volatile Lang current = Lang.TR;
    private static final Map<String, String[]> C = new HashMap<>(); // key -> {tr, en}

    private I18n() {}

    // ---- language state -----------------------------------------------------

    public static void setLang(Lang l) { if (l != null) current = l; }

    /** Accepts "tr"/"en" (case-insensitive); anything else → Turkish. */
    public static void setLang(String code) {
        current = (code != null && code.trim().toLowerCase().startsWith("en")) ? Lang.EN : Lang.TR;
    }

    public static Lang getLang() { return current; }

    /** Two-letter code for persistence ("tr"/"en"). */
    public static String code() { return current == Lang.EN ? "en" : "tr"; }

    public static boolean isTr() { return current == Lang.TR; }

    // ---- lookup -------------------------------------------------------------

    /** Translate by key in the current language (TR fallback, then the key). */
    public static String t(String key) {
        if (key == null) return "";
        String[] v = C.get(key);
        if (v == null) return key;
        String s = (current == Lang.EN) ? v[1] : v[0];
        if (s == null || s.isEmpty()) s = v[0];
        // Strip decorative emoji when the running font can't render them (avoids □ tofu on
        // every label/button/tooltip). No-op on emoji-capable fonts. See Glyphs.
        return Glyphs.clean((s == null) ? key : s);
    }

    /** Translate with positional {0},{1}... placeholders. */
    public static String t(String key, Object... args) {
        String s = t(key);
        if (args != null) {
            for (int i = 0; i < args.length; i++) {
                s = s.replace("{" + i + "}", String.valueOf(args[i]));
            }
        }
        return s;
    }

    private static void put(String key, String tr, String en) { C.put(key, new String[]{tr, en}); }

    // =====================================================================
    //  Catalog. Grouped by UI area. Extend phase by phase.
    // =====================================================================
    static {
        // ---- tab captions ----
        put("tab.scanner",    "Tarayıcı",       "Scanner");
        put("tab.findings",   "Bulgular",       "Findings");
        put("tab.authmatrix", "Yetki Matrisi",  "Authorization Matrix");
        put("tab.copilot",    "Copilot",        "Copilot");
        put("tab.settings",   "Ayarlar",        "Settings");

        // ---- right-click context menu (BurpExtender.createMenuItems) ----
        put("menu.everything", "Hepsini Tara — Tam Otomatik (arka planda)",
                               "Scan Everything — Fully Automatic (background)");
        put("menu.everything.tip",
                "Tek tıkla tüm kampanyaları arka planda çalıştırır: bu isteğin tam taraması, site + proxy "
                        + "history ve otomatik yetki matrisi (BOLA/IDOR/yetki yükseltme)",
                "Runs every campaign in the background with one click: full scan of this request, site + proxy "
                        + "history and the automatic authorization matrix (BOLA/IDOR/priv-esc)");
        put("menu.everything.tip.ai", " + AI yüzey keşfi ve ground-truth/agentic BOLA senaryoları",
                                       " + AI surface discovery and ground-truth/agentic BOLA scenarios");
        put("menu.everything.tip.noai", " (AI kapalı — AI adımları atlanır)", " (AI off — AI steps are skipped)");
        put("menu.thisreq", "Tara — Sadece bu istek (hızlı)", "Scan — This request only (fast)");
        put("menu.thisreq.tip",
                "Yalnızca seçili isteği tüm modüllerle hızlıca tarar (site/history ve yetki senaryoları olmadan)",
                "Quickly scans only the selected request with all modules (no site/history or authz scenarios)");
        put("menu.thisreq.tip.ai", " + AI Pentester", " + AI Pentester");
        put("menu.addsession", "Add Session (rol ekle — opsiyonel)", "Add Session (add role — optional)");
        put("menu.addsession.tip",
                "Bu isteğin auth token'larını bir rol olarak kaydet. Opsiyonel — yetki matrisi rolleri "
                        + "history'den otomatik de bulur; elle rol eklemek doğruluğu artırır.",
                "Register this request's auth tokens as a role. Optional — the authorization matrix also "
                        + "auto-discovers roles from history; adding one manually improves accuracy.");
        put("menu.loginprofile", "🔐 Login isteği olarak kaydet (oto re-login)",
                                 "🔐 Save as login request (auto re-login)");
        put("menu.loginprofile.tip",
                "Bu login isteğini ŞİFRELİ saklar; tarama sırasında oturum düşerse araç bu isteği tekrarlayıp "
                        + "kendini yeniden login eder. Şifreleme anahtarı OS keychain'de tutulur.",
                "Stores this login request ENCRYPTED; if the session drops during a scan the tool replays it to "
                        + "re-login itself. The encryption key is kept in the OS keychain.");

        // ---- Scanner tab: launcher toolbar + run list (DetectionPanel) ----
        put("scan.launch.everything", "🚀 Hepsini Tara", "🚀 Scan Everything");
        put("scan.launch.everything.tip",
                "Bir istek seç → tüm kampanyaları arka planda çalıştır (tam tarama, site+history, "
                        + "otomatik yetki matrisi; AI açıksa yüzey keşfi + BOLA senaryoları)",
                "Pick a request → run every campaign in the background (full scan, site+history, "
                        + "automatic authorization matrix; if AI is on: surface discovery + BOLA scenarios)");
        put("scan.launch.thisreq", "⚡ Tara — Sadece bu istek", "⚡ Scan — This request only");
        put("scan.launch.thisreq.tip",
                "Bir istek seç → yalnızca o isteği hızlıca tara (deterministik + AI). Aktif taramalar listesine eklenir.",
                "Pick a request → quickly scan only that request (deterministic + AI). Added to the active-scan list.");
        put("scan.launch.domain", "🌐 Scan Domain", "🌐 Scan Domain");
        put("scan.launch.domain.tip",
                "Bir istek seç → o host'un tüm site + proxy history girdili uçlarını deterministik tara",
                "Pick a request → deterministically scan all input-bearing site + proxy-history endpoints of that host");

        put("scan.header.title", "🛡️ Aktif Taramalar", "🛡️ Active Scans");
        put("scan.count", "· {0} çalıştırma", "· {0} runs");
        put("scan.btn.closeFinished", "Bitenleri Kapat", "Close Finished");
        put("scan.btn.closeFinished.tip", "Tamamlanan çalıştırmaların sekmelerini kapat",
                                          "Close the tabs of finished runs");
        put("scan.btn.closeAll", "Tümünü Kapat", "Close All");
        put("scan.btn.closeAll.tip", "Tüm çalıştırma sekmelerini kapat (çalışanlar durdurulur)",
                                     "Close all run tabs (running ones are aborted)");
        put("scan.tab.info", "Bilgi", "Info");
        put("scan.placeholder",
                "\nHenüz çalıştırma yok.\n\n"
                        + "Yukarıdaki 🚀 Hepsini Tara / ⚡ Tara — Sadece bu istek / 🌐 Scan Domain\n"
                        + "butonlarını kullanın ya da bir isteğe sağ tıklayın → AppSecHunter ▸ Hepsini Tara.",
                "\nNo runs yet.\n\n"
                        + "Use the 🚀 Scan Everything / ⚡ Scan — This request only / 🌐 Scan Domain\n"
                        + "buttons above, or right-click a request → AppSecHunter ▸ Scan Everything.");
        put("scan.run.close", "Kapat", "Close");
        put("scan.run.closeOthers", "Diğerlerini Kapat", "Close Others");
        put("scan.run.closeAll", "Tümünü Kapat", "Close All");
        put("scan.run.closeTab.tip", "Sekmeyi kapat", "Close tab");
        put("scan.run.rerun.tip", "Bu taramayı yeniden çalıştır (yeni sekmede)", "Re-run this scan (in a new tab)");
        put("scan.run.rerun.title", "Yeniden Çalıştır", "Re-run");
        put("scan.run.rerun.running", "Bu çalıştırma hâlâ sürüyor — bitince yeniden çalıştırın.",
                                      "This run is still in progress — re-run it when it finishes.");
        put("scan.run.rerun.unsupported", "Bu sekme yeniden çalıştırmayı desteklemiyor.",
                                          "This tab does not support re-running.");

        // ---- Settings: language selector (rest of SettingsPanel migrates in a later phase) ----
        put("settings.language.label", "Dil / Language", "Language / Dil");
        put("settings.language.tip", "Arayüz dili. Değişiklik anında uygulanır.",
                                     "Interface language. Applied immediately.");
        put("lang.tr", "Türkçe", "Türkçe");
        put("lang.en", "English", "English");

        // ---- live connection-test dialog (SettingsPanel.LiveTestDialog) ----
        put("settings.live.title", "Bağlantı Testi", "Connection Test");
        put("settings.live.starting", "Test başlatılıyor…", "Starting test…");
        put("settings.live.checking.models", "API erişilebilirliği kontrol ediliyor…", "Checking API reachability…");
        put("settings.live.checking.selected", "Seçili model test ediliyor: {0}", "Testing selected model: {0}");
        put("settings.live.searching", "Çalışan alternatif modeller aranıyor…", "Searching for working alternative models…");
        put("settings.live.trying", "Deneniyor: {0}", "Trying: {0}");
        put("settings.live.workinglist", "Seçili model (yanıt + süre):", "Selected model (response + time):");
        put("settings.live.probing.parallel", "{0} model aynı anda test ediliyor (yavaş modeller yüklenebilir, 60sn'ye kadar)…", "Testing {0} models in parallel (slow models may be loading, up to 60s)…");
        put("settings.live.progress", "{0}/{1} model sonuçlandı · diğerleri bekleniyor…", "{0}/{1} models done · waiting for the rest…");
        put("settings.live.pickworking", "Bu model çalışmıyor (✗). Listeden 🛡 puanlı (çalışan) bir model seçin.", "This model isn't working (✗). Pick a 🛡-scored (working) model from the list.");
        put("settings.live.seclegend", "🛡 Güvenlik puanı (10 = en güvenli)",
                                       "🛡 Security score (10 = most secure)");
        put("settings.live.use", "Bu modeli kullan", "Use this model");
        put("settings.live.retry", "Tekrar Dene", "Retry");
        put("settings.live.close", "Kapat", "Close");
        put("settings.live.selectedok", "✓ Seçili model çalışıyor: {0} ({1} ms)", "✓ Selected model works: {0} ({1} ms)");
        put("settings.live.selectedfail", "✗ Seçili model çalışmadı: {0}\n  {1}", "✗ Selected model failed: {0}\n  {1}");
        put("settings.live.gw.ok", "✓ Bağlantı başarılı: {0} ({1} ms)", "✓ Connection OK: {0} ({1} ms)");
        put("settings.live.pick", "Seçili model ({0}) çalışmadı. Aşağıdan çalışan bir model seçip 'Bu modeli kullan'a basın:",
                                  "Selected model ({0}) failed. Pick a working one below and click 'Use this model':");
        put("settings.live.none", "Hiçbir model yanıt vermedi ({0} dahil). API anahtarını, uç noktayı ve ağ erişimini kontrol edin.",
                                  "No model responded (including {0}). Check the API key, endpoint and network access.");
        put("settings.live.failed", "Bağlantı başarısız: {0}", "Connection failed: {0}");

        // ===================================================================
        //  Phase 2 — bulk workflow migration (2026-06-22): SettingsPanel,
        //  FindingsPanel, AssistantPanel, AuthMatrixPanel, DetectionRunView, dialogs.
        // ===================================================================
        // ---- SettingsPanel.java (184) ----
        put("settings.title", "Ayarlar", "Settings");
        put("settings.advanced.toggle", "🔧 Gelişmiş Ayarlar", "🔧 Advanced Settings");
        put("settings.api.title", "API Yapılandırması", "API Configuration");
        put("settings.api.provider", "API Sağlayıcı:", "API Provider:");
        put("settings.api.provider.tip", "API sağlayıcı seçin", "Select API provider");
        put("settings.provider.hosted", "Barındırılan API (API anahtarı)", "Hosted API (API key)");
        put("settings.provider.local", "Yerel LLM", "Local LLM");
        put("settings.provider.gateway", "Kurumsal Gateway", "Enterprise Gateway");
        put("settings.api.preset", "Hazır Ayar:", "Preset:");
        put("settings.api.preset.tip", "Yaygın sağlayıcılar için temel URL'yi doldurur (OpenAI, OpenRouter, Groq, Together, DeepSeek)", "Fills the base URL for a common provider (OpenAI, OpenRouter, Groq, Together, DeepSeek)");
        put("settings.api.endpoint", "API Uç Noktası:", "API Endpoint:");
        put("settings.api.endpoint.tip", "OpenAI-uyumlu temel URL (ör. https://openrouter.ai/api/v1)", "OpenAI-compatible base URL (e.g. https://openrouter.ai/api/v1)");
        put("settings.api.key", "API Anahtarı:", "API Key:");
        put("settings.api.key.tip", "API anahtarınız (sağlayıcı gerektiriyorsa)", "Your API key (if the provider requires one)");
        put("settings.api.model", "Model:", "Model:");
        put("settings.api.model.tip", "AI modeli seçin veya özel model adı girin", "Select AI model or enter custom model name");
        put("settings.api.model.refresh.tip", "Kullanılabilir modelleri API'den yenile", "Refresh available models from API");
        put("settings.api.timeout", "Zaman aşımı (saniye):", "Timeout (seconds):");
        put("settings.gateway.title", "Gateway API Ayarları", "Gateway API Settings");
        put("settings.gateway.username", "Kullanıcı Adı:", "Username:");
        put("settings.gateway.username.tip", "Gateway API kullanıcı adı", "Gateway API username");
        put("settings.gateway.password", "Parola:", "Password:");
        put("settings.gateway.password.tip", "Gateway API parolası", "Gateway API password");
        put("settings.gateway.clientid", "İstemci Kimliği:", "Client ID:");
        put("settings.gateway.clientid.tip", "Gateway API istemci kimliği", "Gateway API client ID");
        put("settings.gateway.clientsecret", "İstemci Sırrı:", "Client Secret:");
        put("settings.gateway.clientsecret.tip", "Gateway API istemci sırrı", "Gateway API client secret");
        put("settings.gateway.subject", "İstenen Özne:", "Requested Subject:");
        put("settings.gateway.subject.tip", "Gateway API istenen öznesi", "Gateway API requested subject");
        put("settings.local.title", "Yerel AI Modeli Ayarları", "Local AI Model Settings");
        put("settings.local.preset", "Yerel Hazır Ayar:", "Local Preset:");
        put("settings.local.preset.tip", "Yaygın yerel model sunucuları için hızlı hazır ayarlar", "Quick presets for common local model servers");
        put("settings.local.endpoint", "Yerel Uç Nokta:", "Local Endpoint:");
        put("settings.local.endpoint.tip", "OpenAI uyumlu temel URL, örn. http://localhost:11434/v1", "OpenAI-compatible base URL, e.g. http://localhost:11434/v1");
        put("settings.local.model", "Yerel Model:", "Local Model:");
        put("settings.local.model.tip", "Yerel model adı (örn. qwen2.5-coder:7b) veya yenile'ye tıklayın", "Local model name (e.g. qwen2.5-coder:7b) or click refresh");
        put("settings.local.model.refresh.tip", "Kullanılabilir modelleri yerel sunucudan yenile", "Refresh available models from local server");
        put("settings.local.key", "API Anahtarı (isteğe bağlı):", "API Key (optional):");
        put("settings.local.key.tip", "Ollama/llama.cpp için boş bırakın; LM Studio için herhangi bir değer", "Leave empty for Ollama/llama.cpp; any value for LM Studio");
        put("settings.local.info", "Yerel modeller için API anahtarı gerekmez. localhost için düz http'ye izin verilir.", "No API key needed for local models. Plain http is allowed for localhost.");
        put("settings.scan.title", "🔍 Tarama Yapılandırması", "🔍 Scan Configuration");
        put("settings.scan.autoscan", "Yakalanan istekleri otomatik tara", "Auto-scan intercepted requests");
        put("settings.scan.usescope", "Yalnızca Burp kapsamındaki URL'leri tara", "Only scan URLs in Burp scope");
        put("settings.scan.marker", "Tarama trafiğini tanımlama başlığıyla imzala (sorumlu test)", "Tag scan traffic with an identifying header (responsible testing)");
        put("settings.scan.marker.tip", "AppSecHunter'ın hedefe gönderdiği her isteğe bir tanımlama başlığı ekler; böylece mavi takım yetkili tarama trafiğini gerçek saldırıdan ayırabilir.", "Adds an identifying header to every request AppSecHunter sends to the target, so the blue team can tell authorized scan traffic from a real attack.");
        put("settings.scan.confidence", "Minimum Güven Eşiği:", "Minimum Confidence Threshold:");
        put("settings.filters.title", "🔧 İstek Filtreleri", "🔧 Request Filters");
        put("settings.filters.static", "Statik dosyaları filtrele (.js, .css, .jpg, .png, vb.)", "Filter static files (.js, .css, .jpg, .png, etc.)");
        put("settings.filters.cdn", "CDN isteklerini filtrele", "Filter CDN requests");
        put("settings.filters.analytics", "Analitik/izleme isteklerini filtrele", "Filter analytics/tracking requests");
        put("settings.filters.social", "Sosyal medya gömülerini filtrele", "Filter social media embeds");
        put("settings.filters.options", "OPTIONS isteklerini filtrele", "Filter OPTIONS requests");
        put("settings.filters.custom", "Filtrelenecek özel URL desenleri (her satıra bir tane):", "Custom URL patterns to filter (one per line):");
        put("settings.vuln.title", "🛡️ Kontrol Edilecek Zafiyet Türleri", "🛡️ Vulnerability Types to Check");
        put("settings.vuln.sqli", "SQL Enjeksiyonu", "SQL Injection");
        put("settings.vuln.xss", "Siteler Arası Betik Çalıştırma (XSS)", "Cross-Site Scripting (XSS)");
        put("settings.vuln.idor", "Güvensiz Doğrudan Nesne Referansı (IDOR)", "Insecure Direct Object Reference (IDOR)");
        put("settings.vuln.ssrf", "Sunucu Taraflı İstek Sahteciliği (SSRF)", "Server-Side Request Forgery (SSRF)");
        put("settings.vuln.lfi", "Yerel Dosya Dahil Etme (LFI)", "Local File Inclusion (LFI)");
        put("settings.vuln.cmdinj", "Komut Enjeksiyonu", "Command Injection");
        put("settings.dynamic.title", "⚡ Dinamik Test (Aktif Tarama)", "⚡ Dynamic Testing (Active Scanning)");
        put("settings.dynamic.desc", "Bu testler uygulamayı aktif olarak yoklar. Yalnızca yetkili hedeflerde kullanın.", "These tests actively probe the application. Use only on authorized targets.");
        put("settings.dynamic.bizlogic", "İş Mantığı Testi (Fiyat, Miktar, Kupon İstismarı)", "Business Logic Testing (Price, Quantity, Coupon Abuse)");
        put("settings.dynamic.idor", "IDOR Testi (Sıralı ID'ler, UUID'ler, Base64, Hash'ler)", "IDOR Testing (Sequential IDs, UUIDs, Base64, Hashes)");
        put("settings.dynamic.jwt", "JWT Testi (Algoritma Karışıklığı, None Algoritması, İddialar)", "JWT Testing (Algorithm Confusion, None Algorithm, Claims)");
        put("settings.dynamic.waf", "WAF Tespiti ve Atlatma (Tespit edildiğinde otomatik hız sınırlama)", "WAF Detection & Evasion (Auto-throttle on detection)");
        put("settings.dynamic.usage", "Nasıl kullanılır: İsteğe sağ tıklayın → \"⚡ Run Dynamic Tests\"", "How to use: Right-click request → \"⚡ Run Dynamic Tests\"");
        put("settings.aifeatures.title", "🤖 AI Destekli Özellikler", "🤖 AI-Powered Features");
        put("settings.aifeatures.desc", "Tarama doğruluğunu artıran ve yanlış pozitifleri azaltan gelişmiş AI özellikleri.", "Advanced AI features that enhance scanning accuracy and reduce false positives.");
        put("settings.aifeatures.context", "AI Bağlam Analizi (Teknoloji yığını, framework, veritabanını otomatik algıla)", "AI Context Analysis (Auto-detect tech stack, framework, database)");
        put("settings.aifeatures.smartpayloads", "Akıllı Payload Üretimi (Teknolojiye özel payload'lar)", "Smart Payload Generation (Technology-specific payloads)");
        put("settings.aifeatures.fpfilter", "AI Yanlış Pozitif Filtresi (Bulguları AI ile doğrula)", "AI False Positive Filter (Verify findings with AI)");
        put("settings.engine.title", "⚡ Tespit Motoru (Hızlı Aktif Tarama)", "⚡ Detection Engine (Fast Active Scan)");
        put("settings.engine.fastmodel.enabled", "Motor için ayrı bir hızlı model kullan", "Use a separate fast model for the engine");
        put("settings.engine.fastmodel", "Hızlı model (boş = ana):", "Fast model (blank = main):");
        put("settings.engine.maxtokens", "Motor maksimum token:", "Engine max tokens:");
        put("settings.engine.parallel", "Paralel istek:", "Parallel requests:");
        put("settings.engine.sitelimit", "Site/Geçmiş tarama girdi (uç) limiti:", "Site/History scan entry (endpoint) limit:");
        put("settings.engine.reqpermin", "Dakikada maks istek (WAF/FW koruması):", "Max requests/min (WAF/FW guard):");
        put("settings.engine.modules", "Modüller (OWASP):", "Modules (OWASP):");
        put("settings.engine.mod.idor", "IDOR / Nesne Erişimi (A01)", "IDOR / Object Access (A01)");
        put("settings.engine.mod.access", "Bozuk Erişim Denetimi / Kimlik doğrulama atlatma (A01)", "Broken Access Control / Auth bypass (A01)");
        put("settings.engine.mod.injection", "Enjeksiyon: SQLi / XSS / Traversal (A03)", "Injection: SQLi / XSS / Traversal (A03)");
        put("settings.engine.mod.misconfig", "Güvenlik Yanlış Yapılandırması / CORS / başlıklar (A05)", "Security Misconfiguration / CORS / headers (A05)");
        put("settings.engine.mod.ssrf", "SSRF / Açık Yönlendirme (A10)", "SSRF / Open Redirect (A10)");
        put("settings.engine.aggressive.title", "⚠️ Agresif / Müdahaleci testler (tarama başına onaylı):", "⚠️ Aggressive / Intrusive tests (confirmed per scan):");
        put("settings.engine.aggressive.warn", "Hesapları kilitleyebilir, dosya yükleyebilir veya iç ana bilgisayarlara ulaşabilir. Yalnızca yetkili hedeflerde kullanın.", "May lock accounts, upload files, or reach internal hosts. Use only on authorized targets.");
        put("settings.engine.agg.brute", "Oturum Açma Kaba Kuvvet (A07)", "Login Brute Force (A07)");
        put("settings.engine.agg.upload", "Dosya Yükleme (A04/A05)", "File Upload (A04/A05)");
        put("settings.engine.agg.ssrf", "Aktif SSRF (localhost / bulut meta verisi)", "Active SSRF (localhost / cloud metadata)");
        put("settings.engine.agg.cmdtiming", "Komut Enjeksiyonu (zamanlama)", "Command Injection (timing)");
        put("settings.engine.deepai", "Derin AI geçişi (daha yavaş; tüm hat üzerinde ek AI analizi)", "Deep AI pass (slower; extra AI analysis on full pipeline)");
        put("settings.agent.title", "🤖 AI Pentester (ajan ReAct):", "🤖 AI Pentester (agentic ReAct):");
        put("settings.agent.movedNote",
                "🤖 AI Pentester ayarları ve 🔐 Login profilleri artık “Yetki Matrisi” sekmesindeki “🔐 Login Profilleri” butonunda.",
                "🤖 AI Pentester settings and 🔐 Login profiles are now under the “🔐 Login Profiles” button on the “Authorization Matrix” tab.");
        put("settings.agent.maxsteps", "Ajan maksimum adım:", "Agent max steps:");
        put("settings.agent.model", "Ajan modeli (boş = motor):", "Agent model (blank = engine):");
        put("settings.agent.login.label", "Login profilleri (otomatik taze oturum) — JSON dizisi:", "Login profiles (automatic fresh session) — JSON array:");
        put("settings.agent.login.tip", "Her rol için login reçetesi; access-control taramasından önce login olup taze token alınır.", "Login recipe for each role; logs in and obtains a fresh token before the access-control scan.");
        put("settings.agent.login.help", "Örnek: [{\"roleName\":\"user1\",\"loginUrl\":\"https://host/rest/user/login\",\"bodyTemplate\":\"{\\\"email\\\":\\\"{user}\\\",\\\"password\\\":\\\"{pass}\\\"}\",\"username\":\"a@b.com\",\"password\":\"pass\",\"tokenJsonPath\":\"authentication.token\"}]\nPlaceholder: {user}/{pass} → bodyTemplate; {token} → authValueTemplate (örn. \"Bearer {token}\"). Token için tokenJsonPath (nokta yolu) veya tokenRegex (grup 1).", "Example: [{\"roleName\":\"user1\",\"loginUrl\":\"https://host/rest/user/login\",\"bodyTemplate\":\"{\\\"email\\\":\\\"{user}\\\",\\\"password\\\":\\\"{pass}\\\"}\",\"username\":\"a@b.com\",\"password\":\"pass\",\"tokenJsonPath\":\"authentication.token\"}]\nPlaceholder: {user}/{pass} → bodyTemplate; {token} → authValueTemplate (e.g. \"Bearer {token}\"). For the token use tokenJsonPath (dot path) or tokenRegex (group 1).");
        put("settings.agent.login.testbtn", "🔑 Login profillerini test et", "🔑 Test login profiles");
        put("settings.agent.usesessions", "Kayıtlı çoklu oturum kimliklerini kullan (IDOR/BOLA/yetki yükseltme tekrarı)", "Use saved multi-session identities (IDOR/BOLA/privesc replay)");
        put("settings.agent.focus.access", "Odak: Bozuk erişim denetimi / IDOR / BOLA", "Focus: Broken access control / IDOR / BOLA");
        put("settings.agent.focus.biz", "Odak: İş mantığı ve iş akışı istismarı", "Focus: Business logic & workflow abuse");
        put("settings.agent.focus.auth", "Odak: Kimlik doğrulama / JWT atlatma", "Focus: Auth / JWT bypass");
        put("settings.agent.focus.chain", "Odak: Çok adımlı saldırı zincirleri", "Focus: Multi-step attack chains");
        put("settings.agent.rawreq", "⚠️ Ham istek geçersiz kılmaya izin ver (gelişmiş; kapalı = güvenli)", "⚠️ Allow raw-request override (advanced; off = safe)");
        put("settings.ambient.title", "🛰️ Ortam Güvenlik Yardımcısı:", "🛰️ Ambient Security Copilot:");
        put("settings.ambient.warn", "Otonom avlama, yetkili hedeflerde arka planda otomatik istek gönderir. Yalnızca kapsamdaki / izinli sistemlerde kullanın.", "Autonomous hunting automatically sends background requests on authorized targets. Use only on in-scope / authorized systems.");
        put("settings.ambient.passive", "Pasif triyaj (trafiği izle, fırsatları öner)", "Passive triage (watch traffic, suggest opportunities)");
        put("settings.ambient.hunter", "⚠️ Otonom arka plan avcısı (kendiliğinden test gönderir)", "⚠️ Autonomous background hunter (sends tests on its own)");
        put("settings.ambient.scopeonly", "Yalnızca Burp kapsamı içinde otonom çalış", "Run autonomously only within Burp scope");
        put("settings.ambient.sharelimiter", "Hız limitini manuel taramalarla paylaş (global RPS)", "Share rate limit with manual scans (global RPS)");
        put("settings.ambient.minscore", "Fırsat eşik skoru (min):", "Opportunity threshold score (min):");
        put("settings.ambient.concurrency", "Avcı eşzamanlılık:", "Hunter concurrency:");
        put("settings.ambient.tokenbudget", "Token bütçesi (0 = sınırsız):", "Token budget (0 = unlimited):");
        put("settings.ambient.timebudget", "Süre bütçesi dk (0 = sınırsız):", "Time budget min (0 = unlimited):");
        put("settings.ambient.routermode", "Playbook yönlendirici modu:", "Playbook router mode:");
        put("settings.scan.heuristic", "Deterministik (heuristik) modül taraması — varsayılan KAPALI, sadece AI", "Deterministic (heuristic) module scan — default OFF, AI-only");
        // --- Ayar açıklamaları (fare-üstü tooltip'ler) ---
        put("settings.engine.fastmodel.enabled.tip",
                "Açıkken motorun AI yardımcıları ana ajan modeli yerine aşağıdaki hızlı modeli kullanır (daha hızlı, daha ucuz).",
                "When on, the engine's AI helpers use the fast model below instead of the main agent model (faster, cheaper).");
        put("settings.engine.fastmodel.tip",
                "Motorun kullanacağı hızlı modelin adı. Boş bırakılırsa ana model kullanılır.",
                "Name of the fast model the engine uses. Leave empty to use the main model.");
        put("settings.engine.maxtokens.tip",
                "Motor-içi AI çağrılarının üretebileceği maksimum token. Düşük = daha hızlı/ucuz ama daha kısa yanıt.",
                "Max tokens the engine's in-scan AI calls may generate. Lower = faster/cheaper but shorter answers.");
        put("settings.engine.parallel.tip",
                "Deterministik taramada aynı anda gönderilen probe sayısı. Düşük = hedefe nazik (WAF/FW riski azalır), yüksek = hızlı. Varsayılan 2.",
                "Number of probes sent at once in the deterministic scan. Lower = gentler on the target (less WAF/FW risk), higher = faster. Default 2.");
        put("settings.engine.sitelimit.tip",
                "Bir site/geçmiş taramasında işlenecek maksimum benzersiz uç (endpoint) sayısı. Yalnız id'de farklılaşan tekrarlar şablon olarak tekilleştirilir. Varsayılan 60.",
                "Max unique endpoints processed per site/history scan. Repeats that differ only by id are de-duplicated by template. Default 60.");
        put("settings.engine.reqpermin.tip",
                "Tüm tarama yollarının paylaştığı dakika başına TOPLAM istek tavanı. Firewall'un dakikalık oturum sınırının (genelde 200-300) güvenle altında tutar; aşılınca istekler bekletilip zamana yayılır. Varsayılan 100.",
                "Hard per-minute TOTAL request ceiling shared by all scan paths. Stays safely below the firewall's sessions/min limit (usually 200-300); excess requests are delayed and spread over time. Default 100.");
        put("settings.ambient.minscore.tip",
                "Otonom avcının bir ucu test etmeye değer sayması için gereken minimum fırsat skoru. Yüksek = daha seçici (daha az arka plan trafiği).",
                "Minimum opportunity score for the autonomous hunter to test an endpoint. Higher = more selective (less background traffic).");
        put("settings.ambient.concurrency.tip",
                "Aynı anda çalışan paralel AI ajan sayısı. Düşük = hedefe nazik (WAF/FW riski azalır). Varsayılan 2.",
                "Number of parallel AI agents running at once. Lower = gentler on the target (less WAF/FW risk). Default 2.");
        put("settings.ambient.tokenbudget.tip",
                "Bir site taraması için harcanabilecek toplam AI token tavanı. 0 = sınırsız. Bütçe dolunca tarama durur.",
                "Total AI token ceiling for one site scan. 0 = unlimited. The scan stops when the budget is exhausted.");
        put("settings.ambient.timebudget.tip",
                "Bir site taramasının maksimum süresi (dakika). 0 = sınırsız. Süre dolunca tarama durur.",
                "Maximum duration of one site scan in minutes. 0 = unlimited. The scan stops when time runs out.");
        put("settings.ambient.routermode.tip",
                "Her uçta hangi AI playbook'larının çalışacağını belirler. 'ai' = LLM ilgili 1-3'ü seçer (önerilen, en az istek). 'heuristic' = sinyal eşleşenler. 'all' = hepsi (en çok istek).",
                "Decides which AI playbooks run per endpoint. 'ai' = the LLM picks the relevant 1-3 (recommended, fewest requests). 'heuristic' = signal-matched ones. 'all' = every playbook (most requests).");
        put("settings.scan.heuristic.tip",
                "Açıkken AI'nın yanında deterministik modül taraması da çalışır (IDOR/misconfig/header/SSRF vb. — daha kapsamlı ama saldırı-şekilli probe'lar WAF'ı tetikleyebilir). Kapalı (varsayılan) = sadece AI tabanlı tarama.",
                "When on, the deterministic module scan runs alongside AI (IDOR/misconfig/headers/SSRF etc. — more thorough, but attack-shaped probes can trip a WAF). Off (default) = AI-based scanning only.");
        put("settings.action.save", "Ayarları Kaydet", "Save Settings");
        put("settings.action.test", "Bağlantıyı Test Et", "Test Connection");
        put("settings.action.reset", "Varsayılanlara Sıfırla", "Reset to Defaults");
        put("settings.action.cleardb", "🗑️ Veritabanını Temizle", "🗑️ Clear Database");
        put("settings.mode.label", "Mod:", "Mode:");
        put("settings.mode.safe", "🛡️ Güvenli", "🛡️ Safe");
        put("settings.mode.balanced", "⚖️ Dengeli", "⚖️ Balanced");
        put("settings.mode.aggressive", "🔥 Agresif", "🔥 Aggressive");
        put("settings.mode.safe.tip", "Salt-okunur tespit; durum-değiştiren / agresif testler kapalı.", "Read-only detection; state-changing / aggressive tests off.");
        put("settings.mode.balanced.tip", "Tüm tespit modülleri açık; agresif (brute/upload/aktif-SSRF/cmd) kapalı.", "All detection modules on; aggressive (brute/upload/active-SSRF/cmd) off.");
        put("settings.mode.aggressive.tip", "Agresif + durum-değiştiren testler AÇIK — YALNIZCA izole test ortamı!", "Aggressive + state-changing tests ON — ISOLATED test environment ONLY!");
        put("settings.mode.applied", "Mod uygulandı: {0}", "Mode applied: {0}");
        put("settings.mode.applied.aggressive", "🔥 Agresif — durum-değiştiren testler AÇIK (yalnız izole test ortamı!)", "🔥 Aggressive — state-changing tests ON (isolated test environment only!)");
        put("settings.mode.applied.balanced", "⚖️ Dengeli — tüm tespit modülleri, agresif KAPALI", "⚖️ Balanced — all detection modules, aggressive OFF");
        put("settings.mode.applied.safe", "🛡️ Güvenli — salt-okunur tespit, agresif KAPALI", "🛡️ Safe — read-only detection, aggressive OFF");
        put("settings.mode.applied.title", "Mod", "Mode");
        put("settings.usage.title", "🤖 AI Kullanımı (Token İstatistikleri)", "🤖 AI Usage (Token Statistics)");
        put("settings.usage.calls", "Toplam AI çağrısı:", "Total AI calls:");
        put("settings.usage.tokens", "Toplam token:", "Total tokens:");
        put("settings.usage.prompt", "   • Prompt (girdi):", "   • Prompt (input):");
        put("settings.usage.completion", "   • Completion (çıktı):", "   • Completion (output):");
        put("settings.usage.cache", "Cache'den (ücretsiz):", "From cache (free):");
        put("settings.usage.since", "Sayım başlangıcı:", "Counting since:");
        put("settings.usage.refresh", "🔄 Yenile", "🔄 Refresh");
        put("settings.usage.reset", "Sıfırla", "Reset");
        put("settings.usage.reset.confirm", "AI kullanım sayaçları sıfırlansın mı?", "Reset AI usage counters?");
        put("settings.usage.reset.confirm.title", "Onay", "Confirm");
        put("settings.usage.note", "Not: Site/Geçmiş taraması AI kullanmaz (0 token). Token harcaması yalnızca \"Dynamic Tests\" / Detection Pipeline akışındadır.", "Note: Site/History scan does not use AI (0 tokens). Token spending occurs only in the \"Dynamic Tests\" / Detection Pipeline flow.");
        put("settings.usage.errors", "({0} hata)", "({0} errors)");
        put("settings.usage.value.tokens", "{0} token", "{0} tokens");
        put("settings.usage.value.calls", "{0} çağrı", "{0} calls");
        put("settings.usage.lastseen", "  →  son: {0}", "  →  last: {0}");
        put("settings.login.empty", "Geçerli profil bulunamadı. JSON dizisi formatını ve roleName/loginUrl alanlarını kontrol edin.", "No valid profile found. Check the JSON array format and the roleName/loginUrl fields.");
        put("settings.login.test.title", "Login Testi", "Login Test");
        put("settings.login.token", "token: {0}", "token: {0}");
        put("settings.login.error", "HATA: {0}", "ERROR: {0}");
        put("settings.login.results.title", "Login Testi Sonuçları", "Login Test Results");
        // --- Login profile wizard (build from a captured request instead of hand-written JSON) ---
        put("settings.agent.login.easyhint",
                "Elle JSON yazmanıza gerek yok. Hedefe tarayıcıdan bir kez login olun (Burp proxy açıkken), sonra aşağıdaki butonla o login isteğini seçin — profil otomatik oluşturulur.",
                "No need to hand-write JSON. Log in to the target once from your browser (with Burp proxy on), then use the button below to pick that login request — the profile is built automatically.");
        put("settings.agent.login.wizardbtn",
                "🧩 Kolay ekle — Proxy history'den login profili oluştur",
                "🧩 Easy add — build a login profile from proxy history");
        put("settings.agent.login.advlabel",
                "Gelişmiş / elle düzenleme (JSON dizisi):",
                "Advanced / manual editing (JSON array):");
        put("login.wizard.title", "Login Profili Oluştur", "Build Login Profile");
        put("login.wizard.intro",
                "1) “Proxy history'den otomatik doldur” ile uygulamanın login isteğini seçin → alanlar kendiliğinden dolar.\n2) “Test et” ile doğrulayın (token yolu boşsa otomatik bulunur).\n3) “Ekle” ile kaydedin. Kaydet'e basmayı unutmayın.",
                "1) Use “Auto-fill from proxy history” and pick the app's login request → fields fill themselves.\n2) Click “Test” to verify (the token path is auto-detected if left blank).\n3) Click “Add” to save it. Don't forget to press Save afterwards.");
        put("login.wizard.capture", "📜 Proxy history'den otomatik doldur", "📜 Auto-fill from proxy history");
        put("login.wizard.nohistory",
                "Proxy history boş. Önce hedefe tarayıcıdan login olun (Burp proxy açıkken), sonra tekrar deneyin.",
                "Proxy history is empty. Log in to the target from your browser first (with Burp proxy on), then try again.");
        put("login.wizard.pick.title", "Login isteğini seçin", "Pick the login request");
        put("login.wizard.pick.hint", "🔑 ile işaretliler login isteği gibi görünüyor (üstte).", "Entries marked 🔑 look like login requests (shown first).");
        put("login.wizard.captured",
                "✓ Form yakalanan istekten dolduruldu. Kontrol edin ve “Test et”e basın.",
                "✓ Form filled from the captured request. Review it and click “Test”.");
        put("login.wizard.captured.notoken",
                "✓ Form dolduruldu — ancak yanıtta token otomatik bulunamadı. “Test et”e basın (canlı yanıttan bulmaya çalışır) ya da Token JSON yolunu elle girin.",
                "✓ Form filled — but no token was auto-detected in the response. Click “Test” (it will try the live response) or enter the Token JSON path manually.");
        put("login.wizard.field.role", "Rol adı *", "Role name *");
        put("login.wizard.field.url", "Login URL *", "Login URL *");
        put("login.wizard.field.method", "Method", "Method");
        put("login.wizard.field.user", "Kullanıcı ({user})", "Username ({user})");
        put("login.wizard.field.pass", "Parola ({pass})", "Password ({pass})");
        put("login.wizard.field.body", "İstek gövdesi", "Request body");
        put("login.wizard.field.tokenpath", "Token JSON yolu", "Token JSON path");
        put("login.wizard.field.ctype", "Content-Type", "Content-Type");
        put("login.wizard.field.tokenregex", "Token regex (alternatif)", "Token regex (fallback)");
        put("login.wizard.field.authheader", "Auth header adı", "Auth header name");
        put("login.wizard.field.authvalue", "Auth değeri ({token})", "Auth value ({token})");
        put("login.wizard.advanced", "İleri düzey (genelde dokunmayın — Test edince otomatik bulunur):", "Advanced (usually leave as-is — auto-detected on Test):");
        put("login.wizard.test", "🔑 Test et", "🔑 Test");
        put("login.wizard.testing", "Test ediliyor…", "Testing…");
        put("login.wizard.ok", "Başarılı — token: {0}", "Success — token: {0}");
        put("login.wizard.detected", "Token yolu otomatik bulundu: {0}", "Token path auto-detected: {0}");
        put("login.wizard.add", "Ekle", "Add");
        put("login.wizard.needfields", "“Rol adı” ve “Login URL” zorunludur.", "“Role name” and “Login URL” are required.");
        put("login.wizard.added", "“{0}” eklendi. Değişikliği kalıcı yapmak için Ayarlar'da Kaydet'e basın.", "“{0}” added. Press Save in Settings to persist the change.");
        // ── Login-profile manager popup (opened from the Authorization Matrix tab) ──
        put("login.mgr.title", "Login Profilleri & AI Pentester", "Login Profiles & AI Pentester");
        put("login.mgr.intro",
                "Bu profiller her taramada TAZE oturum üretir (yetki matrisi / IDOR / BOLA için). Hedefe Burp proxy açıkken bir kez login olun, sonra “Ekle” ile o login isteğini seçin — profil otomatik oluşturulur. Elle JSON yazmanıza gerek yok.",
                "These profiles mint a FRESH session each scan (for the authorization matrix / IDOR / BOLA). Log in to the target once with Burp proxy on, then use “Add” to pick that login request — the profile is built automatically. No hand-written JSON needed.");
        put("login.mgr.profilesLabel", "Kayıtlı login profilleri:", "Saved login profiles:");
        put("login.mgr.col.role", "Rol", "Role");
        put("login.mgr.col.url", "Login URL", "Login URL");
        put("login.mgr.col.user", "Kullanıcı", "Username");
        put("login.mgr.col.token", "Token yolu", "Token path");
        put("login.mgr.add", "➕ Ekle (proxy history'den)", "➕ Add (from proxy history)");
        put("login.mgr.edit", "✏️ Düzenle", "✏️ Edit");
        put("login.mgr.delete", "🗑️ Sil", "🗑️ Delete");
        put("login.mgr.test", "🔑 Test et", "🔑 Test");
        put("login.mgr.advanced", "⚙️ Gelişmiş (JSON)", "⚙️ Advanced (JSON)");
        put("login.mgr.save", "💾 Kaydet", "💾 Save");
        put("login.mgr.close", "Kapat", "Close");
        put("login.mgr.saved", "Login profilleri kaydedildi.", "Login profiles saved.");
        put("login.mgr.empty", "Henüz login profili yok — “Ekle” ile başlayın.", "No login profiles yet — start with “Add”.");
        put("login.mgr.count", "{0} profil kayıtlı.", "{0} profile(s) saved.");
        put("login.mgr.selectRow", "Önce tablodan bir profil seçin.", "Select a profile from the table first.");
        put("login.mgr.deleteConfirm", "“{0}” profili silinsin mi?", "Delete profile “{0}”?");
        put("login.mgr.editor.new", "Login Profili — Yeni", "Login Profile — New");
        put("login.mgr.editor.edit", "Login Profili — Düzenle", "Login Profile — Edit");
        put("login.mgr.advanced.title", "Gelişmiş — JSON dizisi", "Advanced — JSON array");
        put("login.mgr.advanced.invalid", "Geçersiz JSON dizisi. Değişiklik uygulanmadı.", "Invalid JSON array. No changes applied.");
        put("login.mgr.unavailable", "Login profili yöneticisi şu an kullanılamıyor (eklenti tam yüklenmedi).", "The login-profile manager is unavailable right now (extension not fully loaded).");
        put("settings.save.success", "Ayarlar başarıyla kaydedildi!", "Settings saved successfully!");
        put("settings.save.error", "Ayarlar kaydedilirken hata: {0}", "Error saving settings: {0}");
        put("settings.dialog.error.title", "Hata", "Error");
        put("settings.dialog.success.title", "Başarılı", "Success");
        put("settings.dialog.copy", "Panoya Kopyala", "Copy to Clipboard");
        put("settings.dialog.copied", "Panoya kopyalandı!", "Copied to clipboard!");
        put("settings.dialog.close", "Kapat", "Close");
        put("settings.model.notworking.title", "Model Çalışmıyor", "Model Not Working");
        put("settings.model.notworking.none", "Seçili model '{0}' ÇALIŞMIYOR:\n  {1}\n\nÖnerilen modellerin hiçbiri de şu an yanıt vermedi.\nGateway'i / API anahtarını kontrol edin.", "Selected model '{0}' is NOT WORKING:\n  {1}\n\nNone of the recommended models responded either.\nCheck the gateway / API key.");
        put("settings.model.notworking.pick", "Seçili model '{0}' ÇALIŞMIYOR:\n  {1}\n\nÇalışan modeller (hız sırası) — birini seçin:", "Selected model '{0}' is NOT WORKING:\n  {1}\n\nWorking models (by speed) — pick one:");
        put("settings.model.notworking.pick.title", "Model Çalışmıyor — Çalışan Bir Model Seçin", "Model Not Working — Pick a Working Model");
        put("settings.model.updated", "Model '{0}' seçildi ve kaydedildi. ✓", "Model '{0}' selected and saved. ✓");
        put("settings.model.updated.title", "Model Güncellendi", "Model Updated");
        put("settings.conn.success.title", "Bağlantı Testi - Başarılı", "Connection Test - Success");
        put("settings.conn.success.gw", "Bağlantı Başarılı!\n\nUç Nokta: {0}\nYanıt Süresi: {1} ms\nKullanılabilir Model: {2}", "Connection Successful!\n\nEndpoint: {0}\nResponse Time: {1} ms\nAvailable Models: {2}");
        put("settings.conn.success.title2", "Bağlantı Testi - Başarılı", "Connection Test - Successful");
        put("settings.conn.success.model", "Bağlantı başarılı ✓\n\nUç Nokta: {0}\nKullanılabilir model sayısı: {1}\n\nSeçili model '{2}' ÇALIŞIYOR ({3} ms).", "Connection successful ✓\n\nEndpoint: {0}\nAvailable model count: {1}\n\nSelected model '{2}' is WORKING ({3} ms).");
        put("settings.conn.local.notworking", "Yerel model '{0}' ÇALIŞMIYOR:\n  {1}\n\nYerel sunucuyu (Ollama/LM Studio) ve model adını kontrol edin; modeli indirdiğinizden emin olun.", "Local model '{0}' is NOT WORKING:\n  {1}\n\nCheck the local server (Ollama/LM Studio) and the model name; make sure the model is downloaded.");
        put("settings.conn.unexpected", "Beklenmeyen Hata", "Unexpected Error");
        put("settings.conn.failed.title", "Bağlantı Testi - Başarısız", "Connection Test - Failed");
        put("settings.conn.failed.header", "Bağlantı Başarısız: {0}", "Connection Failed: {0}");
        put("settings.models.found", "{0} kullanılabilir model bulundu!", "Found {0} available models!");
        put("settings.models.refreshed.title", "Modeller Yenilendi", "Models Refreshed");
        put("settings.models.none.title", "Model Yok", "No Models");
        put("settings.models.none.api", "Model bulunamadı. API uç noktanızı kontrol edin.", "No models found. Check your API endpoint.");
        put("settings.models.error.api", "Modeller alınırken hata:\n{0}\n\nAPI uç noktanızın doğru olduğundan emin olun.", "Error fetching models:\n{0}\n\nMake sure your API endpoint is correct.");
        put("settings.models.none.local", "Model bulunamadı. Yerel sunucu {0} adresinde çalışıyor mu?", "No models found. Is the local server running at {0} ?");
        put("settings.models.error.local", "Modeller alınırken hata:\n{0}\n\nYerel sunucunun çalıştığından emin olun.", "Error fetching models:\n{0}\n\nMake sure the local server is running.");
        put("settings.reset.confirm", "Tüm ayarları varsayılanlara sıfırlamak istediğinizden emin misiniz?", "Are you sure you want to reset all settings to defaults?");
        put("settings.reset.confirm.title", "Ayarları Sıfırla", "Reset Settings");
        put("settings.cleardb.confirm", "⚠️ UYARI: Bu, TÜM tarama verilerini, bulguları ve geçmişi kalıcı olarak siler.\n\nTüm veritabanını temizlemek istediğinizden kesinlikle emin misiniz?", "⚠️ WARNING: This will permanently delete ALL scan data, findings, and history.\n\nAre you absolutely sure you want to clear the entire database?");
        put("settings.cleardb.confirm.title", "Veritabanını Temizle", "Clear Database");
        put("settings.cleardb.confirm2", "Bu işlem GERİ ALINAMAZ!\n\nTüm verileri kalıcı olarak silmek için EVET'e tıklayın.", "This action CANNOT be undone!\n\nClick YES to permanently delete all data.");
        put("settings.cleardb.confirm2.title", "Son Onay", "Final Confirmation");
        put("settings.cleardb.success", "✅ Veritabanı başarıyla temizlendi!\n\nTüm tarama verileri, bulgular ve geçmiş silindi.", "✅ Database cleared successfully!\n\nAll scan data, findings, and history have been deleted.");
        put("settings.cleardb.error", "❌ Veritabanı temizlenirken hata:\n{0}", "❌ Error clearing database:\n{0}");
        put("settings.probe.emptyresponse", "boş yanıt", "empty response");
        put("settings.probe.emptycontent", "boş içerik döndü", "returned empty content");
        put("settings.probe.err.unknown", "bilinmeyen hata", "unknown error");
        put("settings.probe.err.timeout", "zaman aşımı (60sn)", "timed out (60s)");
        put("settings.probe.err.server", "sunucu hatası (HTTP {0})", "server error (HTTP {0})");
        put("settings.probe.err.notfound", "model şu an mevcut değil (HTTP {0})", "model unavailable (HTTP {0})");
        put("settings.probe.err.conn", "sunucuya ulaşılamadı / bağlantı kesildi", "couldn't reach the server / connection dropped");
        // ---- FindingsPanel.java (99) ----
        put("findings.title", "Güvenlik Bulguları", "Vulnerability Findings");
        put("findings.count", "{0} bulgu", "{0} findings");
        put("findings.btn.proReport", "Pro Rapor (DOCX)", "Pro Report (DOCX)");
        put("findings.btn.proReport.tip", "Bulguları profesyonel Word raporu olarak dışa aktar (AI yönetici özeti + OWASP/CVSS/repro/kanıt)", "Export findings as a professional Word report (AI executive summary + OWASP/CVSS/repro/evidence)");
        put("findings.report.none", "Rapor için bulgu yok.", "No findings to report.");
        put("findings.report.generating", "Rapor üretiliyor (AI özet + bulgu anlatısı)… Tamamlanınca bildirilecek.", "Generating report (AI summary + finding narrative)… You will be notified when it's done.");
        put("findings.report.saved", "Pro rapor kaydedildi:", "Pro report saved:");
        put("findings.report.error", "Rapor hatası:", "Report error:");
        put("findings.col.type", "Tür", "Type");
        put("findings.col.severity", "Önem", "Severity");
        put("findings.col.cvss", "CVSS", "CVSS");
        put("findings.col.priority", "Öncelik", "Priority");
        put("findings.col.confidence", "Güven", "Confidence");
        put("findings.col.url", "URL", "URL");
        put("findings.btn.clearAll", "Hepsini Temizle", "Clear All");
        put("findings.btn.export", "Dışa Aktar", "Export");
        put("findings.btn.falsePositive", "False Positive", "False Positive");
        put("findings.detail.selectPrompt", "Ayrıntıları görmek için bir bulgu seçin", "Select a finding to view details");
        put("findings.btn.sendToRepeater", "Repeater'a Gönder", "Send to Repeater");
        put("findings.btn.generatePoC", "PoC Üret", "Generate PoC");
        put("findings.btn.fullDetails", "Tüm Ayrıntılar", "Full Details");
        put("findings.tab.vulnInfo", "Zafiyet Bilgisi", "Vulnerability Info");
        put("findings.tab.request", "İstek", "Request");
        put("findings.tab.responseHighlighted", "Yanıt (Vurgulanmış)", "Response (Highlighted)");
        put("findings.noRequestData", "İstek verisi yok", "No request data available");
        put("findings.noResponseData", "Yanıt verisi yok", "No response data available");
        put("findings.responseTruncated", "... (Yanıt performans için kısaltıldı)", "... (Response truncated for performance)");
        put("findings.label.severityWord", "önem", "severity");
        put("findings.label.priority", "Öncelik", "Priority");
        put("findings.label.confidence", "Güven", "Confidence");
        put("findings.label.description", "Açıklama:", "Description:");
        put("findings.label.cwe", "CWE:", "CWE:");
        put("findings.label.owasp", "OWASP:", "OWASP:");
        put("findings.label.evidence", "Kanıt:", "Evidence:");
        put("findings.label.remediation", "Çözüm:", "Remediation:");
        put("findings.label.references", "Referanslar:", "References:");
        put("findings.sev.critical", "Kritik", "Critical");
        put("findings.sev.high", "Yüksek", "High");
        put("findings.sev.medium", "Orta", "Medium");
        put("findings.sev.low", "Düşük", "Low");
        put("findings.sev.info", "Bilgi", "Info");
        put("findings.prio.high", "yüksek", "high");
        put("findings.prio.medium", "orta", "medium");
        put("findings.prio.low", "düşük", "low");
        put("findings.prio.veryLow", "çok düşük", "very low");
        put("findings.dialog.details.title", "Zafiyet Ayrıntıları", "Vulnerability Details");
        put("findings.tab.details", "Ayrıntılar", "Details");
        put("findings.tab.references", "Referanslar", "References");
        put("findings.btn.copyReport", "Raporu Kopyala", "Copy Report");
        put("findings.msg.reportCopied", "Rapor panoya kopyalandı!", "Report copied to clipboard!");
        put("findings.title.success", "Başarılı", "Success");
        put("findings.btn.close", "Kapat", "Close");
        put("findings.label.affectedUrl", "Etkilenen URL:", "Affected URL:");
        put("findings.label.confidenceColon", "Güven:", "Confidence:");
        put("findings.label.priorityColon", "Öncelik:", "Priority:");
        put("findings.heading.description", "Açıklama", "Description");
        put("findings.heading.evidence", "Kanıt", "Evidence");
        put("findings.heading.exploitation", "İstismar", "Exploitation");
        put("findings.heading.remediation", "Çözüm", "Remediation");
        put("findings.heading.affectedUrl", "Etkilenen URL", "Affected URL");
        put("findings.heading.classification", "Sınıflandırma", "Classification");
        put("findings.heading.references", "Referanslar", "References");
        put("findings.legend.evidence", "Kanıt", "Evidence");
        put("findings.legend.sensitive", "Hassas Veri", "Sensitive Data");
        put("findings.legend.error", "Hata/Uyarı", "Error/Warning");
        put("findings.heading.securityReferences", "Güvenlik Referansları", "Security References");
        put("findings.noReferences", "Belirli bir referans yok.", "No specific references available.");
        put("findings.heading.relatedResources", "İlgili Kaynaklar", "Related Resources");
        put("findings.msg.cannotDetermineHost", "Hedef host belirlenemiyor", "Cannot determine target host");
        put("findings.msg.sentToRepeater", "İstek Repeater'a gönderildi!", "Request sent to Repeater!");
        put("findings.title.error", "Hata", "Error");
        put("findings.msg.errorPrefix", "Hata:", "Error:");
        put("findings.msg.pocError", "PoC üretme hatası:", "Error generating PoC:");
        put("findings.menu.sendToRepeater", "📤 Repeater'a Gönder", "📤 Send to Repeater");
        // Reproduction bundle (replayable proof trail)
        put("findings.menu.repro", "🧾 Kanıt Paketi", "🧾 Reproduction Bundle");
        put("findings.menu.reproRepeater", "Tüm adımları Repeater'a gönder", "Send all steps to Repeater");
        put("findings.menu.reproCurl", "curl olarak kopyala", "Copy as curl");
        put("findings.menu.reproHar", "HAR olarak kopyala", "Copy as HAR");
        put("findings.msg.noRepro", "Bu bulgunun kanıt paketi yok.", "This finding has no reproduction bundle.");
        put("findings.msg.reproSent", "Kanıt paketi Repeater'a gönderildi ({0} adım).", "Reproduction bundle sent to Repeater ({0} steps).");
        put("findings.msg.reproCopied", "Kanıt paketi panoya kopyalandı.", "Reproduction bundle copied to clipboard.");
        put("repro.role.own", "Sahip isteği (kendi nesnesi)", "Owner request (own object)");
        put("repro.role.attack", "Saldırı (kurbanın id'si)", "Attack (victim's id)");
        put("repro.role.control", "Negatif kontrol (geçersiz id)", "Negative control (invalid id)");
        put("repro.role.public", "Public sonda (yetki kaldırılmış)", "Public probe (auth stripped)");
        put("repro.role.victim", "Kurban oturumu (ground-truth)", "Victim session (ground truth)");
        put("repro.detail.authStripped", "yetki başlıkları kaldırıldı", "auth headers stripped");
        put("repro.curl.header", "AppSecHunter kanıt paketi — adımları sırayla çalıştırın", "AppSecHunter reproduction bundle — run the steps in order");
        put("repro.text.header", "AppSecHunter Kanıt Paketi", "AppSecHunter Reproduction Bundle");
        put("repro.text.request", "İSTEK", "REQUEST");
        put("repro.text.response", "YANIT", "RESPONSE");
        put("findings.menu.generatePoC", "💻 PoC Üret", "💻 Generate PoC");
        put("findings.menu.viewDetails", "Ayrıntıları Gör", "View Details");
        put("findings.menu.markFalsePositive", "❌ False Positive Olarak İşaretle", "❌ Mark as False Positive");
        put("findings.msg.noFindingSelected", "Bulgu seçilmedi.", "No finding selected.");
        put("findings.title.cannotGeneratePoC", "PoC Üretilemiyor", "Cannot Generate PoC");
        put("findings.dialog.generatingPoC.title", "PoC Üretiliyor", "Generating PoC");
        put("findings.msg.generatingPoC", "⏳ Kavram Kanıtı (PoC) üretiliyor...", "⏳ Generating Proof of Concept...");
        put("findings.msg.pocFailed", "PoC üretilemedi:", "Failed to generate PoC:");
        put("findings.dialog.poc.title", "PoC —", "PoC for");
        put("findings.poc.heading", "💻 Kavram Kanıtı (PoC)", "💻 Proof of Concept");
        put("findings.msg.repeaterFailed", "Repeater'a gönderilemedi:", "Failed to send to Repeater:");
        put("findings.btn.sendToIntruder", "Intruder'a Gönder", "Send to Intruder");
        put("findings.msg.sentToIntruder", "İstek Intruder'a gönderildi!", "Request sent to Intruder!");
        put("findings.msg.intruderFailed", "Intruder'a gönderilemedi:", "Failed to send to Intruder:");
        put("findings.btn.copyToClipboard", "📋 Panoya Kopyala", "📋 Copy to Clipboard");
        put("findings.msg.pocCopied", "PoC panoya kopyalandı!", "PoC copied to clipboard!");
        put("findings.title.cannotSendToRepeater", "Repeater'a Gönderilemiyor", "Cannot Send to Repeater");
        put("findings.msg.noRequestForFinding", "Bu bulgu için istek verisi yok.\nBu durum, bulgu istek verisi olmadan veritabanından yüklendiğinde oluşabilir.", "No request data available for this finding.\nThis can happen if the finding was loaded from database without request data.");
        put("findings.msg.cannotDetermineHostPort", "Bu bulgu için hedef host/port belirlenemiyor.", "Cannot determine target host/port for this finding.");
        put("findings.msg.sentToRepeaterSuccess", "İstek Repeater'a başarıyla gönderildi!", "Request sent to Repeater successfully!");
        put("findings.msg.selectFirst", "Lütfen önce bir bulgu seçin.", "Please select a finding first.");
        put("findings.msg.confirmFalsePositive", "'{0}' false positive olarak işaretlensin mi?", "Mark '{0}' as false positive?");
        put("findings.title.confirmFalsePositive", "False Positive Onayı", "Confirm False Positive");
        put("findings.msg.falsePositiveReason", "Neden false positive? (opsiyonel — öğrenme döngüsünü besler)", "Why is this a false positive? (optional — feeds the learning loop)");
        put("findings.title.falsePositiveNote", "False Positive Notu", "False Positive Note");
        put("findings.msg.markedFalsePositive", "False positive olarak işaretlendi.", "Marked as false positive.");
        put("findings.msg.noFindingsToExport", "Dışa aktarılacak bulgu yok.", "No findings to export.");
        put("findings.msg.exportedToClipboard", "Bulgular panoya aktarıldı!", "Findings exported to clipboard!");
        // ---- AssistantPanel.java (43) ----
        put("copilot.header.title", "🛰️ Security Copilot", "🛰️ Security Copilot");
        put("copilot.header.subtitle", "Trafiği pasif izler · test edilecek uçları önerir · otonom avlar", "Passively watches traffic · suggests endpoints to test · hunts autonomously");
        put("copilot.welcome", "Trafiğinizi izliyorum. İlginç uçlar yukarıdaki Fırsatlar listesinde belirir — sağ tık ile test edebilir, ya da bir satır seçip bana o uçta ne deneyeceğinizi sorabilirsiniz. (Ambient'i Settings → Ambient Security Copilot'tan açın.)", "I'm watching your traffic. Interesting endpoints appear in the Opportunities list above — right-click to test them, or select a row and ask me what to try on that endpoint. (Enable Ambient from Settings → Ambient Security Copilot.)");
        put("copilot.opp.title", "Fırsatlar (pasif triyaj)", "Opportunities (passive triage)");
        put("copilot.opp.status", "{0} uç · {1} kuyrukta", "{0} endpoints · {1} queued");
        put("copilot.col.score", "Skor", "Score");
        put("copilot.col.host", "Host", "Host");
        put("copilot.col.method", "Metot", "Method");
        put("copilot.col.path", "Yol", "Path");
        put("copilot.col.class", "Sınıf", "Class");
        put("copilot.col.status", "Durum", "Status");
        put("copilot.oppStatus.queued", "kuyrukta", "queued");
        put("copilot.oppStatus.running", "çalışıyor", "running");
        put("copilot.oppStatus.done", "bitti", "done");
        put("copilot.oppStatus.ignored", "yoksayıldı", "ignored");
        put("copilot.oppStatus.new", "yeni", "new");
        put("copilot.hunt.pause", "⏸ Avlamayı Durdur", "⏸ Pause Hunting");
        put("copilot.hunt.resume", "▶ Avlamayı Sürdür", "▶ Resume Hunting");
        put("copilot.hunt.terminate", "⛔ Sonlandır", "⛔ Terminate");
        put("copilot.hunt.toggle.tip", "Otonom avlamayı duraklat / sürdür — aynı buton açıp kapatır", "Pause / resume autonomous hunting — the same button toggles it");
        put("copilot.hunt.terminate.tip", "Avcıyı tamamen sonlandır ve ambient avlama ayarını kapat", "Terminate the hunter completely and turn off the ambient hunting setting");
        put("copilot.meter.hunterOff", "Avcı kapalı", "Hunter off");
        put("copilot.meter.pausedPrefix", "⏸ Duraklatıldı · ", "⏸ Paused · ");
        put("copilot.meter.token", "Token", "Token");
        put("copilot.meter.time", "Süre", "Time");
        put("copilot.meter.active", "Aktif", "Active");
        put("copilot.meter.queue", "Kuyruk", "Queue");
        put("copilot.meter.minutesSuffix", "dk", "min");
        put("copilot.menu.test", "🎯 Test et (playbook agentic)", "🎯 Test (agentic playbook)");
        put("copilot.menu.fastScan", "⚡ Hızlı tara (deterministik)", "⚡ Fast scan (deterministic)");
        put("copilot.menu.ignore", "✖ Yoksay", "✖ Ignore");
        put("copilot.input.tip", "Seçili uç hakkında soru sorun, Enter'a basın", "Ask a question about the selected endpoint, press Enter");
        put("copilot.btn.send", "Gönder ➤", "Send ➤");
        put("copilot.btn.clear", "Temizle", "Clear");
        put("copilot.chatCleared", "Sohbet temizlendi.", "Chat cleared.");
        put("copilot.role.copilot", "Copilot", "Copilot");
        put("copilot.role.you", "Siz", "You");
        put("copilot.error.noReply", "Yanıt alınamadı: {0}\nSettings → Test Connection ile bağlantıyı kontrol edin.", "Could not get a reply: {0}\nCheck the connection via Settings → Test Connection.");
        put("copilot.status.typing", "Copilot yazıyor…", "Copilot is typing…");
        put("copilot.status.huntTerminated", "Otonom avlama sonlandırıldı (Settings'ten yeniden açabilirsiniz).", "Autonomous hunting terminated (you can re-enable it from Settings).");
        put("copilot.status.huntResumed", "Avlama sürdürüldü.", "Hunting resumed.");
        put("copilot.status.huntPaused", "Avlama duraklatıldı — aynı butonla ('Avlamayı Sürdür') devam edin.", "Hunting paused — continue with the same button ('Resume Hunting').");
        put("copilot.status.runningInDetection", "Detection sekmesinde çalışıyor: {0}", "Running in the Detection tab: {0}");
        // ---- AssistantPanel.java — IDOR enrichment ----
        put("copilot.idor.role", "Copilot · IDOR", "Copilot · IDOR");
        put("copilot.btn.explainIdor", "🤖 IDOR'u açıkla", "🤖 Explain IDOR");
        put("copilot.btn.explainIdor.tip", "Son doğrulanan (ya da seçili olası) IDOR'u AI ile derinlemesine açıkla", "Use AI to deeply explain the last confirmed (or selected suspected) IDOR");
        put("copilot.idor.confirmed.title", "🚨 IDOR DOĞRULANDI", "🚨 IDOR CONFIRMED");
        put("copilot.idor.confirmed.alert", "IDOR doğrulandı: {0}", "IDOR confirmed: {0}");
        put("copilot.idor.confirmed.status", "🚨 IDOR doğrulandı: {0}", "🚨 IDOR confirmed: {0}");
        put("copilot.idor.candidate.title", "🔍 Olası IDOR", "🔍 Possible IDOR");
        put("copilot.idor.candidate.more", "… ve {0} olası IDOR ucu daha (yukarıdaki Fırsatlar tablosuna bakın).", "… and {0} more possible IDOR endpoints (see the Opportunities table above).");
        put("copilot.idor.none", "Henüz açıklanacak bir IDOR yok. Bir IDOR doğrulanınca ya da tabloda olası bir IDOR seçince bu düğme çalışır.", "No IDOR to explain yet. This works once an IDOR is confirmed, or you select a possible IDOR in the table.");
        put("copilot.idor.field.type", "Tür", "Type");
        put("copilot.idor.field.location", "Konum", "Location");
        put("copilot.idor.field.confidence", "Güven", "Confidence");
        put("copilot.idor.field.evidence", "Kanıt", "Evidence");
        put("copilot.idor.field.host", "Host", "Host");
        put("copilot.idor.field.score", "Skor", "Score");
        put("copilot.idor.field.reason", "Neden", "Reason");
        put("copilot.idor.confirmed.verify", "Nasıl doğrularsın: aynı isteği BAŞKA bir kullanıcının kimliğiyle (veya oturumsuz) tekrarla; yanıt hâlâ yabancı nesneyi döndürüyorsa IDOR gerçektir.", "How to verify: replay the same request as ANOTHER user (or with no session); if the response still returns the foreign object, the IDOR is real.");
        put("copilot.idor.confirmed.cta", "→ Derin analiz için aşağıdaki '🤖 IDOR'u açıkla' düğmesine basın.", "→ Press '🤖 Explain IDOR' below for a deep analysis.");
        put("copilot.idor.candidate.cta", "→ Doğrulamak için tabloda sağ tık → 'Test et' (AI 3-oy konsensüsü karara bağlar).", "→ To confirm: right-click the row → 'Test' (decided by AI 3-vote consensus).");
        put("copilot.idor.explain.you", "IDOR'u açıkla: {0}", "Explain the IDOR: {0}");
        put("copilot.idor.explain.candidateYou", "Olası IDOR'u değerlendir: {0}", "Assess the possible IDOR: {0}");
        put("copilot.idor.reported", "✅ Bu IDOR aktif olarak doğrulandı ve Bulgular ekranına eklendi: {0} (sahiplik kontrolleri: anonim genel prob + negatif kontrol + yabancı-sahip belirteç + AI onayı).", "✅ This IDOR was actively verified and added to the Findings panel: {0} (ownership checks: anonymous public probe + negative control + foreign-owner token + AI confirmation).");
        put("copilot.idor.unconfirmed", "ℹ️ Aktif doğrulama bunu IDOR olarak kanıtlamadı (genel/paylaşılan kaynak, kendi veriniz ya da yeterli kanıt yok) — bulgu olarak EKLENMEDİ: {0}.", "ℹ️ Active verification did not prove this as IDOR (public/shared resource, your own data, or insufficient evidence) — NOT filed as a finding: {0}.");
        put("copilot.idor.reported.desc", "AI derin analizi bu uçta yabancı nesneye erişim (IDOR/BOLA) olduğu sonucuna vardı. Aktif olarak yeniden test edilmedi — ikinci bir kimlikle doğrulanmalı.", "AI deep-dive concluded this endpoint allows cross-object access (IDOR/BOLA). Not actively re-tested — confirm with a second identity.");
        put("copilot.btn.scenario", "🎯 Tüm Uygulamada IDOR/BOLA", "🎯 Whole-App IDOR/BOLA");
        put("copilot.btn.scenario.tip", "Seçili (ya da en üstteki) uca ait host'ta uçtan uca IDOR/BAC/BOLA senaryosu çalıştır: çapraz-sahip BOLA + uç-başına URL & gövde id takası", "Run an end-to-end IDOR/BAC/BOLA scenario on the selected (or top) endpoint's host: cross-owner BOLA + per-endpoint URL & body id swapping");
        put("copilot.idor.scenario.noTarget", "Önce hedef trafiği üret: uygulamada gez (mümkünse 2 farklı kullanıcıyla giriş yap), Fırsatlar listesi dolunca bir uç seç ve tekrar dene.", "Generate target traffic first: browse the app (ideally log in as 2 different users), then once the Opportunities list fills, select an endpoint and try again.");
        put("copilot.idor.scenario.crossTab", "Çapraz-sahip BOLA — {0}", "Cross-owner BOLA — {0}");
        put("copilot.idor.scenario.perEndpointTab", "Uç-başına IDOR/BAC — {0}", "Per-endpoint IDOR/BAC — {0}");
        put("copilot.idor.scenario.status", "IDOR/BOLA senaryosu çalışıyor: {0}", "IDOR/BOLA scenario running: {0}");
        put("copilot.idor.scenario.intro",
                "🎯 Tüm uygulamada IDOR/BAC/BOLA senaryosu başlatıldı ({0}). Detection sekmesinde iki aşama açıldı:\n"
                + "1) Çapraz-sahip BOLA — history'deki GERÇEK kimliklerle bir kullanıcının nesnesini DİĞER kullanıcı olarak çağırır, AI 3-oy konsensüsüyle doğrular (en az 2 oturum-açmış kimlik gerekir; yoksa bu aşama atlanır).\n"
                + "2) Uç-başına IDOR/BAC — her uçta URL VE request-body id'lerini (örn. customerId) takas eder + negatif kontrol + yetki (auth düşürme) testleri yapar; tek kimlikle de çalışır.\n"
                + "Bulgular burada 🚨 (doğrulandı) / 🔍 (olası) olarak duyurulacak. İpucu: tam BOLA için 2 farklı kullanıcıyla gezip trafiği biriktir; rol×uç matrisi için 'Yetki Matrisi' sekmesini kullan.",
                "🎯 Whole-app IDOR/BAC/BOLA scenario started ({0}). Two phases opened in the Detection tab:\n"
                + "1) Cross-owner BOLA — replays one user's object AS another using REAL identities from history, confirmed by AI 3-vote consensus (needs >=2 logged-in identities; otherwise this phase is skipped).\n"
                + "2) Per-endpoint IDOR/BAC — swaps URL AND request-body ids (e.g. customerId) + negative control + access-control (auth-drop) checks; works with a single identity too.\n"
                + "Findings are announced here as 🚨 (confirmed) / 🔍 (suspected). Tip: browse as 2 different users for full BOLA; use the 'Authorization Matrix' tab for the role×endpoint matrix.");
        // ---- AuthMatrixPanel.java (20) ----
        put("authz.summary.empty", "Henüz yetki matrisi çalıştırılmadı.", "Authorization matrix has not been run yet.");
        put("authz.summary.stats", "{0} endpoint × {1} rol  ·  {2} ihlal ({3} yüksek)", "{0} endpoints × {1} roles  ·  {2} violations ({3} high)");
        put("authz.col.severity", "Önem", "Severity");
        put("authz.col.type", "Tür", "Type");
        put("authz.col.endpoint", "Endpoint", "Endpoint");
        put("authz.col.evidence", "Kanıt", "Evidence");
        put("authz.col.role", "Rol", "Role");
        put("authz.col.token", "Token", "Token");
        put("authz.col.created", "Oluşturma", "Created");
        put("authz.col.method", "Method", "Method");
        put("authz.col.path", "Path", "Path");
        put("authz.btn.exportCsv", "CSV Dışa Aktar", "Export CSV");
        put("authz.btn.exportHtml", "HTML Dışa Aktar", "Export HTML");
        put("authz.btn.clear", "Temizle", "Clear");
        put("authz.btn.refresh", "Yenile", "Refresh");
        put("authz.btn.deleteRole", "Seçili Rolü Sil", "Delete Selected Role");
        put("authz.btn.loginProfiles", "🔐 Login Profilleri", "🔐 Login Profiles");
        put("authz.btn.loginProfiles.tip",
                "Login profillerini yönet (taze oturum) + AI Pentester ayarları — eskiden Ayarlar'daydı.",
                "Manage login profiles (fresh sessions) + AI Pentester settings — previously in Settings.");
        put("authz.identities.label", "Kimlikler (roller) — gerçek BOLA için ≥2 önerilir:", "Identities (roles) — ≥2 recommended for real BOLA:");
        put("authz.dialog.runFirst", "Önce bir matris çalıştırın.", "Run a matrix first.");
        put("authz.dialog.saved", "Kaydedildi: {0}", "Saved: {0}");
        put("authz.dialog.exportError", "Dışa aktarma hatası: {0}", "Export error: {0}");
        put("authz.dialog.autoRole", "Bu kimlik history'den otomatik bulundu (kayıtlı oturum değil), silinemez.",
                "This identity was auto-discovered from history (not a stored session) and cannot be deleted.");
        // ---- DetectionRunView.java (34) ----
        put("run.btn.approve", "Onayla ▶", "Approve ▶");
        put("run.btn.abort", "Durdur ✕", "Abort ✕");
        put("run.notRunYet", "Henüz çalıştırılmadı", "Not run yet");
        put("run.stage.recon", "Keşif", "Recon");
        put("run.stage.hypothesis", "Hipotez", "Hypothesis");
        put("run.stage.testPlan", "Test Planı", "Test Plan");
        put("run.stage.execute", "Yürüt", "Execute");
        put("run.stage.analyze", "Analiz", "Analyze");
        put("run.stage.verify", "Doğrula", "Verify");
        put("run.stage.report", "Rapor", "Report");
        put("run.col.num", "#", "#");
        put("run.col.test", "Test", "Test");
        put("run.col.location", "Konum", "Location");
        put("run.col.target", "Hedef", "Target");
        put("run.col.payload", "Payload", "Payload");
        put("run.col.result", "Sonuç", "Result");
        put("run.activeTests", "Aktif Testler", "Active Tests");
        put("run.tab.log", "Log", "Log");
        put("run.tab.request", "İstek", "Request");
        put("run.tab.response", "Yanıt", "Response");
        put("run.target", "Hedef: {0}", "Target: {0}");
        put("run.mode.guided", "Mod: Rehberli (her aşamayı onaylayın)", "Mode: Guided (approve each stage)");
        put("run.mode.auto", "Mod: Otomatik", "Mode: Automatic");
        put("run.preview.notReady", "(istek/yanıt henüz hazır değil)", "(request/response not ready yet)");
        put("run.preview.noRequest", "(istek yok)", "(no request)");
        put("run.preview.noResponse", "(yanıt yok)", "(no response)");
        put("run.status.running", "⏳ çalışıyor", "⏳ running");
        put("run.counter", "Gönderilen: {0} · Hata: {1}", "Sent: {0} · Errors: {1}");
        put("run.siteScan", "🌐 Site Taraması: {0}", "🌐 Site Scan: {0}");
        put("run.endpointsScanned", "{0} / {1} uç tarandı", "{0} / {1} endpoints scanned");
        put("run.site.stopped", "Durduruldu — {0} bulgu", "Stopped — {0} findings");
        put("run.site.completed", "Tamamlandı — {0} bulgu", "Completed — {0} findings");
        put("run.awaitingApproval", "Onay bekleniyor: {0}", "Awaiting approval: {0}");
        put("run.running", "Çalışıyor: {0}", "Running: {0}");
        // ---- BurpExtender.java (38) ----
        put("dialog.pick.emptyHistory", "Proxy history boş. Önce hedefte gezinin, sonra tekrar deneyin.", "Proxy history is empty. Browse the target first, then try again.");
        put("dialog.pick.titleSuffix", "istek seç", "select a request");
        put("dialog.pick.selectLabel", "Proxy History'den bir istek seçin:", "Select a request from Proxy History:");
        put("dialog.pick.unparsable", "(çözümlenemeyen istek)", "(unparsable request)");
        put("dialog.pick.run", "Çalıştır", "Run");
        put("dialog.pick.selectOne", "Lütfen bir istek seçin.", "Please select a request.");
        put("dialog.pick.cancel", "İptal", "Cancel");
        put("dialog.everything.intro", "TAM OTOMATİK TARAMA — tek tıkla tüm kampanyalar arka planda çalışır:", "FULLY AUTOMATIC SCAN — one click runs every campaign in the background:");
        put("dialog.everything.line.thisreq", "  • Bu isteğin tam taraması (deterministik", "  • Full scan of this request (deterministic");
        put("dialog.everything.line.thisreq.ai", " + AI pentester", " + AI pentester");
        put("dialog.everything.line.site", "  • Site + proxy history taraması (tüm girdili uçlar)", "  • Site + proxy history scan (all input-bearing endpoints)");
        put("dialog.everything.line.authmatrix", "  • Otomatik yetki matrisi — roller history'den (BOLA/IDOR/yetki yükseltme)", "  • Automatic authorization matrix — roles from history (BOLA/IDOR/privilege escalation)");
        put("dialog.everything.line.ai", "  • AI yüzey keşfi (gizli endpoint'ler)\n  • Ground-truth + agentic BOLA/BAC senaryoları (AI)\n", "  • AI surface discovery (hidden endpoints)\n  • Ground-truth + agentic BOLA/BAC scenarios (AI)\n");
        put("dialog.everything.warning", "AGRESİF ve DURUM-DEĞİŞTİREN istekler (POST/PUT/DELETE) gönderilir — hedefte veri\noluşturabilir / değiştirebilir / silebilir. YALNIZCA yetkili ve izole test\nortamında çalıştırın.", "AGGRESSIVE and STATE-CHANGING requests (POST/PUT/DELETE) are sent — they may\ncreate / modify / delete data on the target. Run ONLY in an authorized and isolated\ntest environment.");
        put("dialog.everything.title", "Hepsini Tara — Onay", "Scan Everything — Confirm");
        put("dialog.common.proceed", "Devam edilsin mi?", "Proceed?");
        put("dialog.testenv.message", "AGRESİF MOD — durum-değiştiren istekler (POST/PUT/DELETE) gönderilsin mi?\nBunlar hedefte veri oluşturabilir / değiştirebilir / silebilir ve YALNIZCA izole bir\nTEST ORTAMINDA güvenlidir.\n\nEVET  = burası bir test ortamı, agresif test yap.\nHAYIR = güvenli / salt-okunur modda devam et (yalnız GET/HEAD/OPTIONS).", "AGGRESSIVE MODE — send state-changing requests (POST/PUT/DELETE)?\nThese may create / modify / delete data on the target and are safe ONLY in an isolated\nTEST ENVIRONMENT.\n\nYES = this is a test environment, run aggressive tests.\nNO  = continue in safe / read-only mode (GET/HEAD/OPTIONS only).");
        put("dialog.testenv.title", "Test Ortamı Onayı (agresif test)", "Test Environment Confirmation (aggressive testing)");
        put("dialog.intrusive.test.bruteforce", "Login Brute Force", "Login Brute Force");
        put("dialog.intrusive.test.fileupload", "File Upload", "File Upload");
        put("dialog.intrusive.test.ssrf", "Aktif SSRF (localhost / cloud metadata)", "Active SSRF (localhost / cloud metadata)");
        put("dialog.intrusive.test.cmdinjection", "Komut Enjeksiyonu (zamanlama)", "Command Injection (timing)");
        put("dialog.intrusive.test.massassignment", "Mass Assignment / BOPLA (gövdeye yetki/sahiplik alanı enjekte)", "Mass Assignment / BOPLA (inject authorization/ownership fields into the body)");
        put("dialog.intrusive.message", "Şu AGRESİF testler etkin ve çalıştırılacak:\n  • {0}\n\nBu testler hesap kilitleme, dosya yükleme veya iç ağ erişimi riski taşır.\nYALNIZCA yetkili hedeflerde kullanın.\n\nDevam edilsin mi?", "The following AGGRESSIVE tests are enabled and will run:\n  • {0}\n\nThese tests risk account lockout, file upload, or internal network access.\nUse ONLY on authorized targets.\n\nProceed?");
        put("dialog.intrusive.title", "Agresif Test Onayı", "Aggressive Test Confirmation");
        put("dialog.addsession.prompt", "Bu oturum için rol adı girin (örn: Admin, User, Guest):", "Enter a role name for this session (e.g. Admin, User, Guest):");
        put("dialog.addsession.title", "Oturum Ekle", "Add Session");
        put("dialog.addsession.noTokens", "⚠️ Uyarı: Request'te token bulunamadı!", "⚠️ Warning: No token found in the request!");
        put("dialog.addsession.foundTokens", "📋 Bulunan Tokenlar:", "📋 Found Tokens:");
        put("dialog.addsession.success", "Oturum başarıyla eklendi!\n\nRol: {0}\nOturum: {1}{2}\n\nRoller 'Hepsini Tara' yetki matrisinde otomatik kullanılır (birden çok rol eklemek BOLA/yetki tespitini güçlendirir).", "Session added successfully!\n\nRole: {0}\nSession: {1}{2}\n\nRoles are used automatically in the 'Scan Everything' authorization matrix (adding multiple roles strengthens BOLA/authorization detection).");
        put("dialog.addsession.success.title", "Başarılı", "Success");
        put("dialog.loginprofile.prompt", "Bu login isteği hangi kimlik/rol için? (örn: user, admin)\nHedef: {0}", "Which identity/role is this login request for? (e.g. user, admin)\nTarget: {0}");
        put("dialog.loginprofile.title", "Login Profili Kaydet (şifreli)", "Save Login Profile (encrypted)");
        put("dialog.loginprofile.success", "Login profili ŞİFRELİ kaydedildi.\n\nHedef: {0}\nRol: {1}\n\nOturum düştüğünde araç bu isteği tekrarlayıp kendini yeniden login etmeyi dener. Aynı uygulamayı tekrar test ederken hazır gelir.", "Login profile saved ENCRYPTED.\n\nTarget: {0}\nRole: {1}\n\nWhen the session drops, the tool replays this request to try to re-login itself. It will be ready when you test the same application again.");
        put("dialog.loginprofile.success.title", "Kaydedildi", "Saved");
        put("dialog.loginprofile.error", "Login profili kaydedilemedi: {0}\n(OS keychain erişilemezse Ayarlar'dan master parola gerekir.)", "Could not save login profile: {0}\n(If the OS keychain is unavailable, a master password is required in Settings.)");
        put("dialog.common.error.title", "Hata", "Error");

        // =====================================================================
        //  Finding detail text (f.*) — bilingual description / evidence /
        //  exploitation / remediation emitted by the deterministic scan engine.
        //  Vulnerability TYPE names stay in English (industry standard) by design;
        //  only the human-readable prose is localised. Placeholders: {0},{1}...
        //  carry dynamic values (param, payload, status, byte counts) verbatim.
        // =====================================================================

        // --- InjectionModule (SQLi / XSS / Path Traversal / Command Injection) ---
        put("f.inj.ev", "Parametre: {0} | Yük: {1} | HTTP {2}", "Parameter: {0} | Payload: {1} | HTTP {2}");
        put("f.inj.exp", "Yük: {0}", "Payload: {0}");
        put("f.inj.sqli.desc", "'{0}' parametresine tek tırnak (') enjekte edildiğinde bir SQL hatası tetiklendi.", "A SQL error was triggered by injecting a single quote into '{0}'.");
        put("f.inj.sqli.rem", "Parametreli sorgular / hazırlanmış ifadeler (prepared statements) kullanın.", "Use parameterized queries / prepared statements.");
        put("f.inj.xss.desc", "Yük, '{0}' parametresi üzerinden çalıştırılabilir bir HTML bağlamına KODLANMADAN yansıtıldı.", "Payload reflected UNENCODED in an executable HTML context via '{0}'.");
        put("f.inj.xss.rem", "Bağlama duyarlı çıktı kodlaması uygulayın; CSP kullanın.", "Context-aware output encoding; CSP.");
        put("f.inj.trav.desc", "Yanıt, '{0}' parametresi üzerinden /etc/passwd içeriği barındırıyor (dizin geçişi / path traversal).", "Response contains /etc/passwd content via '{0}' (path traversal).");
        put("f.inj.trav.rem", "Dosya yollarını kanonikleştirin ve beyaz listeyle sınırlayın; kullanıcı girdisini asla dosya yolunda kullanmayın.", "Canonicalize and whitelist file paths; never use user input in paths.");
        put("f.inj.cmdi.desc", "Zaman tabanlı komut enjeksiyonu ORANTILI gecikmelerle doğrulandı: 'sleep {0}' yaklaşık {1}ms, 'sleep {2}' yaklaşık {3}ms gecikme ekledi (gecikme enjekte edilen sleep süresiyle ölçekleniyor — ağ titreşimini eler), '{4}' parametresinde.", "Time-based command injection confirmed by PROPORTIONAL delays: 'sleep {0}' added ~{1}ms and 'sleep {2}' added ~{3}ms (delay scales with the injected sleep — rules out network jitter) in '{4}'.");
        put("f.inj.cmdi.rem", "Kullanıcı girdisini asla kabuk komutlarına geçirmeyin; güvenli API'ler / izin listeleri kullanın.", "Never pass user input to shell commands; use safe APIs / allow-lists.");

        // --- MisconfigModule (security headers / cookies / banner / CORS) ---
        put("f.misc.headers.desc.api", "API/JSON yanıtı ({0}) önerilen güvenlik başlıklarını içermiyor: {1} — bunlar genellikle HTML sayfalarında bulunur ancak API rotalarında atlanır.", "API/JSON response ({0}) is missing recommended security headers: {1} — often present on HTML pages but omitted on API routes.");
        put("f.misc.headers.desc.html", "Yanıt önerilen güvenlik başlıklarını içermiyor: {0}.", "Response is missing recommended security headers: {0}.");
        put("f.misc.headers.ev", "Eksik: {0} | {1}", "Missing: {0} | {1}");
        put("f.misc.headers.exp", "Eksik başlıkları web sunucusu / framework katmanında ekleyin.", "Add the missing headers at the web server / framework layer.");
        put("f.misc.headers.rem", "API'ler dahil TÜM yanıtlar için CSP, X-Frame-Options, HSTS ve X-Content-Type-Options yapılandırın.", "Configure CSP, X-Frame-Options, HSTS and X-Content-Type-Options for ALL responses incl. APIs.");
        put("f.misc.cookie.desc", "'{0}' çerezi {1} bayrağı/bayrakları olmadan ayarlanmış.", "Cookie '{0}' is set without the {1} flag(s).");
        put("f.misc.cookie.exp", "Oturum çerezlerinde Secure ve HttpOnly bayraklarını ayarlayın.", "Set Secure and HttpOnly on session cookies.");
        put("f.misc.cookie.rem", "Hassas çerezlere Secure + HttpOnly (ve SameSite) ekleyin.", "Add Secure + HttpOnly (and SameSite) to sensitive cookies.");
        put("f.misc.banner.desc", "Sunucu bileşen/sürüm afişlerini ifşa ediyor (saldırganın parmak izi çıkarmasına yardımcı olur).", "Server discloses component/version banners (aids attacker fingerprinting).");
        put("f.misc.banner.exp", "Server/X-Powered-By sürüm afişlerini gizleyin.", "Suppress Server/X-Powered-By version banners.");
        put("f.misc.banner.rem", "Sürüm bilgisi taşıyan yanıt başlıklarını kaldırın veya genelleştirin.", "Remove or genericize version-bearing response headers.");
        put("f.misc.cors.desc.creds", "Sunucu, Access-Control-Allow-Origin başlığında rastgele bir Origin değerini KİMLİK BİLGİLERİNE izin vererek yansıtıyor (kökenler arası veri hırsızlığı).", "The server reflects an arbitrary Origin in Access-Control-Allow-Origin WITH credentials allowed (cross-origin data theft).");
        put("f.misc.cors.desc.plain", "Sunucu, Access-Control-Allow-Origin başlığında rastgele bir Origin değerini yansıtıyor.", "The server reflects an arbitrary Origin in Access-Control-Allow-Origin.");
        put("f.misc.cors.ev", "Gönderilen Origin: {0} → ACAO içinde yansıtıldı", "Sent Origin: {0} → reflected in ACAO");
        put("f.misc.cors.exp", "Güvenilir kökenleri izin listesine alın; rastgele Origin değerini asla kimlik bilgileriyle yansıtmayın.", "Whitelist trusted origins; never reflect arbitrary Origin with credentials.");
        put("f.misc.cors.rem", "CORS için bir izin listesi kullanın; ACAO yansıtmasından kaçının.", "Use an allow-list for CORS; avoid ACAO reflection.");

        // --- ContentDiscoveryModule (sensitive paths / component disclosure) ---
        put("f.disc.path.desc", "{0} yolu kimlik doğrulama olmadan erişilebilir (HTTP 200). Yönetim / yönetici veya hassas uç noktalar herkese açık erişilebilir olmamalıdır.", "The path {0} is reachable without authentication (HTTP 200). Admin / management or sensitive endpoints should not be publicly accessible.");
        put("f.disc.path.exp", "{0} adresine anonim olarak göz atın ve yüklendiğini doğrulayın.", "Browse to {0} anonymously and confirm it loads.");
        put("f.disc.path.rem", "Yolu IP izin listesi / kimlik doğrulama ile kısıtlayın; gerekmiyorsa kaldırın.", "Restrict the path by IP allow-list / authentication; remove it if not needed.");
        put("f.disc.tech.desc", "Kurulu bileşenler, sayfa kaynağındaki /App_Plugins/ referansları aracılığıyla ifşa ediliyor: {0}. Bu, hedefli CVE araştırmasına yardımcı olur.", "Installed components are disclosed via /App_Plugins/ references in page source: {0}. This aids targeted CVE research.");
        put("f.disc.tech.exp", "Sayfa kaynağını görüntüleyin ve /App_Plugins/ referanslarını listeleyin.", "View page source and enumerate /App_Plugins/ references.");
        put("f.disc.tech.rem", "/App_Plugins/ dizinine anonim erişimi kısıtlayın; yalnızca geliştirmeye yönelik araçları üretimden kaldırın.", "Restrict anonymous access to /App_Plugins/; remove dev-only tools from production.");

        // --- TransportModule (HTTP->HTTPS downgrade) ---
        put("f.trans.downgrade.desc", "80 numaralı bağlantı noktasındaki düz HTTP, HTTPS'e yönlendirmek yerine içerikle birlikte HTTP {0} döndürüyor. Trafik, herhangi bir TLS yükseltmesinden önce ele geçirilebilir (MitM).", "Plain HTTP on port 80 returns HTTP {0} with content instead of redirecting to HTTPS. Traffic could be intercepted (MitM) before any TLS upgrade.");
        put("f.trans.downgrade.desc.hsts", "HTTPS kökü zaten HSTS ({0}) ayarlıyor, bu nedenle etki yalnızca ilk ziyaret / preload olmayan istemcilerle sınırlıdır.", "The HTTPS root already sets HSTS ({0}), so impact is limited to first-visit / non-preloaded clients.");
        put("f.trans.downgrade.ev.noredir", "b (https'e 301/302 yönlendirmesi yok)", "b (no 301/302 to https)");
        put("f.trans.downgrade.ev.hsts", "HSTS mevcut", "HSTS present");
        put("f.trans.downgrade.exp", "http://{0}/ adresine istek gönderin ve https'e yönlendirme olmadığını doğrulayın.", "Request http://{0}/ and confirm there is no redirect to https.");
        put("f.trans.downgrade.rem", "Web sunucusunda HTTP->HTTPS yönlendirmesini 301 ile zorunlu kılın ve HSTS'i (preload ile) etkin tutun.", "Force HTTP->HTTPS with a 301 redirect at the web server and keep HSTS (with preload) enabled.");

        // --- HttpMethodModule (XST / OPTIONS) ---
        put("f.meth.xst.desc", "Sunucu {0} isteğine isteği YANSITARAK yanıt veriyor (Cross-Site Tracing). {0} yansıması, normalde HttpOnly olan başlıkları/çerezleri okumak için kötüye kullanılabilir.", "The server answers {0} by ECHOING the request (Cross-Site Tracing). {0} echo can be abused to read otherwise HttpOnly headers/cookies.");
        put("f.meth.xst.ev", " / -> HTTP 200 ve yanıt isteği yansıtıyor (Content-Type: {0})", " / -> HTTP 200 and the response echoes the request (Content-Type: {0})");
        put("f.meth.xst.exp", "/ adresine bir {0} isteği gönderin ve yanıtın istek satırını yansıttığını doğrulayın.", "Send a {0} request to / and confirm the response echoes the request line.");
        put("f.meth.xst.rem", "TRACE/TRACK yöntemlerini web sunucusunda devre dışı bırakın (IIS izin verilen fiiller, Apache TraceEnable off).", "Disable TRACE/TRACK at the web server (IIS allowed verbs, Apache TraceEnable off).");
        put("f.meth.options.desc", "OPTIONS, Allow başlığında potansiyel olarak tehlikeli HTTP yöntemleri ilan ediyor: {0}. Allow başlığı genellikle yanlıştır — bunu bir bulgu olarak değerlendirmeden önce fiilin gerçekten çalıştığını elle doğrulayın.", "OPTIONS advertises potentially dangerous HTTP methods in the Allow header: {0}. The Allow header is often inaccurate — confirm manually that the verb actually works before treating this as a finding.");
        put("f.meth.options.ev", " (ilan edildi, doğrulanmadı)", " (advertised, NOT confirmed)");
        put("f.meth.options.exp", "İlan edilen fiili (örn. PUT/DELETE) gönderin ve 405/501 olmayan bir yanıt aldığınızı doğrulayın.", "Send the advertised verb (e.g. PUT/DELETE) and confirm a non-405/501 response.");
        put("f.meth.options.rem", "İzin verilen HTTP yöntemlerini uygulamanın gerçekten ihtiyaç duyduklarıyla sınırlayın.", "Restrict allowed HTTP methods to those the application actually needs.");

        // --- AccessControlModule (auth bypass / JWT) ---
        put("f.access.bypass.desc", "Kaynak, \"{0}\" sonrasında neredeyse aynı bir gövdeyle HTTP 200 döndürdü — yetkilendirme zorunlu kılınmıyor olabilir. Yanıtın gerçekten korumalı/kimliği doğrulanmış içerik taşıdığını (kimlik doğrulamadan bağımsız sunulan herkese açık bir sayfa olmadığını) doğrulayın.", "Resource returned HTTP 200 after \"{0}\" with a near-identical body — authorization may not be enforced. Confirm the response actually contains protected/authenticated content (not a public page served regardless of auth).");
        put("f.access.bypass.ev", "{0} | HTTP {1} | {2}b (temel yanıt {3}b)", "{0} | HTTP {1} | {2}b (baseline {3}b)");
        put("f.access.bypass.exp", "Uç noktanın geçerli kimlik doğrulama/yetkilendirme gerektirdiğini doğrulayın.", "Verify the endpoint requires valid authentication/authorization.");
        put("f.access.bypass.rem", "Her istekte sunucu tarafında kimlik doğrulamayı zorunlu kılın; JWT imzasını ve algoritmasını doğrulayın.", "Enforce server-side auth on every request; validate JWT signature and algorithm.");

        // --- IdorModule ---
        put("f.idor.idor.desc", "Tanımlayıcının ({0}:{1} → {2}) değiştirilmesi HTTP 200 döndürdü ve kesinlikle geçersiz bir id'den (negatif kontrol) farklı, yani id dikkate alınıyor. Farklı bir kullanıcı/kiracı (tenant) nesnesinin ifşa edilip edilmediğini doğrulamak için yapay zeka gövdeleri karşılaştırır.", "Changing the identifier ({0}:{1} → {2}) returned HTTP 200 and differs from a definitely-invalid id (negative control), so the id is honoured. AI compares the bodies to confirm whether a different user/tenant object was exposed.");
        put("f.idor.idor.ev", "{0} ile değiştirildi | HTTP 200 | {1}b (temel yanıt {2}b) | negatif kontrol farklı", "Swapped to {0} | HTTP 200 | {1}b (baseline {2}b) | negative control differs");
        put("f.idor.idor.exp", "Kullanıcılar arası erişimi elle doğrulayın.", "Confirm cross-user access manually.");
        put("f.idor.idor.rem", "Sunucu tarafında nesne-bazlı yetkilendirmeyi (sahiplik kontrolleri) zorunlu kılın.", "Enforce per-object authorization (ownership checks) server-side.");
        put("f.idor.foreign", "Değiştirilen yanıt, bize/genel kaynağa ait olmayan yabancı sahip belirteçleri içeriyor (başka bir kullanıcı/kiracı verisi): {0}", "The tampered response contains foreign owner tokens that are not ours or public (another user/tenant's data): {0}");
        put("f.idor.ownership", "Hesap aitlik kontrolü eksikliği: '{0}' alanı (hesap/müşteri tanımlayıcısı) istemciden alınıp sunucu tarafında sahiplik doğrulaması (IsOwnAccount benzeri) yapılmadan işleniyor olabilir — başka bir müşterinin hesabını/verisini görüntüleme veya o hesap üzerinden işlem yapma riski (OWASP A01 – Broken Access Control / IDOR).", "Account-ownership validation gap: the '{0}' field (an account/customer identifier) is taken from the client and may be processed without a server-side ownership check (IsOwnAccount-style) — risk of viewing another customer's account/data or transacting on it (OWASP A01 – Broken Access Control / IDOR).");

        // --- ParamGuessModule ---
        put("f.pg.bac.desc", "Bildirilmemiş '{0}={1}' parametresinin eklenmesi, bunu yetkilendirme olmadan kabul eden bir uç noktada yanıtı değiştirdi ({2}b -> {3}b). Dahili/ayrıcalıklı verileri (dahili listeler, taslaklar, yönetici görünümleri) ifşa edebilir.", "Adding the undeclared parameter '{0}={1}' changed the response ({2}b -> {3}b) on an endpoint that accepted it without authorization. It may expose internal / privileged data (internal listings, drafts, admin views).");
        put("f.pg.bac.ev", "{0}={1} | {2}b -> {3}b", "{0}={1} | {2}b -> {3}b");
        put("f.pg.bac.exp", "Yanıtı parametre varken ve yokken karşılaştırın; kısıtlı veri ifşa edip etmediğini doğrulayın.", "Compare the response with and without the parameter; verify it exposes restricted data.");
        put("f.pg.bac.rem", "Görünürlük bayrakları için sunucu tarafında yetkilendirmeyi zorunlu kılın; istemcinin sağladığı ayrıcalık parametrelerini yok sayın.", "Enforce server-side authorization for visibility flags; ignore client-supplied privilege parameters.");

        // --- BruteForceModule ---
        put("f.bf.weakpw.desc", "Tahmin edilen/yaygın bir parola ('{0}') ile oturum açma başarılı oldu. Hesap zayıf, tahmin edilebilir bir kimlik bilgisi kullanıyor ve kimlik doğrulama kaba kuvvete açık.", "A login succeeded with a guessed/common password ('{0}'). The account uses a weak, predictable credential and authentication is brute-forceable.");
        put("f.bf.weakpw.ev", "password='{0}' -> HTTP {1} (kimlik doğrulanmış yanıt)", "password='{0}' -> HTTP {1} (authenticated response)");
        put("f.bf.weakpw.exp", "Erişimi doğrulamak için oturum açmayı listelenen parola ile tekrar oynatın.", "Replay the login with the listed password to confirm access.");
        put("f.bf.weakpw.rem", "Güçlü bir parola politikası zorunlu kılın (şirket/klavye kalıplarını engelleyin), MFA isteyin, N başarısız denemeden sonra hesabı kilitleyin.", "Enforce a strong password policy (block company/keyboard patterns), require MFA, lock accounts after N failures.");
        put("f.bf.noprotect.desc", "{0} ardışık oturum açma denemesi, herhangi bir hız sınırlama veya hesap kilitleme olmadan işlendi (HTTP 429 / kilitleme yanıtı yok). Bu ZAYIF bir sinyaldir — oturum açmanın CAPTCHA içermediğini ve gerçekçi sayıda denemeden sonra kilitleme uygulamadığını elle doğrulayın.", "{0} consecutive login attempts were processed with no rate-limiting or lockout (no HTTP 429 / lockout response). This is a WEAK signal — confirm manually that the login has no CAPTCHA and no lockout after a realistic number of attempts.");
        put("f.bf.noprotect.ev", "{0} deneme, 0 engellendi (düşük eşik — elle doğrulayın)", "{0} attempts, 0 blocked (low threshold — verify manually)");
        put("f.bf.noprotect.exp", "Sonuca varmadan önce daha fazla oturum açma denemesi yapın ve bir CAPTCHA ya da kilitleme olup olmadığını kontrol edin.", "Repeat more login attempts and check for a CAPTCHA or lockout before concluding.");
        put("f.bf.noprotect.rem", "Kimlik doğrulamada hesap kilitleme, hız sınırlama ve CAPTCHA uygulayın.", "Implement account lockout, rate limiting and CAPTCHA on authentication.");

        // --- CaptchaBypassModule ---
        put("f.cap.how.omit", "CAPTCHA parametresi KALDIRILMIŞ olarak", "with the CAPTCHA parameter REMOVED");
        put("f.cap.how.empty", "BOŞ bir CAPTCHA değeriyle", "with an EMPTY CAPTCHA value");
        put("f.cap.how.garbage", "GEÇERSİZ bir CAPTCHA değeriyle", "with a GARBAGE CAPTCHA value");
        put("f.cap.bypass.ev.strong", " · kimlik bilgisi/sonraki adıma ulaşıldı", " · credential/next-step reached");
        put("f.cap.bypass.ev.weak", " · referansla (baseline) aynı", " · same as baseline");
        put("f.cap.bypass.desc", "Uç nokta isteği {0} işledi — sunucu geçerli bir CAPTCHA talep etmek yerine kimlik bilgisi/sonraki adım işlemesine (HTTP {1}) ulaştı. CAPTCHA sunucu tarafında zorunlu kılınmıyor; bu nedenle bu işleme yönelik otomatik kaba kuvvet / kimlik bilgisi doldurma (credential stuffing) / toplu kötüye kullanımı mümkün kılmak için atlanabilir.", "The endpoint processed the request {0} — the server reached credential/next-step handling (HTTP {1}) instead of demanding a valid CAPTCHA. The CAPTCHA is not enforced server-side, so it can be skipped to enable automated brute-force / credential-stuffing / mass abuse of this action.");
        put("f.cap.bypass.ev", "{0} → HTTP {1} · {2}b (referans/baseline {3}b){4}", "{0} → HTTP {1} · {2}b (baseline {3}b){4}");
        put("f.cap.bypass.exp", "İsteği {0} tekrar oynatın ve CAPTCHA çözülmeden işlemin yine de devam ettiğini doğrulayın.", "Replay the request {0} and confirm the action still proceeds without solving the CAPTCHA.");
        put("f.cap.bypass.rem", "CAPTCHA token'ını HER gönderimde sunucu tarafında doğrulayın; eksik/boş/kullanılmış token'ları reddedin; token'ı tek kullanımdan sonra geçersiz kılın; katmanlı savunma olarak hız sınırlama/hesap kilitleme ekleyin.", "Validate the CAPTCHA token server-side on EVERY submission; reject missing/empty/used tokens; invalidate the token after a single use; add rate-limiting/lockout as defense in depth.");

        // --- FileUploadModule ---
        put("f.upl.unrestricted.desc.reflected", "Tehlikeli uzantıya sahip bir dosya kabul edildi (HTTP {0}). Yüklenen dosya adı/işaretçisi (marker) yanıtta yansıtıldı (bir erişim yolu mevcut; çalıştırma henüz kanıtlanmadı).", "A file with a dangerous extension was accepted (HTTP {0}). The uploaded filename/marker is reflected in the response (a retrieval path exists; execution still unproven).");
        put("f.upl.unrestricted.desc.unconfirmed", "Tehlikeli uzantıya sahip bir dosya kabul edildi (HTTP {0}). Tehlikeli uzantı kabul edildi (reddedilmedi); dosyanın depolandığını ve sunulduğunu/çalıştırıldığını doğrulayın.", "A file with a dangerous extension was accepted (HTTP {0}). The dangerous extension was accepted (no rejection); confirm the file is stored and served/executed.");
        put("f.upl.unrestricted.ev", "Tehlikeli uzantı yüklendi | HTTP {0}{1}", "Uploaded dangerous extension | HTTP {0}{1}");
        put("f.upl.unrestricted.ev.marker", " | işaretçi (marker) yansıtıldı", " | marker reflected");
        put("f.upl.unrestricted.exp", "Sunucuda çalıştırılabilir bir uzantıya sahip bir dosya yükleyin ve dosyanın depolanıp depolanmadığını VE sunulup/çalıştırılıp çalıştırılmadığını kontrol edin.", "Upload a file with a server-executable extension and check if it is stored AND served/executed.");
        put("f.upl.unrestricted.rem", "Uzantıları/içerik türlerini beyaz listeye alın, dosyaları web kök dizini dışında saklayın, dosya adlarını rastgele oluşturun.", "Whitelist extensions/content-types, store outside web root, randomize names.");

        // --- MassAssignmentModule (BOPLA) ---
        put("f.mass.bopla.desc.echo", "Uç nokta, enjekte edilen ayrıcalıklı/sahiplik özelliğini '{0}={1}' kabul etti ve dönen varlık (entity) artık bu key:value çiftini taşıyor (temel yanıtta yoktu) — ancak istek gövdesi geri yansıtıldığı için, değerin yalnızca yansıtılmadığını, gerçekten BAĞLANDIĞINI (nesneyi yeniden okuyarak) doğrulayın. Bu durum yetki yükseltmesine / sahiplik ele geçirilmesine (mass assignment / BOPLA) yol açabilir.", "The endpoint accepted an injected privileged/ownership property '{0}={1}' and the returned entity now carries that key:value pair (absent from the baseline) — but the request body is echoed back, so confirm the value was BOUND (re-read the object), not merely reflected. This may allow privilege escalation / ownership takeover (mass assignment / BOPLA).");
        put("f.mass.bopla.desc.bound", "Uç nokta, enjekte edilen ayrıcalıklı/sahiplik özelliğini '{0}={1}' kabul etti ve dönen varlık (entity) artık bu key:value çiftini taşıyor (temel yanıtta yoktu) — özellik bağlandı. Bu durum yetki yükseltmesine / sahiplik ele geçirilmesine (mass assignment / BOPLA) yol açabilir.", "The endpoint accepted an injected privileged/ownership property '{0}={1}' and the returned entity now carries that key:value pair (absent from the baseline) — the field was bound. This may allow privilege escalation / ownership takeover (mass assignment / BOPLA).");
        put("f.mass.bopla.ev", "enjekte edilen {0}={1} | HTTP {2} | key:value yanıtta", "injected {0}={1} | HTTP {2} | key:value in response");
        put("f.mass.bopla.ev.echo", "enjekte edilen {0}={1} | HTTP {2} | key:value yanıtta (yankı?)", "injected {0}={1} | HTTP {2} | key:value in response (echo?)");
        put("f.mass.bopla.exp", "Özelliğin gerçekten etkili olup olmadığını doğrulayın (nesneyi yeniden okuyun / ayrıcalığı kontrol edin).", "Verify the property actually took effect (re-read the object / check the privilege).");
        put("f.mass.bopla.rem", "Bağlanabilir alanları sunucu tarafında beyaz listeye alın; istemci girdisini asla ayrıcalıklı/sahiplik özelliklerine bağlamayın.", "Allow-list bindable fields server-side; never bind client input to privileged/ownership properties.");

        // --- ErrorForcingModule (stack trace disclosure) ---
        put("f.err.stacktrace.desc", "Bozuk bir istek ({0}) HTTP {1} döndürdü ve ayrıntılı bir hata ile bir yığın izi (stack trace) / kaynak yolu / framework iç ayrıntıları sızdırdı. Bu durum, saldırganlara sunucu dosya yollarını ve bileşen ayrıntılarını ifşa eder.", "A malformed request ({0}) returned HTTP {1} with a verbose error leaking a stack trace / source path / framework internals. This exposes server file paths and component details to attackers.");
        put("f.err.stacktrace.ev.srcpath", "Kaynak yolu: {0} | ", "Source path: {0} | ");
        put("f.err.stacktrace.ev.trace", "İz: {0}", "Trace: {0}");
        put("f.err.stacktrace.exp", "Bozuk isteği yeniden gönderin ve sızdırılan yol/sınıf adlarını gözlemleyin.", "Replay the malformed request and observe the leaked path/class names.");
        put("f.err.stacktrace.rem", "Üretim ortamında ayrıntılı/geliştirici hata sayfalarını devre dışı bırakın; genel 500 yanıtları döndürün ve ayrıntıları yalnızca sunucu tarafında günlüğe kaydedin.", "Disable verbose/developer error pages in production; return generic 500s and log details server-side only.");

        // --- SsrfRedirectModule ---
        put("f.ssrf.openredirect.desc", "'{0}' parametresi, harici bir sunucuya yapılan yönlendirmeyi kontrol ediyor.", "The '{0}' parameter controls a redirect to an external host.");
        put("f.ssrf.openredirect.ev", "Yük: {0} | HTTP {1} | Location → evil.example", "Payload: {0} | HTTP {1} | Location → evil.example");
        put("f.ssrf.openredirect.exp", "Yönlendirme hedeflerini bir izin listesine göre doğrulayın.", "Validate redirect targets against an allow-list.");
        put("f.ssrf.openredirect.rem", "Yalnızca göreli veya beyaz listedeki yönlendirme URL'lerine izin verin.", "Only allow relative or whitelisted redirect URLs.");
        put("f.ssrf.ssrf.desc", "'{0}' parametresi bir iç/metadata URL'i getirdi (sunucu taraflı istek sahteciliği - SSRF).", "The '{0}' parameter fetched an internal/metadata URL (server-side request forgery).");
        put("f.ssrf.ssrf.ev", "Yük: {0} | metadata içeriği döndü", "Payload: {0} | metadata content returned");
        put("f.ssrf.ssrf.exp", "İç IP aralıklarını/metadata'yı engelleyin; bir çıkış (egress) izin listesi kullanın.", "Block internal IP ranges/metadata; use an egress allow-list.");
        put("f.ssrf.ssrf.rem", "Sunucu taraflı getirme hedeflerini doğrulayın ve kısıtlayın.", "Validate and restrict server-side fetch destinations.");

        // --- ForcedBrowser ---
        put("f.fb.exposure.desc", "Zorlamalı gezinme {0} kaynağına erişilebildiğini buldu (HTTP 200). {1}", "Forced browsing found {0} reachable (HTTP 200). {1}");
        put("f.fb.exposure.ev", "{0} → HTTP 200 ({1}b)", "{0} → HTTP 200 ({1}b)");
        put("f.fb.exposure.exp", "{0} adresine anonim olarak gidip ifşayı doğrulayın.", "Browse to {0} anonymously and confirm the exposure.");
        put("f.fb.exposure.rem", "Kaynağı kaldırın veya kısıtlayın; hassas dosya/yolları web sunucusunda engelleyin.", "Remove or restrict the resource; block sensitive files/paths at the web server.");
        put("f.fb.describe.secrets", "Sırları/kimlik bilgilerini ifşa edebilir.", "May expose secrets/credentials.");
        put("f.fb.describe.vcs", "Sürüm kontrolü metadata'sı tüm kaynak kodun ifşasına olanak tanıyabilir.", "Source-control metadata may allow full source disclosure.");
        put("f.fb.describe.dbdump", "Bir veritabanı/yedek dökümünü ifşa edebilir.", "May expose a database/backup dump.");
        put("f.fb.describe.mgmt", "Bir yönetim arayüzü herkese açık erişilebilir olmamalıdır.", "A management interface should not be publicly reachable.");
        put("f.fb.describe.internals", "Sunucu/yapılandırma iç ayrıntılarını ifşa eder.", "Exposes server/config internals.");
        put("f.fb.describe.review", "Herkese açık erişilebilir olması gerekip gerekmediğini değerlendirin.", "Review whether it should be publicly reachable.");

        // --- ParamMiningTester ---
        put("f.pmt.honored.desc", "AI ile keşfedilen gizli bir parametre '{0}={1}' uç nokta tarafından kabul ediliyor (durum {2}{3}, gövde {4}b→{5}b{6}). Orijinal istekte yoktu — iç davranışı, veriyi veya yetkilendirmeyi ifşa edebilir.", "An AI-mined hidden parameter '{0}={1}' is honoured by the endpoint (status {2}{3}, body {4}b→{5}b{6}). It was not in the original request — may expose internal behaviour, data or authorization.");
        put("f.pmt.honored.desc.baseline", " vs taban {0}", " vs baseline {0}");
        put("f.pmt.honored.desc.reflected", ", yansıtıldı", ", reflected");
        put("f.pmt.honored.ev", "eklendi {0}={1} | {2}→{3} | {4}b→{5}b{6}", "added {0}={1} | {2}→{3} | {4}b→{5}b{6}");
        put("f.pmt.honored.ev.reflected", " | yansıdı", " | reflected");
        put("f.pmt.honored.exp", "Parametreyi elle ekleyip karşılaştırın; kısıtlı veri/davranış ifşa edip etmediğini kontrol edin.", "Add the parameter manually and compare; check whether it exposes restricted data/behaviour.");
        put("f.pmt.honored.rem", "Belgelenmemiş istemci parametrelerini yok sayın; sunucu tarafında izin listeleri ve yetkilendirme uygulayın.", "Ignore undocumented client parameters; enforce server-side allow-lists and authorization.");

        // --- DetectionPipeline (attack chain / AI test wrapper labels) ---
        put("f.dp.chain.desc", "AI çok adımlı bir saldırı zinciri kurup yürüttü.\n\n{0}", "AI constructed and executed a multi-step attack chain.\n\n{0}");
        put("f.dp.chain.ev", "Zincir Yürütme Günlüğü:\n{0}", "Chain Execution Log:\n{0}");
        put("f.dp.chain.exp", "Zincir adımlarını elle doğrulayın.", "Verify the chain steps manually.");
        put("f.dp.chain.rem", "Durum doğrulaması ve güvenli iş akışı mantığı uygulayın.", "Implement state validation and secure workflow logic.");
        put("f.dp.aitest.ev", "Parametre: {0} | Yük: {1} | HTTP {2}", "Parameter: {0} | Payload: {1} | HTTP {2}");
        put("f.dp.aitest.vulnif", "\n\nZafiyet koşulu: {0}", "\n\nVulnerable if: {0}");
        put("f.dp.aitest.exp", "Yük: {0}", "Payload: {0}");

        // --- ScenarioAccessTester (cross-owner BOLA) ---
        put("f.sat.bola.desc", "'{0}' kimliği, {1} nesnesine ('{2}' tarafından kanıtlanabilir şekilde sahip olunan) erişti ve HTTP 200 yanıtı aldı. Nesne farklı bir kimliğe ait olduğundan bu, yetkisiz çapraz-sahip nesne erişimidir.", "Identity '{0}' accessed object {1} (provably owned by '{2}') and received HTTP 200. The object belongs to a different identity, so this is unauthorized cross-owner object access.");
        put("f.sat.bola.ev", "attacker={0} | victim={1} | object={2} | {3}", "attacker={0} | victim={1} | object={2} | {3}");
        put("f.sat.bola.exp", "Kurbanın nesne isteğini saldırganın oturumuyla tekrar oynatın ve veriyi doğrulayın.", "Replay the victim's object request with the attacker's session and confirm the data.");
        put("f.sat.bola.rem", "Sunucu tarafında nesne başına sahiplik denetimlerini zorunlu kılın (nesne, çağrıyı yapana ait olmalıdır).", "Enforce per-object ownership checks server-side (the object must belong to the caller).");
        put("f.sat.ownermatch", "Sahip-görünümü eşleşmesi: saldırganın aldığı gövde, nesnenin gerçek sahibinin gördüğüyle birebir aynı — çapraz-sahip erişim kanıtlandı (kendi verisi değil, genel kaynak değil).", "Owner-view match: the attacker's body is identical to what the object's real owner sees — cross-owner access proven (not the caller's own data, not a public resource).");
        put("f.sat.writeidor.desc", "'{0}' kimliği, '{3}' kimliğine ait {2} nesnesini {1} ile DEĞİŞTİREBİLDİ (saldırganın oturumuyla; geçerli id'de 2xx, geçersiz id'de reddedildi). Bu, yetkisiz çapraz-sahip YAZMA erişimidir — başka bir sahibin nesnesini değiştirme (okuma-IDOR'dan daha yüksek etki).", "Identity '{0}' was able to {1} object {2} owned by '{3}' (attacker's session; 2xx on the valid id, denied on an invalid id). This is unauthorized cross-owner WRITE access — modifying another owner's object (higher impact than read-IDOR).");
        put("f.sat.writeidor.ev", "attacker={0} | victim={1} | {2} object={3} | {4}", "attacker={0} | victim={1} | {2} object={3} | {4}");
        put("f.sat.writeidor.exp", "Kurbanın değiştirme isteğini (kendi gövdesiyle, idempotent) saldırganın oturumuyla tekrar oynatın; geçerli id'de 2xx ama geçersiz id'de ret → yazma yetkisi başka sahibin nesnesinde atlanıyor.", "Replay the victim's mutating request (its own body, idempotent) with the attacker's session; 2xx on the valid id but denied on an invalid id proves the write authorization is missing on another owner's object.");
        put("f.sat.writeidor.rem", "Sunucu tarafında her DEĞİŞTİRME (PUT/PATCH/DELETE) işleminde nesne-başına sahiplik yetkisini zorunlu kılın; istemciden gelen id'ye tek başına güvenmeyin.", "Enforce per-object ownership authorization on every mutating operation (PUT/PATCH/DELETE) server-side; never trust the client-supplied id alone.");
        put("f.sat.writeidor.note", "Replay idempotent (kurbanın kendi gövdesi) — veri değiştirilmedi; yalnızca yazma yetkisinin atlandığı kanıtlandı.", "Idempotent replay (victim's own body) — no data was changed; only the missing write-authorization was proven.");

        // --- ResponseAnalyzer (text-fallback deterministic findings) ---
        put("f.aiapp.desc", "{0} yönetim arayüzü/API'si internete açık tespit edildi ({1}). AI uygulama çatıları sık sık kimlik doğrulamasız dağıtılır ve kritik kod-çalıştırma/dosya-okuma uç noktaları barındırır.", "An exposed {0} administrative interface/API was detected ({1}). AI application frameworks are often deployed without authentication and expose critical code-execution/file-read endpoints.");
        put("f.aiapp.ev", "İmza yolu {0} → HTTP {1}; gövdede '{2}' işareti. Riskli uç nokta: {3}", "Signature path {0} → HTTP {1}; body marker '{2}'. Sensitive endpoint: {3}");
        put("f.aiapp.exp", "Bu çatının bilinen kritik uç noktaları ({0}) kimlik doğrulama olmadan erişilebilirse uzaktan kod çalıştırma veya rastgele dosya okuma mümkün olabilir. Erişilebilirlik GÜVENLİ biçimde (payload gönderilmeden) doğrulandı; sömürü denenmedi.", "If this framework's known-critical endpoints ({0}) are reachable without authentication, remote code execution or arbitrary file read may be possible. Reachability was verified SAFELY (no payload sent); no exploitation was attempted.");
        put("f.aiapp.rem", "{0} çatısını internete kapatın (ağ segmentasyonu / VPN / zorunlu kimlik doğrulama); en son sürüme yükseltin; yönetim ve kod-çalıştırma uç noktalarını kısıtlayın.", "Remove the {0} framework from internet exposure (network segmentation / VPN / enforced authentication); upgrade to the latest version; restrict administrative and code-execution endpoints.");
        put("f.kev.note", "⚠ AKTİF SÖMÜRÜLÜYOR: aşağıdaki CVE'ler vahşi doğada aktif olarak sömürülüyor (CISA KEV / gözlemlenen saldırılar) — öncelikli olarak giderin: {0}", "⚠ ACTIVELY EXPLOITED: the following CVEs are being exploited in the wild (CISA KEV / observed attacks) — prioritize remediation: {0}");
        put("f.ra.serverver.desc", "Yanıtta sunucu sürümü ifşa edildi: {0}", "Server version disclosed in response: {0}");
        put("f.ra.serverver.ev", "Server: {0}", "Server: {0}");
        put("f.ra.serverver.exp", "Saldırganlar bu sürümdeki bilinen zafiyetleri araştırabilir.", "Attackers can search for known vulnerabilities in this version");
        put("f.ra.serverver.rem", "Sunucu yapılandırmasında sürüm bilgisini gizleyin.", "Hide version information in server configuration");
        put("f.ra.techstack.desc", "X-Powered-By başlığı şunu açığa çıkarıyor: {0}", "X-Powered-By header reveals: {0}");
        put("f.ra.techstack.ev", "X-Powered-By: {0}", "X-Powered-By: {0}");
        put("f.ra.techstack.exp", "Saldırganlar teknolojiye özgü zafiyetleri hedefleyebilir.", "Attackers can target technology-specific vulnerabilities");
        put("f.ra.techstack.rem", "Sunucu yapılandırmasından X-Powered-By başlığını kaldırın.", "Remove X-Powered-By header from server configuration");
        put("f.ra.sqlerr.desc", "Yanıtta MySQL hata mesajları görünüyor.", "MySQL error messages visible in response");
        put("f.ra.sqlerr.ev", "Yanıtta MySQL hatası tespit edildi", "MySQL error detected in response");
        put("f.ra.sqlerr.exp", "SQL enjeksiyonu zafiyetine işaret edebilir.", "May indicate SQL injection vulnerability");
        put("f.ra.sqlerr.rem", "Uygun hata yönetimi uygulayın ve ayrıntılı hata mesajlarını devre dışı bırakın.", "Implement proper error handling and disable detailed error messages");

        // --- ScanManager (authorization matrix) ---
        put("f.sm.authzmatrix.exp", "Yetki matrisi ile tespit edildi", "Detected via the authorization matrix");

        // --- AccessOracle (authorization-matrix violations V1/V2/V3) ---
        put("f.ao.v1.ev", "anonim (kimlik doğrulamasız) -> HTTP {0}, korumalı yolda", "anonymous (no auth) -> HTTP {0} on protected path");
        put("f.ao.v1.desc", "{0} {1} uç noktası, kimliği doğrulanmamış bir istemciye içerik döndürüyor. Korumalı bir kaynağa oturum olmadan erişilebiliyor.", "The endpoint {0} {1} returns content to an unauthenticated client. A protected resource is reachable with no session.");
        put("f.ao.v1.rem", "Bu rota için sunucu tarafında kimlik doğrulama/yetkilendirme zorunlu kılın; arayüze (UI) güvenmeyin.", "Require authentication/authorization server-side for this route; do not rely on the UI.");
        put("f.ao.v2.ev", "'{0}' rolü (seviye {1}) -> HTTP {2}, ayrıcalıklı yolda", "role '{0}' (rank {1}) -> HTTP {2} on privileged path");
        put("f.ao.v2.desc", "Düşük ayrıcalıklı bir rol, bir yönetim/ayrıcalıklı uç noktaya ({0} {1}) erişiyor. İşlev düzeyinde erişim denetimi eksik.", "A low-privilege role accesses a management/privileged endpoint ({0} {1}). Function-level access control is missing.");
        put("f.ao.v2.rem", "Ayrıcalıklı rotalarda sunucu tarafında rol tabanlı yetkilendirmeyi zorunlu kılın.", "Enforce role-based authorization on privileged routes server-side.");
        put("f.ao.v3.ev", "'{0}' ve '{1}' rolleri aynı nesne-uçlu kaynağa erişiyor (AI içerik karşılaştırması)", "roles '{0}' & '{1}' access the same object-bearing resource (AI body comparison)");
        put("f.ao.v3.desc", "Nesne referanslı bir uç noktaya ({0} {1}) iki farklı kimlik erişebiliyor; çapraz kullanıcı/kiracı erişimini doğrulamak için AI yanıt gövdelerini karşılaştırır.", "An object-referencing endpoint ({0} {1}) is reachable by two different identities; AI compares the response bodies to confirm cross-user/tenant access.");
        put("f.ao.v3.rem", "Nesne başına sahiplik denetimlerini zorunlu kılın (nesne, çağrıyı yapana ait olmalıdır).", "Enforce per-object ownership checks (the object must belong to the caller).");

        // --- ChainAttackDetector (predefined business-logic attack chains) ---
        put("f.chain.ev.success", "Toplam {0} adımın tamamı başarıyla yürütüldü", "Successfully executed all {0} steps");
        put("f.chain.ev.failed", "Zincir yürütmesi {0}. adımda başarısız oldu", "Chain execution failed at step {0}");
        put("f.chain.ev.error", "Hata: ", "Error: ");
        put("f.chain.impact.registration", "Saldırgan, doğrulama olmadan admin hesapları oluşturabilir; bu durum uygulamanın tamamen ele geçirilmesine yol açar", "Attacker can create admin accounts without verification, leading to full application compromise");
        put("f.chain.impact.cart", "Saldırgan, ürünleri keyfi fiyatlarla satın alarak doğrudan maddi kayba neden olabilir", "Attacker can purchase items for arbitrary prices, causing direct financial loss");
        put("f.chain.impact.pwreset", "Saldırgan, yöneticiler dahil herhangi bir kullanıcı hesabını ele geçirebilir", "Attacker can takeover any user account, including administrators");
        put("f.chain.impact.idor", "Saldırgan, admin işlevlerine erişebilir, tüm kullanıcı verilerini görüntüleyebilir/değiştirebilir", "Attacker can access admin functionality, view/modify all user data");
        put("f.chain.impact.apikey", "Sızdırılan kimlik bilgileri, hesabın tamamen ele geçirilmesine ve veri hırsızlığına olanak tanır", "Leaked credentials allow complete account takeover and data theft");
        put("f.chain.impact.default", "Yetkisiz erişime olanak tanıyan kritik bir güvenlik zafiyeti", "Critical security vulnerability allowing unauthorized access");
        put("f.chain.rem.registration", "Önerilen düzeltmeler:\n\n1. Hesap etkinleştirilmeden önce e-posta doğrulamasını zorunlu kılın\n2. İstemciden gelen rol/ayrıcalık parametrelerini asla kabul etmeyin\n3. Sunucu tarafında rol atama mantığını uygulayın\n4. Kayıt uç noktalarına hız sınırlama ekleyin\n", "Recommended fixes:\n\n1. Enforce mandatory email verification before account activation\n2. Never accept role/privilege parameters from client\n3. Implement server-side role assignment logic\n4. Add rate limiting on registration endpoints\n");
        put("f.chain.rem.cart", "Önerilen düzeltmeler:\n\n1. Tüm fiyatları sunucu tarafında doğrulayın, istemciye asla güvenmeyin\n2. Kullanıcı başına indirim kodu kullanım limitleri uygulayın\n3. Adet değerlerini doğrulayın (negatif sayı olmamalı)\n4. Sepet verileri üzerinde bütünlük kontrolleri ekleyin\n", "Recommended fixes:\n\n1. Validate all prices server-side, never trust client\n2. Implement discount code usage limits per user\n3. Validate quantity values (no negative numbers)\n4. Add integrity checks on cart data\n");
        put("f.chain.rem.pwreset", "Önerilen düzeltmeler:\n\n1. Kriptografik olarak güçlü, rastgele sıfırlama token'ları kullanın\n2. Tek kullanımlık token'lar uygulayın\n3. Kısa bir geçerlilik süresi ekleyin (15-30 dakika)\n4. Kullanıcı başına sıfırlama isteklerini hız sınırlamaya tabi tutun\n", "Recommended fixes:\n\n1. Use cryptographically strong, random reset tokens\n2. Implement single-use tokens\n3. Add short expiration time (15-30 minutes)\n4. Rate limit reset requests per user\n");
        put("f.chain.rem.idor", "Önerilen düzeltmeler:\n\n1. Tüm uç noktalarda uygun yetkilendirme kontrolleri uygulayın\n2. Rastgele, tahmin edilemez tanımlayıcılar (UUID) kullanın\n3. Veri döndürmeden önce kullanıcı izinlerini doğrulayın\n4. Hassas uç noktalara yapılan tüm erişimleri günlüğe kaydedin\n", "Recommended fixes:\n\n1. Implement proper authorization checks on all endpoints\n2. Use random, unpredictable identifiers (UUIDs)\n3. Verify user permissions before returning data\n4. Log all access to sensitive endpoints\n");
        put("f.chain.rem.apikey", "Önerilen düzeltmeler:\n\n1. API anahtarlarını veya token'ları yanıtlarda asla açığa çıkarmayın\n2. Yenileme mekanizmalı kısa ömürlü token'lar kullanın\n3. Token rotasyon politikası uygulayın\n4. API kullanımına hız sınırlama ve izleme ekleyin\n", "Recommended fixes:\n\n1. Never expose API keys or tokens in responses\n2. Use short-lived tokens with refresh mechanism\n3. Implement token rotation policy\n4. Add rate limiting and monitoring on API usage\n");
        put("f.chain.rem.default", "Önerilen düzeltmeler:\n\n1. Uygun kimlik doğrulama ve yetkilendirme uygulayın\n2. Tüm girdileri sunucu tarafında doğrulayın\n3. En az ayrıcalık ilkesini izleyin\n4. Kapsamlı güvenlik günlüğü ekleyin\n", "Recommended fixes:\n\n1. Implement proper authentication and authorization\n2. Validate all inputs server-side\n3. Follow principle of least privilege\n4. Add comprehensive security logging\n");
        put("f.chain.desc.registration", "Kullanıcı oluştur, e-posta doğrulamasını atla, admin'e yükselt", "Create user, bypass email verification, escalate to admin");
        put("f.chain.scenario.registration", "1. Yeni kullanıcı hesabı oluştur\n2. E-posta doğrulamasını atla veya atlat\n3. Admin ayrıcalıkları elde etmek için rol parametresini değiştir\n4. Admin uç noktalarına eriş", "1. Create new user account\n2. Skip or bypass email verification\n3. Modify role parameter to gain admin privileges\n4. Access admin endpoints");
        put("f.chain.desc.cart", "Ürün ekle, birden fazla indirim uygula, nihai fiyatı manipüle et", "Add items, apply multiple discounts, manipulate final price");
        put("f.chain.scenario.cart", "1. Sepete pahalı ürünler ekle\n2. İndirim kodunu birden fazla kez uygula\n3. Adedi negatif değere manipüle et\n4. Ödeme isteğinde nihai fiyatı değiştir\n5. Manipüle edilmiş fiyatla satın almayı tamamla", "1. Add expensive items to cart\n2. Apply discount code multiple times\n3. Manipulate quantity to negative value\n4. Modify final price in checkout request\n5. Complete purchase with manipulated price");
        put("f.chain.desc.pwreset", "Zayıf parola sıfırlama mekanizmasını istismar et", "Exploit weak password reset mechanism");
        put("f.chain.scenario.pwreset", "1. Kurban için parola sıfırlama talep et\n2. Sıfırlama token'ını yakala veya tahmin et\n3. Token'ı birden fazla kez yeniden kullan\n4. Kurbanın parolasını sıfırla\n5. Kurban olarak giriş yap", "1. Request password reset for victim\n2. Intercept or predict reset token\n3. Reuse token multiple times\n4. Reset victim's password\n5. Login as victim");
        put("f.chain.desc.idor", "Diğer kullanıcılara erişmek için IDOR'u istismar et, admin'e yükselt", "Exploit IDOR to access other users, escalate to admin");
        put("f.chain.scenario.idor", "1. Kullanıcı uç noktasında IDOR zafiyeti bul\n2. Admin kullanıcıları bulmak için kullanıcı ID'lerini numaralandır\n3. Admin kullanıcı verilerine eriş\n4. Admin oturum token'larını çıkar\n5. Yalnızca admin'e özel uç noktalara eriş", "1. Find IDOR vulnerability in user endpoint\n2. Enumerate user IDs to find admin users\n3. Access admin user data\n4. Extract admin session tokens\n5. Access admin-only endpoints");
        put("f.chain.desc.apikey", "Sızdırılan kimlik bilgileri hesabın tamamen ele geçirilmesine yol açar (harekete geçmeden önce token'ın bir CSRF/oturum token'ı değil, uzun ömürlü bir API anahtarı/access token olduğunu doğrulayın).", "Leaked credentials lead to full account compromise (verify the token is a long-lived API key/access token, not a CSRF/session token, before acting).");
        put("f.chain.scenario.apikey", "1. Yanıttan API anahtarını/token'ını çıkar\n2. Kurban olarak kimlik doğrulamak için token'ı kullan\n3. Kurbanın hassas verilerine eriş\n4. Kurban adına işlemler gerçekleştir\n5. Erişilebilir tüm verileri dışarı sız", "1. Extract API key/token from response\n2. Use token to authenticate as victim\n3. Access victim's sensitive data\n4. Perform actions on behalf of victim\n5. Exfiltrate all accessible data");
    }
}

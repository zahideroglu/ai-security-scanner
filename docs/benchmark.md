# AppSecHunter — Golden Benchmark & Scorecard

Amaç: "iyileşti"yi lafla değil **sayıyla** kanıtlamak. Her faz/PR bu scorecard'a karşı ölçülür;
bir metrik düşerse regression sayılır. (Profesyonellik ekseni #1: ölçülebilir kalite.)

## Baseline (neye karşı ölçüyoruz)

- **OWASP Juice Shop** (varsayılan) — bilinen BOLA/IDOR, broken access control, injection seti.
- **DVWA** — klasik injection/XSS/CSRF seti.
- **Gerçek 15-bulgulu koşu** — tek-seferlik duman testi (6 yanlış-kritik referansı).
- *(Kendi test uygulaman eklenebilir.)*

Her hedef için elle küratörlü bir **ground-truth listesi** tutulur: `{endpoint, vuln-class, doğru-severity}`.

## Scorecard (her koşuda tek satır, önce → sonra)

| Metrik | Eşik (kabul) | Tanım |
|---|---|---|
| **Uydurma-kritik** | **= 0** (sert kapı) | Ground-truth'ta olmayan Critical/High raporlanmamalı. Deterministik kanıtı olmayan Critical/High sevk edilemez. |
| **Severity doğruluğu** | **≥ %90** | Raporlanan `effectiveSeverity`, ground-truth severity ile eşleşsin. |
| **Precision (1 − FP)** | **≥ %85** | Raporlanan (FP-gizli olmayan) bulguların ≥%85'i gerçek. |
| **Recall** | **≥ %70** | Ground-truth zafiyetlerinin ≥%70'i bulunsun (özellikle access-control/BOLA alt-kümesi). |
| **Kanıt-eksiksizliği** | **%100** | Her Critical/High'da req+resp(+kontrol) ve `hasDeterministicEvidence()=true`. |

## Faz başına "bitti" tanımı (definition of done)

- **Faz 0** — Önceki 15-bulgulu koşu tekrarında **uydurma-kritik = 0**; düşük/orta bulgular sabit; FP bulgular Burp/panelde görünmez (DB'de durur).
- **Faz 1** — AI kapalıyken (fail-closed) hiçbir kanıtsız Critical/High Burp'a düşmez; agent `compare` olmadan `report_finding` çağıramaz.
- **Faz 2** — Juice Shop'ta login→tara→logout: araç ölü oturumla karar vermez; şifreli profille kendi re-login olur, olmazsa bildirir.
- **Faz 3** — Juice Shop'un bilinen BOLA'sı (numeric + UUID id) ground-truth ile, foreign-owner kanıtıyla, doğru-severity bulunur; recall ≥ %70 alt-kümede.
- **Faz 4** — Ambient salt-okunur (proxy history ile doğrula); "Derin Tara" agresif onayı sorar; rapor confidence-tier + kanıt-durumu + doğrulama-adımları içerir.

## Nasıl çalıştırılır (manuel, CI yok — kapsam dışı)

1. Test hedefini ayağa kaldır (ör. `docker run -p 3000:3000 bkimminich/juice-shop`).
2. Birkaç kullanıcı olarak gez (≥2 kimlik → gerçek BOLA için).
3. Burp scope'unu hedefe ayarla → "Hepsini Tara" / "Derin Tara".
4. Çıkan bulguları `ground-truth` listesine karşı işaretle; scorecard'ı doldur.
5. Sonucu bu dosyanın altındaki **Koşu Geçmişi** tablosuna bir satır olarak ekle.

> Not: Otomatik `BenchmarkRunner` (Burp'süz, fixture'a karşı recall/precision hesaplayan
> test modülü) henüz yazılmadı — şimdilik manuel scorecard. JDK ayrımı: jar=JDK8, testler=JDK12.

## Koşu Geçmişi

| Tarih | Hedef | Recall | Precision | Severity doğr. | Uydurma-kritik | Not |
|---|---|---|---|---|---|---|
| _(ilk koşu buraya)_ | | | | | | |

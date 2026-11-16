# Database Timestamp Hatası Düzeltme

## Hata
```
Error refreshing findings: [SQLITE_ERROR] SQL error or missing database (no such column: timestamp)
```

## Çözüm

Mevcut database'inizi güncellemek için Burp Suite'i **kapatıp** aşağıdaki komutu çalıştırın:

```bash
sqlite3 ~/.burp_ai_scanner.db "ALTER TABLE findings ADD COLUMN timestamp TIMESTAMP;"
sqlite3 ~/.burp_ai_scanner.db "UPDATE findings SET timestamp = created_at WHERE timestamp IS NULL;"
```

**VEYA**

Eski database'i silin (tüm veriler silinir):

```bash
rm ~/.burp_ai_scanner.db
```

Burp Suite'i tekrar başlattığınızda yeni database otomatik oluşturulacak.

## Yapılan İyileştirmeler

### 1. ✅ Fuzzing Tab - Test Sonuçlarını Göster
- Artık fuzzing testleri tablo formatında görünüyor
- Her payload için durum (İlginç/Normal) ve süre gösteriliyor
- İlginç sonuçlar otomatik olarak Bulgular tab'ına ekleniyor

### 2. ✅ Multi-Session Tab - Oturum ve Test Sonuçları
- Sol tarafta kayıtlı oturumlar listesi
- Sağ tarafta test sonuçları tablosu
- Test tipi, durum, severity ve açıklama gösteriliyor

### 3. ✅ Oturum Ekleme - UI'da Görünür
- Sağ tık → Oturum Ekle yaptığınızda
- Oturum Multi-Session tab'ında listeleniyor

### 4. ✅ Chat Memory - Çalışıyor
- AI artık konuşma geçmişini hatırlıyor
- "Temizle" butonu ile geçmişi sıfırlayabilirsiniz

## Test Etme

1. **Fuzzing Test**:
   - Proxy'den bir request seçin
   - Sağ tık → Yeni Özellikler → AI Fuzzing Başlat
   - Fuzzing tab'ına gidin ve test sonuçlarını görün

2. **Multi-Session Test**:
   - Admin olarak giriş yapın
   - Request'e sağ tık → Yeni Özellikler → Oturum Ekle → "Admin" yazın
   - User olarak giriş yapın
   - Request'e sağ tık → Yeni Özellikler → Oturum Ekle → "User" yazın
   - Multi-Session tab'ına gidin, oturumları görün
   - Test'e tıklayın ve sonuçları görün

3. **AI Chat**:
   - AI Asistan tab'ına gidin
   - "SQL Injection için hangi payloadları kullanmalıyım?" diye sorun
   - Sonra "Daha tehlikeli olanları söyler misin?" diye sorun
   - AI önceki sorunuzu hatırlayacak

## JAR Dosyası
`build/libs/ai-security-scanner-1.0.0.jar`

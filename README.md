# Siber Güvenlik Log Analizi ve Anomali Tespiti

Bu proje, bir sunucuya (server) ait erişim loglarını (access logs) analiz ederek siber tehditleri ve anormal IP hareketlerini tespit etmeyi amaçlayan, akademik kurallara uygun olarak tasarlanmış modüler bir veri analizi sistemidir.

Proje geliştirilirken **SoC (Separation of Concerns)**, **DRY (Don't Repeat Yourself)** ve **G-İ-K-Ç (Girdi-İşlem-Kontrol-Çıktı)** prensipleri katı bir şekilde uygulanmıştır.

## 🚀 Projenin Amacı ve Çözdüğü Sorun

Siber güvenlik uzmanlarının binlerce satırlık log dosyaları içerisinde kötü niyetli hareketleri (Hacker, Brute-Force, DDoS) gözle tespit etmesi imkânsızdır. 

Bu sistem:
1. İhtiyaç duyulan sentetik sunucu loglarını kendi başına üretir.
2. **Pandas ve Numpy** kullanarak büyük veri setlerini saniyeler içerisinde filtreler ve toplulaştırır (groupby).
3. IP adresleri bazında bir **"Tehdit Skoru"** hesaplayarak şüpheli aktörleri anında tespit edip raporlar.

## 🛠️ Teknolojiler
- **Python 3.x**
- **Pandas:** Veri çerçevelerinin (Dataframe) okunması, filtrelenmesi ve gruplanması.
- **Numpy:** Mantıksal veri filtreleme işlemleri (`np.where`).
- **Datetime / Random:** Gerçekçi sentetik veri (log) üretimi.

## 📂 Proje Yapısı ve Modülerlik (SoC)

Sistem, "Tek Sorumluluk Prensibi" (Single Responsibility) gereği modüllere ayrılmıştır:

* **`data_generator.py`**: Sistemin **Veri Erişim ve Üretim Katmanıdır**. Eğer ortamda log dosyası yoksa, gerçekçi zaman damgaları (timestamp), IP adresleri ve HTTP durum kodları üreterek `server_log.csv` dosyasını oluşturur.
* **`main.py`**: Sistemin **Analiz Motorudur**. Veriyi okur, Pandas ile işler, tehdit skorlaması yapar ve sonucu raporlar.
* **`server_log.csv`**: Modül tarafından üretilen ve analiz edilen veritabanı / log dosyası.

## ⚙️ Akademik Kurallar ve Uygulanışı

Projede aşağıdaki yazılım mimarisi prensipleri başarıyla uygulanmıştır:

1. **Modüler SoC:** Veri üretimi ve analiz işlemleri ayrı dosyalara taşınmış ve `import` mantığıyla entegre edilmiştir.
2. **G-İ-K-Ç Modeli:** `main.py` içerisindeki `anomali_tespit_et()` fonksiyonu sırasıyla:
   - **Girdi:** CSV dosyasını okuma (Hata yönetimi ile)
   - **İşlem:** `np.where` ve `groupby` ile verileri işleme ve matematiksel skorlama
   - **Kontrol:** Tehdit skoru > 35 olanları tespit etme
   - **Çıktı:** Konsol üzerinden rapor sunma aşamalarını takip eder.
3. **Hata Yönetimi (Exception Handling):** `try/except` kullanılarak dosya bulunamama (FileNotFoundError) durumlarında kodun çökmesi engellenmiş ve otomatik simülasyon başlatma yeteneği eklenmiştir.
4. **DRY (Kendini Tekrar Etme):** 1000 satırlık log verisi tek tek elle yazılmak yerine, döngüler ve rastgele seçim (random.choices ağırlıklandırma) mantığıyla dinamik olarak üretilmiştir.

## 🏃‍♂️ Kurulum ve Çalıştırma

**Gereksinimler:** Pandas ve Numpy kütüphanelerinin kurulu olması gerekmektedir.
```bash
pip install pandas numpy
```

**Çalıştırma:**
Projeyi başlatmak için terminalden ana dosyayı çalıştırmanız yeterlidir:
```bash
python main.py
```

*Not: Sistem çalıştırıldığında `server_log.csv` dosyası yoksa, `data_generator.py` otomatik olarak devreye girip veriyi üretecek ve ardından analize geçecektir.*

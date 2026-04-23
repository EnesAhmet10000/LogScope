# ============================================================
# SİBER GÜVENLİK LOG ANALİZİ VE ANOMALİ TESPİTİ (MODÜLER)
# ============================================================
# Bu proje, teorik ve pratik kurallara bağlı olarak yazılmıştır.
#
# UYGULANAN KURALLAR:
# 1. Modüler SoC: Veri simülasyonu "data_generator.py" dosyasına taşındı.
#    "import" kullanılarak Tek Görev ve Klasörleme kuralı işlendi.
# 2. G-İ-K-Ç (Girdi-İşlem-Kontrol-Çıktı): Analiz fonksiyonu bu sırayı izler.
# 3. Hata Yönetimi: try/except (FileNotFoundError)
# ============================================================

import pandas as pd
import numpy as np
import os
import datetime

# data_generator.py içerisinden veri üretim modülünü içeri aktarma
from data_generator import guvenlik_logu_olustur

# Görselleştirme modülünü içeri aktarma (SoC)
from visualize import log_gorsellestir

LOG_FILE = "server_log.csv"

def anomali_tespit_et():
    """
    G-İ-K-Ç (Girdi-İşlem-Kontrol-Çıktı) Prensibine Göre Tasarlanmış Ana Motor
    """
    # ------------------ G: GİRDİ (Input) ve HATA YÖNETİMİ ------------------
    # Senaryo 1: Geçmiş logları okumak esastır. Dosya silme (os.remove) mantığı KALDIRILDI.
    
    try:
        # FileNotFoundError yakalama kuralı (Önce mevcut dosyayı okumayı dener)
        df = pd.read_csv(LOG_FILE)
        print("[BİLGİ] Mevcut log dosyası başarıyla okundu ve analize başlanıyor...")
    except FileNotFoundError:
        # Sadece dosya gerçekten yoksa burası çalışır ve yenisini üretir
        print("HATA: Log dosyası bulunamadı, V1 (Minimum Viable Product) için simülasyon başlatılıyor...")
        guvenlik_logu_olustur(LOG_FILE) # Harici Data Generator Modülü çalışır
        df = pd.read_csv(LOG_FILE)
        
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    
    print("\n======== SİBER TEHDİT & LOG ANALİZ RAPORU =========")
    print(f"Toplam incelenen sunucu isteği : {len(df)}")
    
    # ------------------ İ: İŞLEM (Process) ------------------
    # İş Kuralları np.where ile karar mekanizması
    df['Risk_Durumu'] = np.where(df['Status_Code'].isin([401, 403, 404, 500]), 1, 0)
    
    # Pandas GroupBy - Logları sıkıştırma ve toplulaştırma işlemi
    ip_stats = df.groupby("IP_Address").agg(
        Toplam_Istek=("Status_Code", "count"),
        Riskli_Istek=("Risk_Durumu", "sum")
    ).reset_index()
    
    ip_stats["Tehdit_Skoru"] = (ip_stats["Riskli_Istek"] / ip_stats["Toplam_Istek"]) * 100
    
    # Zaman Bazlı Hız Analizi (Brute Force / DDoS Tespiti)
    # Timestamp index yapılır ve 5 dakikalık pencerelerde IP bazlı gruplama yapılır.
    df_time = df.set_index("Timestamp")
    brute_force_stats = df_time.groupby([pd.Grouper(freq='5min'), 'IP_Address']).agg(
        Pencere_Risk_Sayisi=("Risk_Durumu", "sum"),
        Pencere_Toplam_Istek=("Status_Code", "count")
    ).reset_index()
    
    # ------------------ K: KONTROL (Control) ------------------
    # 1. Oransal Şüpheliler (Eski Mantık)
    supheliler = ip_stats[(ip_stats["Tehdit_Skoru"] > 35) & (ip_stats["Riskli_Istek"] >= 5)]
    
    # 2. Brute Force / DDoS Şüphelileri (Yeni Mantık)
    # 5 dakika içinde 10'dan fazla riskli istek varsa Brute Force olarak işaretle
    brute_force_supheliler = brute_force_stats[brute_force_stats["Pencere_Risk_Sayisi"] >= 10]
    
    # ------------------ Ç: ÇIKTI (Output) ve DOSYALAMA (File I/O) ------------------
    zaman_damgasi = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    rapor_dosyasi = f"tehdit_raporu_{zaman_damgasi}.txt"
    
    with open(rapor_dosyasi, "w", encoding="utf-8") as f:
        # Hem konsola yazdıran hem de dosyaya kaydeden yardımcı fonksiyon
        def log_ve_yaz(mesaj):
            print(mesaj)
            f.write(mesaj + "\n")
            
        log_ve_yaz("\n--- [!] TESPİT EDİLEN ŞÜPHELİ IP ADRESLERİ (Oransal) ---")
        if supheliler.empty:
            log_ve_yaz("Sistem güvende. Anormal bir aktivite tespit edilmedi.")
        else:
            for idx, row in supheliler.sort_values(by="Tehdit_Skoru", ascending=False).iterrows():
                log_ve_yaz(f"Uyarı! IP: {row['IP_Address']:15} | Toplam Ziyaret: {row['Toplam_Istek']:<4} | Maskelenmiş İhlaller: {row['Riskli_Istek']:<3} | Tehdit Olasılığı: %{row['Tehdit_Skoru']:.1f}")

        log_ve_yaz("\n--- [🚀] ZAMAN BAZLI ANALİZ: BRUTE FORCE TESPİTİ ---")
        if brute_force_supheliler.empty:
            log_ve_yaz("Sistem güvende. Zaman bazlı kaba kuvvet veya DDoS saldırısı saptanmadı.")
        else:
            for idx, row in brute_force_supheliler.sort_values(by="Pencere_Risk_Sayisi", ascending=False).iterrows():
                zaman = row['Timestamp'].strftime('%H:%M:%S')
                log_ve_yaz(f"KRİTİK UYARI! Saat {zaman} civarında {row['IP_Address']:15} IP'si 5 dk içinde {row['Pencere_Risk_Sayisi']:<3} riskli istek yaptı. (Olası Brute Force!)")
                
        log_ve_yaz("\n--- EN ÇOK SALDIRI ALAN ENDPOINTLER (İlk 3) ---")
        log_ve_yaz(df[df['Risk_Durumu'] == 1]["Endpoint"].value_counts().head(3).to_string())
        
        log_ve_yaz("\n====================================================")
        log_ve_yaz(" 🎯 SİSTEMİN VERDİĞİ AKIL VE ÇÖZDÜĞÜ GERÇEK SORUN")
        log_ve_yaz("====================================================")
        log_ve_yaz("1. Gerçek Hayat Sorunu:")
        log_ve_yaz("   Siber güvenlik uzmanının on binlerce satır içerisinde hacker'ı gözlemlemesi imkansızdır.")
        log_ve_yaz("2. Programın Getirdiği Modüler Zeka:")
        log_ve_yaz("   Veriler 'data_generator.py' modülünde bağımsız olarak üretilir (SoC).")
        log_ve_yaz("   Pandas zaman serisi (.resample/Grouper) ve gruplama (GroupBy) ile saniyeler içinde analiz edilir.")
        log_ve_yaz("   Sonuçlar 'visualize.py' modülü üzerinden Matplotlib ve Seaborn ile görselleştirilir.")
        log_ve_yaz("   G-İ-K-Ç yapısına uygun olarak rapor otomatik kaydedilir (File I/O).")
        log_ve_yaz("3. Kullanıcıya Verdiği Akıl (Tavsiye):")
        if not supheliler.empty or not brute_force_supheliler.empty:
            en_tehlikeli = supheliler.sort_values(by="Tehdit_Skoru", ascending=False).iloc[0]['IP_Address'] if not supheliler.empty else brute_force_supheliler.iloc[0]['IP_Address']
            log_ve_yaz(f"   Sistem, log kalabalığı arasında 'Dikkat, {en_tehlikeli} numaralı IP bir saldırgandır!' aklını verir.")
            log_ve_yaz(f"   Tavsiye: Bu IP adres(ler)i acilen Firewall'dan Kara Liste'ye (Ban) alınmalıdır.")
        else:
             log_ve_yaz("   Sistem bir tehdit bulamadığı için operasyonel rahattır.")
        log_ve_yaz("====================================================\n")
        
    print(f"\n[BİLGİ] Yukarıdaki analiz raporu '{rapor_dosyasi}' dosyasına kalıcı olarak kaydedildi.")
    
    # Tüm analiz bittikten sonra rapor grafiklerini ekrana çizdir (Çıktı aşaması)
    log_gorsellestir(df, ip_stats)

if __name__ == "__main__":
    print("\n>>> BPU Dersi Kuralları (Multi-File SoC, DRY, G-İ-K-Ç) Aktif Edildi... <<<\n")
    anomali_tespit_et()
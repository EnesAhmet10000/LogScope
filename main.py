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

# data_generator.py içerisinden veri üretim modülünü içeri aktarma
from data_generator import guvenlik_logu_olustur

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
    
    # ------------------ K: KONTROL (Control) ------------------
    supheliler = ip_stats[(ip_stats["Tehdit_Skoru"] > 35) & (ip_stats["Riskli_Istek"] >= 5)]
    
    # ------------------ Ç: ÇIKTI (Output) ------------------
    print("\n--- [!] TESPİT EDİLEN ŞÜPHELİ IP ADRESLERİ ---")
    if supheliler.empty:
        print("Sistem güvende. Anormal bir aktivite tespit edilmedi.")
    else:
        for idx, row in supheliler.sort_values(by="Tehdit_Skoru", ascending=False).iterrows():
            print(f"Uyarı! IP: {row['IP_Address']:15} | Toplam Ziyaret: {row['Toplam_Istek']:<4} | Maskelenmiş İhlaller: {row['Riskli_Istek']:<3} | Tehdit Olasılığı: %{row['Tehdit_Skoru']:.1f}")
            
    print("\n--- EN ÇOK SALDIRI ALAN ENDPOINTLER (İlk 3) ---")
    print(df[df['Risk_Durumu'] == 1]["Endpoint"].value_counts().head(3).to_string())
    
    print("\n====================================================")
    print(" 🎯 SİSTEMİN VERDİĞİ AKIL VE ÇÖZDÜĞÜ GERÇEK SORUN")
    print("====================================================")
    print("1. Gerçek Hayat Sorunu:")
    print("   Siber güvenlik uzmanının on binlerce satır içerisinde hacker'ı gözlemlemesi imkansızdır.")
    print("2. Programın Getirdiği Modüler Zeka:")
    print("   Veriler 'data_generator.py' modülünde bağımsız olarak üretilir (SoC).")
    print("   Pandas (GroupBy) altyapısı bu verileri saniyeler içinde özetleyip skorlar.")
    print("3. Kullanıcıya Verdiği Akıl (Tavsiye):")
    if not supheliler.empty:
        en_tehlikeli = supheliler.sort_values(by="Tehdit_Skoru", ascending=False).iloc[0]['IP_Address']
        print(f"   Sistem, log kalabalığı arasında 'Dikkat, {en_tehlikeli} numaralı IP bir saldırgandır!' aklını verir.")
        print(f"   Tavsiye: Bu IP adres(ler)i acilen Firewall'dan Kara Liste'ye (Ban) alınmalıdır.")
    else:
         print("   Sistem bir tehdit bulamadığı için operasyonel rahattır.")
    print("====================================================\n")

if __name__ == "__main__":
    print("\n>>> BPU Dersi Kuralları (Multi-File SoC, DRY, G-İ-K-Ç) Aktif Edildi... <<<\n")
    anomali_tespit_et()
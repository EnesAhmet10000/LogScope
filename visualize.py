import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

def log_gorsellestir(df, ip_stats):
    """
    SoC (Separation of Concerns) Prensibine Uygun Görselleştirme Modülü
    Sistemdeki verileri analiz edip akademik ve profesyonel grafiklere dönüştürür.
    """
    print("\n[BİLGİ] Görselleştirme modülü (visualize.py) başlatıldı. Grafikler hazırlanıyor...")
    
    # Seaborn tema ayarları
    sns.set_theme(style="whitegrid")
    
    # 1 satırda 3 grafik gösterecek bir figür oluşturalım
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    fig.suptitle('Siber Tehdit ve Anomali Analiz Raporu', fontsize=16, fontweight='bold')
    
    # --- 1. Grafik: Zaman Çizelgesinde İstek Yoğunluğu (Line Chart) ---
    # 5 dakikalık periyotlarla toplam istek sayısını hesapla
    df_time = df.set_index("Timestamp")
    zaman_serisi = df_time.resample('5min').size()
    
    axes[0].plot(zaman_serisi.index, zaman_serisi.values, color='firebrick', marker='o', linestyle='-')
    axes[0].set_title("Zaman Bazlı İstek Yoğunluğu (5 Dk Periyot)")
    axes[0].set_xlabel("Zaman")
    axes[0].set_ylabel("İstek Sayısı")
    axes[0].tick_params(axis='x', rotation=45)
    
    # --- 2. Grafik: En Çok Saldırı Alan Endpoint'ler (Pie Chart) ---
    # Sadece riskli istekleri (Risk_Durumu == 1) filtreleyelim
    riskli_df = df[df['Risk_Durumu'] == 1]
    endpoint_sayilari = riskli_df['Endpoint'].value_counts().head(5)
    
    if not endpoint_sayilari.empty:
        axes[1].pie(endpoint_sayilari, labels=endpoint_sayilari.index, autopct='%1.1f%%', startangle=90, colors=sns.color_palette("Reds_r", len(endpoint_sayilari)))
        axes[1].set_title("Riskli İstek Dağılımı (Top 5 Endpoint)")
    else:
        axes[1].text(0.5, 0.5, "Riskli İstek Yok", ha='center', va='center')
        axes[1].set_title("Riskli İstek Dağılımı")
        
    # --- 3. Grafik: Tehdit Skoruna Göre İlk 10 IP (Bar Chart) ---
    top_10_ip = ip_stats.sort_values(by="Tehdit_Skoru", ascending=False).head(10)
    
    sns.barplot(ax=axes[2], x="Tehdit_Skoru", y="IP_Address", data=top_10_ip, palette="Reds_r", hue="IP_Address", legend=False)
    axes[2].set_title("En Yüksek Tehdit Skoruna Sahip İlk 10 IP")
    axes[2].set_xlabel("Tehdit Olasılığı (%)")
    axes[2].set_ylabel("IP Adresi")
    
    # Tasarım düzenlemesi
    plt.tight_layout()
    plt.subplots_adjust(top=0.9) # Ana başlık için biraz boşluk bırak
    
    # Grafiklerin PNG olarak kaydedilmesi
    rapor_ismi = 'tehdit_analiz_grafikleri.png'
    plt.savefig(rapor_ismi, dpi=300)
    print(f"[BİLGİ] İşlem tamam! Grafikler '{rapor_ismi}' dosyasına yüksek çözünürlüklü olarak kaydedildi.")
    
    # Ekranda Göster (Hocaya sunum yaparken çok işe yarar)
    plt.show()

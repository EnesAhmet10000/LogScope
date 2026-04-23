import pandas as pd
import datetime
import random

def guvenlik_logu_olustur(dosya_adi="server_log.csv"):
    """ 
    Modüler Yapı: Sadece veri üretiminden sorumlu Python Modülü (Data Access Layer).
    DRY Kuralı: 1000 satırı tekrarlamak yerine döngü kullanıldı.
    """
    print(f"Modül: {dosya_adi} için gerçekçi siber güvenlik verileri sentezleniyor...")
    ip_listesi = [f"192.168.1.{random.randint(10, 50)}" for _ in range(15)] + ["10.0.0.99"] * 5 
    durum_kodlari = [200, 201, 400, 401, 403, 404, 500]
    
    veri = []
    baslangic = datetime.datetime.now()
    
    for i in range(1000):
        # Gerçekçi ve yoğun bir saldırı testi için tüm olayları son 1 saate (60 dk) sıkıştırdık
        zaman = baslangic - datetime.timedelta(minutes=random.randint(1, 60))
        ip = random.choice(ip_listesi)
        
        if ip == "10.0.0.99":
            kod = random.choice([401, 403, 404, 500])
        else:
            kod = random.choices(durum_kodlari, weights=[75, 10, 5, 2, 2, 5, 1], k=1)[0]
            
        veri.append({
            "Timestamp": zaman.strftime("%Y-%m-%d %H:%M:%S"),
            "IP_Address": ip,
            "Endpoint": random.choice(["/login", "/api/v1/data", "/home", "/admin/dashboard", "/wp-admin"]),
            "Status_Code": kod
        })
        
    df_log = pd.DataFrame(veri)
    df_log = df_log.sort_values(by="Timestamp")
    df_log.to_csv(dosya_adi, index=False) # CSV Dosyası diske yazılır
    print(f"[{dosya_adi}] başarıyla oluşturuldu.\n")

if __name__ == "__main__":
    # Eğer bu dosya tek başına çalıştırılırsa, fonksiyonu çağır.
    guvenlik_logu_olustur()

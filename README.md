# SurfaceWatch

[![CI](https://github.com/gorkem-pre/surfacewatch/actions/workflows/ci.yml/badge.svg)](https://github.com/gorkem-pre/surfacewatch/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

SurfaceWatch, kendi sistemlerinin saldırı yüzeyini iki açıdan inceleyen bir araçtır:

- **Red (`scan`):** Saldırgan gözüyle keşif. Açık portlar, servis sürümleri, subdomain'ler, web yapılandırma hataları ve bilinen CVE'ler. Her bulgu MITRE ATT&CK tekniğiyle eşlenir.
- **Blue (`watch`):** Savunmacı gözüyle izleme. Taramalar arasındaki farkı çıkarır (yeni açılan port, değişen sürüm, yaklaşan sertifika bitişi) ve her bulgu için düzeltme önerir.

> ⚠️ Araç **yalnızca `scope.yml` içinde tanımlı hedefleri** tarar. Sadece sahibi olduğun ya da yazılı izin aldığın sistemlerde kullan.

## Durum

| Modül | Durum |
|---|---|
| 1. Çekirdek: kapsam kontrolü, SQLite kayıt, CLI | ✅ |
| 2. Ağ: Nmap entegrasyonu, servis/sürüm tespiti, MITRE + düzeltme bilgi tabanı | ✅ |
| 3. Pasif OSINT: Certificate Transparency, DNS | ⏳ |
| 4. Web: güvenlik header'ları, TLS, açık hassas dosyalar | ⏳ |
| 5. Zafiyet: sürüm → CVE (NVD) | ⏳ |
| 6. Diff motoru + HTML/JSON rapor | ⏳ |

## Kurulum

```bash
git clone https://github.com/gorkem-pre/surfacewatch.git
cd surfacewatch
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Kullanım

Aşağıdaki örnekler [scanme.nmap.org](http://scanme.nmap.org/) üzerinde yapılmıştır. Nmap ekibi bu sunucuyu hafif taramalar için herkese açmıştır.

**1. Kapsamı tanımla**

```bash
surfacewatch init          # scope.yml şablonu oluşturur
```

```yaml
# scope.yml
name: home-lab
targets:
  hosts:
    - 45.33.32.156                    # scanme.nmap.org IPv4
    - 2600:3c01::f03c:91ff:fe18:bb2f  # scanme.nmap.org IPv6
  domains:
    - name: scanme.nmap.org
      include_subdomains: false
options:
  max_rate: 100
```

**2. Kapsamı doğrula**

```bash
surfacewatch scope check scanme.nmap.org 45.33.32.156 8.8.8.8
```

```
İZİN  scanme.nmap.org      domain ve çözümlenen IP'ler kapsamda  [2600:3c01::f03c:91ff:fe18:bb2f, 45.33.32.156]
İZİN  45.33.32.156         IP kapsamda
RED   8.8.8.8              IP hiçbir kapsam ağında değil
```

**3. Tara**

```bash
surfacewatch scan scanme.nmap.org -v
```

```
[i] IPv6 atlandı 2600:3c01::f03c:91ff:fe18:bb2f (dahil etmek için --ipv6)
[*] Taranıyor: scanme.nmap.org (45.33.32.156)  profil=default  max_rate=100
    $ nmap -sT -sV --version-light -T3 --max-rate 100 -n -oX - -Pn --top-ports 1000 45.33.32.156
    45.33.32.156: up, 3 açık, 997 filtreli, 0 kapalı, RTT 194.9 ms

ÖNEM      HEDEF              PORT       SERVİS         SÜRÜM
LOW       45.33.32.156       tcp/9929   nping-echo     Nping echo
          MITRE  : T1046
          düzelt : Bu servis gerçekten gerekli mi? Gerekli değilse kapat; ...
INFO      45.33.32.156       tcp/22     ssh            OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
          risk   : Uzaktan yönetim kapısı; brute force'un ilk hedefi.
          MITRE  : T1021.004, T1046, T1110
          düzelt : Parola ile girişi kapat (PasswordAuthentication no), sadece anahtar kullan; ...
INFO      45.33.32.156       tcp/80     http           Apache httpd 2.4.7
          MITRE  : T1046, T1190, T1595.002
          düzelt : HTTPS'e yönlendir (301 + HSTS); sürüm bilgisini gizle ...

3 bulgu  low: 1  info: 2
```

**4. Geçmiş**

```bash
surfacewatch show          # son taramanın bulguları
surfacewatch show 1 -v     # belirli bir tarama
surfacewatch scans         # tarama geçmişi
```

**Diğer seçenekler**

```bash
surfacewatch scan 192.168.56.0/28 --profile quick     # kendi lab ağın (top 100 port)
surfacewatch scan 192.168.56.10 -p 22,80,443          # belirli portlar
surfacewatch scan scanme.nmap.org --ipv6              # IPv6 adreslerini de tara
```

> `scanme.nmap.org` üzerinde `--profile full` kullanma; tüm 65.535 portu tarar ve paylaşılan bir sunucuyu yorar.

## Kapsam güvenliği

Kapsam kontrolü aracın en kritik parçasıdır ve tüm aktif modüller ondan geçer:

1. **`exclude` her şeyi ezer.** Hariç tutulan bir IP'yi kapsayan ağ taraması da reddedilir.
2. **Domain sahipliği, IP sahipliği demek değildir.** `cdn.ornek.com` senin domain'in olabilir ama Cloudflare'e çözülüyorsa o sunucuyu taramak Cloudflare'i taramaktır. Aktif taramada çözümlenen tüm IP'ler de kapsamda olmalı; tek bir IP bile dışarıdaysa hedef reddedilir:
   ```
   RED   cdn.ornek.com   domain kapsamda ama çözümlenen IP kapsam dışı: 104.16.1.1 (üçüncü taraf sunucu olabilir)
   ```
3. **Sonek hilelerine karşı:** `evil-lab.local` ve `lab.local.evil.com`, `lab.local` kapsamına girmez.
4. **Aşırı geniş kapsam reddedilir:** /16'dan büyük ağlar kabul edilmez.
5. **Pasif / aktif ayrımı:** CT log ve DNS sorgusu gibi hedefe paket göndermeyen işlemler sadece domain kuralına bakar.
6. **IP sabitleme (TOCTOU koruması):** Domain taranırken Nmap'e hostname değil, kapsam kontrolünde çözümlenen IP verilir. Kontrol ile tarama arasında DNS kaydı değişse bile (DNS rebinding) kontrol edilen adres taranan adrestir.
7. **Enjeksiyon yok:** Nmap `shell=True` olmadan liste argümanlarla çağrılır; hedef `ipaddress` ile, port listesi regex'siz sayısal kontrolle doğrulanır.
8. **Yanlış negatife karşı uyarı:** Her host için açık/filtreli/kapalı port sayısı ve RTT gösterilir. Hiç açık port yoksa ya da RTT uzak bir host için gerçekçi değilse (ör. VirtualBox NAT'ın kendi verdiği 0.2 ms'lik cevap), araç sonucun yanıltıcı olabileceğini söyler. Tek IP hedeflerde varsayılan olarak `-Pn` kullanılır.
9. **Hız sınırı:** `options.max_rate` (varsayılan 100 paket/sn) her taramaya uygulanır. NSE script'leri çalıştırılmaz.

## Mimari

```
surfacewatch/
├── core/
│   ├── scope.py     kapsam yükleme, doğrulama ve karar (Decision + gerekçe)
│   ├── models.py    Finding: tüm modüllerin ortak bulgu formatı (MITRE + remediation)
│   └── storage.py   SQLite: scans / findings, diff için son iki tarama
├── modules/
│   ├── network.py   nmap komutu, XML parse, Finding üretimi
│   └── knowledge.py servis → önem, MITRE, düzeltme bilgi tabanı
└── cli.py
```

Her `Finding` için `(target, module, key)` kimliği ve `data` hash'i (fingerprint) tutulur. Diff motoru bu ikisiyle bulguları "yeni", "kapandı" ya da "değişti" olarak sınıflandırır.

## Test

```bash
pytest -q
ruff check .
```

## Geliştirme notu

Bu proje AI asistanı (Claude) desteğiyle geliştirildi; tasarım kararları, test ve doğrulama tarafımdan yapıldı.

## Lisans

MIT

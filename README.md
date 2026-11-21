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
| 2. Ağ: Nmap entegrasyonu, servis/sürüm tespiti | ⏳ |
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

```bash
surfacewatch init                                  # scope.yml şablonu
surfacewatch scope show
surfacewatch scope check 192.168.56.10 8.8.8.8 cdn.lab.local
```

```
İZİN  192.168.56.10                       IP kapsamda
RED   8.8.8.8                             IP hiçbir kapsam ağında değil
RED   cdn.lab.local                       domain kapsamda ama çözümlenen IP kapsam dışı: 104.16.1.1 (üçüncü taraf sunucu olabilir)
```

## Kapsam güvenliği

Kapsam kontrolü aracın en kritik parçasıdır ve tüm aktif modüller ondan geçer:

1. **`exclude` her şeyi ezer.** Hariç tutulan bir IP'yi kapsayan ağ taraması da reddedilir.
2. **Domain sahipliği, IP sahipliği demek değildir.** `cdn.ornek.com` senin domain'in olabilir ama Cloudflare'e çözülüyorsa o sunucuyu taramak Cloudflare'i taramaktır. Aktif taramada çözümlenen tüm IP'ler de kapsamda olmalı; tek bir IP bile dışarıdaysa hedef reddedilir.
3. **Sonek hilelerine karşı:** `evil-lab.local` ve `lab.local.evil.com`, `lab.local` kapsamına girmez.
4. **Aşırı geniş kapsam reddedilir:** /16'dan büyük ağlar kabul edilmez.
5. **Pasif / aktif ayrımı:** CT log ve DNS sorgusu gibi hedefe paket göndermeyen işlemler sadece domain kuralına bakar.

## Mimari

```
surfacewatch/
├── core/
│   ├── scope.py     kapsam yükleme, doğrulama ve karar (Decision + gerekçe)
│   ├── models.py    Finding: tüm modüllerin ortak bulgu formatı (MITRE + remediation)
│   └── storage.py   SQLite: scans / findings, diff için son iki tarama
├── modules/         network, osint, web, vuln (sırayla eklenecek)
└── cli.py
```

Her `Finding` için `(target, module, key)` kimliği ve `data` hash'i (fingerprint) tutulur. Diff motoru bu ikisiyle bulguları "yeni", "kapandı" ya da "değişti" olarak sınıflandırır.

## Test

```bash
pytest -q
ruff check .
```

## Lisans

MIT
## Geliştirme notu
Bu proje AI asistanı (Claude) desteğiyle geliştirildi; tasarım kararları,
test ve doğrulama tarafımdan yapıldı.

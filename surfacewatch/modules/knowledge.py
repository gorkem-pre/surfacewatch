"""Servis bilgi tabanı: açık bir servisin red ve blue yorumu.

Her açık port için:
  * severity     : servisin internete/ağa açık olmasının risk seviyesi
  * mitre        : saldırganın bu servisle neler yapabileceği (red)
  * remediation  : nasıl sıkılaştırılır (blue)

Tüm açık portlar T1046 (Network Service Discovery) ile de eşlenir, çünkü
saldırgan da aynı taramayı yaparak bu bilgiye ulaşır.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ServiceInfo:
    severity: str
    mitre: list[str] = field(default_factory=list)
    remediation: str = ""
    note: str = ""


DEFAULT = ServiceInfo(
    severity="low",
    mitre=[],
    remediation="Bu servis gerçekten gerekli mi? Gerekli değilse kapat; gerekliyse "
                "sadece ihtiyaç duyan IP'lere firewall ile aç.",
)

# Anahtar: nmap servis adı (service@name)
SERVICES: dict[str, ServiceInfo] = {
    "ssh": ServiceInfo(
        "info", ["T1021.004", "T1110"],
        "Parola ile girişi kapat (PasswordAuthentication no), sadece anahtar kullan; "
        "root girişini kapat (PermitRootLogin no); fail2ban ile brute force'u sınırla.",
        "Uzaktan yönetim kapısı; brute force'un ilk hedefi.",
    ),
    "telnet": ServiceInfo(
        "high", ["T1021", "T1040", "T1110"],
        "Telnet'i tamamen kapat, yerine SSH kullan.",
        "Kimlik bilgileri dahil her şey açık metin gider; ağı dinleyen herkes görür.",
    ),
    "ftp": ServiceInfo(
        "medium", ["T1040", "T1110", "T1071.002"],
        "FTP yerine SFTP/FTPS kullan; anonim girişi kapat.",
        "Açık metin protokol; anonim giriş sık görülen bir yapılandırma hatası.",
    ),
    "http": ServiceInfo(
        "info", ["T1190", "T1595.002"],
        "HTTPS'e yönlendir (301 + HSTS); sürüm bilgisini gizle (ServerTokens Prod / server_tokens off).",
        "Web uygulaması saldırı yüzeyi; Modül 4 bu servisi ayrıntılı inceler.",
    ),
    "https": ServiceInfo(
        "info", ["T1190", "T1595.002"],
        "TLS 1.2+ zorunlu kıl, sürüm bilgisini gizle; Modül 4'teki web bulgularına bak.",
    ),
    "microsoft-ds": ServiceInfo(
        "medium", ["T1021.002", "T1210", "T1135"],
        "SMB'yi dış ağa asla açma; SMBv1'i kapat; SMB imzalamayı zorunlu kıl.",
        "EternalBlue gibi kritik açıkların geçmişi olan, yanal hareket için kullanılan servis.",
    ),
    "netbios-ssn": ServiceInfo(
        "medium", ["T1021.002", "T1135"],
        "NetBIOS'u gerekmiyorsa kapat; SMB ile aynı kısıtlamaları uygula.",
    ),
    "ms-wbt-server": ServiceInfo(
        "medium", ["T1021.001", "T1110"],
        "RDP'yi doğrudan açma; VPN arkasına al, NLA'yı zorunlu kıl, hesap kilitleme politikası uygula.",
        "Fidye yazılımı gruplarının en sık kullandığı giriş noktalarından biri.",
    ),
    "vnc": ServiceInfo(
        "high", ["T1021.005", "T1110"],
        "VNC'yi dış ağa açma; SSH tüneli üzerinden kullan, güçlü parola belirle.",
        "Çoğu kurulumda zayıf ya da hiç kimlik doğrulama yok.",
    ),
    "mysql": ServiceInfo(
        "high", ["T1190", "T1110", "T1005"],
        "Veritabanını sadece localhost'a bağla (bind-address=127.0.0.1); uygulama sunucusu dışından erişimi kapat.",
        "Veritabanı portunun ağa açık olması doğrudan veri sızıntısı riski.",
    ),
    "postgresql": ServiceInfo(
        "high", ["T1190", "T1110", "T1005"],
        "listen_addresses='localhost'; pg_hba.conf'ta sadece gerekli IP'lere izin ver.",
    ),
    "ms-sql-s": ServiceInfo(
        "high", ["T1190", "T1110", "T1005"],
        "MSSQL'i dış ağa açma; 'sa' hesabını kapat; Windows kimlik doğrulaması kullan.",
    ),
    "mongodb": ServiceInfo(
        "critical", ["T1190", "T1005", "T1485"],
        "Kimlik doğrulamayı aç (security.authorization: enabled), bindIp'yi 127.0.0.1 yap.",
        "Kimlik doğrulamasız MongoDB'ler toplu fidye saldırılarında silindi.",
    ),
    "redis": ServiceInfo(
        "critical", ["T1190", "T1005", "T1059"],
        "bind 127.0.0.1, protected-mode yes, requirepass ayarla; CONFIG komutunu yeniden adlandır.",
        "Kimlik doğrulamasız Redis uzaktan kod çalıştırmaya kadar gidebilir.",
    ),
    "elasticsearch": ServiceInfo(
        "critical", ["T1190", "T1005"],
        "xpack.security.enabled: true; 9200 portunu dış ağa kapat.",
    ),
    "smtp": ServiceInfo(
        "low", ["T1071.003"],
        "Open relay olmadığını doğrula; VRFY/EXPN komutlarını kapat; STARTTLS zorunlu kıl.",
    ),
    "domain": ServiceInfo(
        "low", ["T1590.002"],
        "Zone transfer'ı (AXFR) sadece yetkili ikincil sunuculara izin ver; açık recursive resolver olma.",
    ),
    "snmp": ServiceInfo(
        "high", ["T1602.001"],
        "SNMPv3 kullan; 'public'/'private' community string'lerini değiştir.",
    ),
    "tcpwrapped": ServiceInfo(
        "info", [],
        "Port açık ama bağlantı hemen kapatılıyor (TCP wrapper/firewall). Gerekli değilse kapat.",
    ),
}


def lookup(service: str) -> ServiceInfo:
    return SERVICES.get(service.lower(), DEFAULT)

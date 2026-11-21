"""Pasif OSINT modülü: hedefe tek paket göndermeden bilgi toplar.

1. Certificate Transparency (crt.sh): Domain için yayımlanmış tüm TLS
   sertifikalarındaki isimlerden subdomain listesi. Unutulmuş dev/test/old
   sunucuları genelde buradan çıkar.
2. Subdomain analizi: Her isim DNS'te çözülür (A/AAAA/CNAME).
   * Çözülmeyen eski kayıtlar        -> bilgi
   * dev/test/admin gibi isimler     -> düşük risk (internete açık iç ortam)
   * CNAME hedefi artık yok          -> "dangling CNAME"
   * ... ve hedef bulut servisiyse   -> subdomain takeover adayı (yüksek)
   * Her subdomain için aktif taramaya kapsam izni (scope.check) raporlanır.
3. E-posta güvenliği: SPF, DMARC kayıtları (domain sahteciliği / phishing).
4. DNS altyapısı: NS, MX, CAA. NS değişikliği domain ele geçirme işaretidir;
   blue modundaki diff bunu yakalar.

DNS sorguları recursive resolver üzerinden yapılır; hedef sunuculara (web,
ssh vb.) bağlantı açılmaz. Bu yüzden kapsam kontrolü "pasif" modda yapılır.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .. import __version__
from ..core.models import Finding
from ..core.scope import Decision
from .dnsclient import DnsClient, DnsError, DnsNXDomain

MODULE = "osint"

# ------------------------------------------------------------------ crt.sh
CRTSH_URL = "https://crt.sh/?q={q}&output=json"
Fetcher = Callable[[str], str]


class OsintError(RuntimeError):
    pass


def http_get(url: str, timeout: int = 30, retries: int = 3) -> str:
    """crt.sh sık sık 502/zaman aşımı verir; artan beklemeyle tekrar dener."""
    req = urllib.request.Request(url, headers={"User-Agent": f"surfacewatch/{__version__}"})
    last: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (sabit https)
                return resp.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError) as exc:
            last = exc
            time.sleep(2 * (attempt + 1))
    raise OsintError(f"crt.sh'e ulaşılamadı ({retries} deneme): {last}")


def parse_crtsh(text: str, domain: str) -> set[str]:
    """crt.sh JSON'undan domain'e ait benzersiz isimleri çıkarır."""
    try:
        rows = json.loads(text) if text.strip() else []
    except json.JSONDecodeError as exc:
        raise OsintError(f"crt.sh geçersiz JSON döndürdü: {exc}") from exc
    names: set[str] = set()
    for row in rows:
        for raw in str(row.get("name_value", "")).splitlines():
            n = raw.strip().lower().rstrip(".")
            if n.startswith("*."):
                n = n[2:]
            if (n == domain or n.endswith("." + domain)) and _valid_hostname(n):
                names.add(n)
    return names


_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def _valid_hostname(name: str) -> bool:
    # crt.sh e-posta adresleri ve bozuk girdiler de içerebilir
    return len(name) <= 253 and all(_LABEL_RE.match(p) for p in name.split("."))


def crtsh_subdomains(domain: str, fetch: Fetcher | None = None) -> set[str]:
    url = CRTSH_URL.format(q=urllib.parse.quote(f"%.{domain}"))
    return parse_crtsh((fetch or http_get)(url), domain)


# ------------------------------------------------------------------ subdomain analizi
INTERESTING_RE = re.compile(
    r"(^|[.-])(dev|develop|test|testing|staging|stage|stg|uat|qa|old|legacy|backup|bak|"
    r"admin|administrator|vpn|jenkins|ci|git|gitlab|internal|intranet|beta|demo|sandbox|"
    r"debug|phpmyadmin|grafana|kibana|prometheus|portainer|db|mysql|sql)\d*([.-]|$)"
)

# CNAME hedefi bu servislerdeyse ve hedef artık yoksa, saldırgan aynı ismi o
# serviste kaydederek subdomain'i ele geçirebilir.
TAKEOVER_SUFFIXES = (
    "github.io", "herokuapp.com", "herokudns.com", "s3.amazonaws.com", "s3-website",
    "cloudfront.net", "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
    "trafficmanager.net", "blob.core.windows.net", "azureedge.net", "netlify.app",
    "netlify.com", "vercel.app", "pages.dev", "surge.sh", "ghost.io", "myshopify.com",
    "readthedocs.io", "bitbucket.io", "wordpress.com", "pantheonsite.io", "fly.dev",
    "zendesk.com", "helpscoutdocs.com", "unbouncepages.com",
)


@dataclass
class SubdomainInfo:
    name: str
    ips: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    status: str = "ok"      # ok | nxdomain | no-address | dangling | error
    error: str = ""


def _resolve_chain(dns: DnsClient, name: str) -> SubdomainInfo:
    info = SubdomainInfo(name)
    try:
        info.cname = dns.query(name, "CNAME")
        target = info.cname[-1] if info.cname else name
        if info.cname:
            try:
                dns.query(target, "A")
            except DnsNXDomain:
                info.status = "dangling"
                return info
        info.ips = sorted(set(dns.query(name, "A") + dns.query(name, "AAAA")))
        if not info.ips:
            info.status = "no-address"
    except DnsNXDomain:
        info.status = "nxdomain"
    except DnsError as exc:
        info.status, info.error = "error", str(exc)
    return info


def resolve_all(dns: DnsClient, names: list[str], workers: int = 10) -> list[SubdomainInfo]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda n: _resolve_chain(dns, n), names))


def subdomain_finding(apex: str, info: SubdomainInfo, decision: Decision | None) -> Finding:
    data = {
        "name": info.name, "ips": info.ips, "cname": info.cname, "status": info.status,
        "active_scan": None if decision is None else decision.allowed,
        "scope_reason": "" if decision is None else decision.reason,
    }
    mitre = ["T1596.003"]  # Search Open Technical Databases: Digital Certificates
    label = info.name[: -len(apex)].rstrip(".") if info.name != apex else ""

    if info.status == "dangling":
        target = info.cname[-1]
        if any(s in target for s in TAKEOVER_SUFFIXES):
            return Finding(
                apex, MODULE, f"subdomain/{info.name}",
                f"Subdomain takeover adayı: {info.name} -> {target} (hedef yok)",
                "high", data, mitre + ["T1584.001"],
                f"{info.name} için CNAME kaydını sil ya da {target} kaynağını yeniden oluştur. "
                "Saldırgan bu ismi serviste kaydederse senin domain'inde içerik yayınlar "
                "(phishing, cookie çalma). Doğrulamak için tarayıcıda açıp servisin "
                "'not found' sayfasını kontrol et.",
            )
        return Finding(
            apex, MODULE, f"subdomain/{info.name}",
            f"Dangling CNAME: {info.name} -> {target} (hedef yok)",
            "medium", data, mitre + ["T1584.001"],
            "Kullanılmayan CNAME kaydını DNS'ten kaldır.",
        )

    if info.status in ("nxdomain", "no-address"):
        return Finding(apex, MODULE, f"subdomain/{info.name}",
                       f"{info.name} (sertifikada var, DNS'te çözülmüyor)", "info", data, mitre,
                       "Eski kayıt. Gerekirse sertifika envanterini temizle.")

    if info.status == "error":
        return Finding(apex, MODULE, f"subdomain/{info.name}",
                       f"{info.name} (DNS hatası: {info.error})", "info", data, mitre, "")

    if label and INTERESTING_RE.search(label):
        return Finding(
            apex, MODULE, f"subdomain/{info.name}",
            f"Hassas görünen subdomain internete açık: {info.name}", "low", data, mitre,
            "Geliştirme/yönetim ortamlarını internete açma; VPN ya da IP kısıtlaması arkasına al, "
            "kullanılmıyorsa kapat.",
        )
    return Finding(apex, MODULE, f"subdomain/{info.name}", info.name, "info", data, mitre, "")


# ------------------------------------------------------------------ e-posta / DNS kontrolleri
_ALL_RE = re.compile(r"(?:^|\s)([+\-~?]?)all(?:\s|$)", re.IGNORECASE)
SPOOF_MITRE = ["T1566", "T1656"]  # Phishing, Impersonation


def _safe(dns: DnsClient, name: str, rdtype: str) -> list[str] | None:
    try:
        return dns.query(name, rdtype)
    except DnsNXDomain:
        return []
    except DnsError:
        return None


def check_spf(domain: str, txt: list[str] | None, has_mx: bool) -> Finding:
    key, title_base = "email/spf", "SPF"
    if txt is None:
        return Finding(domain, MODULE, key, "SPF kontrol edilemedi (DNS hatası)", "info")
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    data = {"records": spf}
    if not spf:
        rem = ("SPF kaydı ekle: yetkili mail sunucularını listele, sonuna -all koy." if has_mx else
               "Bu domain mail göndermiyorsa 'v=spf1 -all' yayımla; böylece kimse senin adına "
               "mail gönderemez.")
        return Finding(domain, MODULE, key, "SPF kaydı yok: domain adına sahte e-posta gönderilebilir",
                       "medium", data, SPOOF_MITRE, rem)
    if len(spf) > 1:
        return Finding(domain, MODULE, key, f"Birden fazla SPF kaydı ({len(spf)}): SPF geçersiz (permerror)",
                       "medium", data, SPOOF_MITRE, "SPF kayıtlarını tek bir TXT kaydında birleştir.")
    m = _ALL_RE.search(spf[0])
    qualifier = m.group(1) if m else None
    data["all"] = None if m is None else (qualifier or "+") + "all"
    if m is None:
        return Finding(domain, MODULE, key, f"{title_base}: 'all' mekanizması yok (varsayılan neutral)",
                       "medium", data, SPOOF_MITRE, "Kaydın sonuna -all (ya da en az ~all) ekle.")
    if qualifier in ("", "+"):
        return Finding(domain, MODULE, key, f"{title_base}: +all, herkes bu domain adına mail gönderebilir",
                       "high", data, SPOOF_MITRE, "+all'u -all olarak değiştir.")
    if qualifier == "?":
        return Finding(domain, MODULE, key, f"{title_base}: ?all (neutral), sahteciliği engellemez",
                       "medium", data, SPOOF_MITRE, "?all yerine -all kullan.")
    if qualifier == "~":
        return Finding(domain, MODULE, key, f"{title_base}: ~all (softfail)", "low", data, SPOOF_MITRE,
                       "DMARC p=reject ile birlikte kabul edilebilir; mümkünse -all'a geç.")
    return Finding(domain, MODULE, key, f"{title_base}: -all (doğru yapılandırılmış)", "info", data)


def _dmarc_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_dmarc(domain: str, txt: list[str] | None) -> Finding:
    key = "email/dmarc"
    if txt is None:
        return Finding(domain, MODULE, key, "DMARC kontrol edilemedi (DNS hatası)", "info")
    recs = [t for t in txt if t.lower().replace(" ", "").startswith("v=dmarc1")]
    if not recs:
        return Finding(domain, MODULE, key, "DMARC kaydı yok: sahte e-postalar alıcıda reddedilmez",
                       "medium", {"records": []}, SPOOF_MITRE,
                       f"_dmarc.{domain} için TXT ekle. Önce 'v=DMARC1; p=none; rua=mailto:...' ile "
                       "raporları izle, sonra p=quarantine ve p=reject'e geç.")
    tags = _dmarc_tags(recs[0])
    policy = tags.get("p", "").lower()
    data = {"records": recs, "p": policy, "pct": tags.get("pct", "100"), "rua": tags.get("rua", "")}
    if policy == "reject":
        return Finding(domain, MODULE, key, "DMARC: p=reject (doğru yapılandırılmış)", "info", data)
    if policy == "quarantine":
        return Finding(domain, MODULE, key, "DMARC: p=quarantine", "info", data, [],
                       "Sahte mailler spam'e düşüyor; tam koruma için p=reject'e geç.")
    if policy == "none":
        return Finding(domain, MODULE, key, "DMARC: p=none, sadece izleme yapıyor, engellemiyor",
                       "low", data, SPOOF_MITRE, "Raporları inceledikten sonra p=quarantine / p=reject'e geç.")
    return Finding(domain, MODULE, key, f"DMARC: geçersiz politika '{policy}'", "medium", data,
                   SPOOF_MITRE, "p=reject, p=quarantine veya p=none olmalı.")


def check_caa(domain: str, caa: list[str] | None) -> Finding:
    if caa is None:
        return Finding(domain, MODULE, "dns/caa", "CAA kontrol edilemedi (DNS hatası)", "info")
    if not caa:
        return Finding(domain, MODULE, "dns/caa", "CAA kaydı yok: her sertifika otoritesi sertifika verebilir",
                       "low", {"records": []}, ["T1588.004"],
                       'Kullandığın CA\'yı sınırla, ör: 0 issue "letsencrypt.org"')
    return Finding(domain, MODULE, "dns/caa", f"CAA: {len(caa)} kayıt", "info", {"records": sorted(caa)})


def dns_inventory(domain: str, dns: DnsClient) -> list[Finding]:
    """NS / MX envanteri. Diff motoru bu kayıtların değişimini yakalar
    (ör. NS değişti -> domain ele geçirilmiş olabilir)."""
    out: list[Finding] = []
    ns = _safe(dns, domain, "NS")
    if ns:
        out.append(Finding(domain, MODULE, "dns/ns", f"NS: {', '.join(sorted(ns))}", "info",
                           {"records": sorted(ns)}, ["T1590.002"],
                           "NS kayıtlarındaki beklenmedik değişiklik domain ele geçirme işaretidir; "
                           "registrar hesabında 2FA ve registrar lock kullan."))
    mx = _safe(dns, domain, "MX")
    if mx:
        out.append(Finding(domain, MODULE, "dns/mx", f"MX: {', '.join(sorted(mx))}", "info",
                           {"records": sorted(mx)}, ["T1590.002"]))
    return out


# ------------------------------------------------------------------ ana giriş
@dataclass
class OsintResult:
    domain: str
    findings: list[Finding]
    subdomains: list[SubdomainInfo]
    ct_error: str = ""
    truncated: bool = False


def run(domain: str, dns: DnsClient, scope_check: Callable[[str, list[str]], Decision] | None = None,
        use_ct: bool = True, fetch: Fetcher | None = None, max_subdomains: int = 300) -> OsintResult:
    """Pasif OSINT. `scope_check(isim, ips)` her subdomain için aktif tarama iznini hesaplar."""
    findings: list[Finding] = []

    # E-posta ve DNS
    mx = _safe(dns, domain, "MX")
    findings.append(check_spf(domain, _safe(dns, domain, "TXT"), has_mx=bool(mx)))
    findings.append(check_dmarc(domain, _safe(dns, f"_dmarc.{domain}", "TXT")))
    findings.append(check_caa(domain, _safe(dns, domain, "CAA")))
    findings.extend(dns_inventory(domain, dns))

    # Certificate Transparency
    names: set[str] = {domain}
    ct_error = ""
    if use_ct:
        try:
            names |= crtsh_subdomains(domain, fetch)
        except OsintError as exc:
            ct_error = str(exc)
    ordered = sorted(names, key=lambda n: (n.count("."), n))
    truncated = len(ordered) > max_subdomains
    ordered = ordered[:max_subdomains]

    infos = resolve_all(dns, ordered)
    for info in infos:
        decision = scope_check(info.name, info.ips) if (scope_check and info.ips) else None
        findings.append(subdomain_finding(domain, info, decision))

    return OsintResult(domain, findings, infos, ct_error, truncated)

"""Zafiyet modülü: servis sürümü -> bilinen CVE'ler (NVD API 2.0).

Yaklaşım:
  1. Ağ taramasındaki Nmap CPE'sinden üretici ve ürünü al
     (cpe:/a:openbsd:openssh:6.6.1p1 -> openbsd / openssh / 6.6.1p1).
  2. NVD'den o ürünün TÜM CVE'lerini çek (sürüm joker: ...:openssh:*:...).
     Sonuçlar diskte önbelleklenir (varsayılan 24 saat); NVD'ye az istek gider.
  3. Her CVE'nin "configurations" içindeki CPE eşleme kriterlerini YEREL olarak
     değerlendir: versionStartIncluding / versionEndExcluding vb. aralıklar ve
     tam sürüm eşleşmeleri.

Neden eşlemeyi kendimiz yapıyoruz? NVD'nin sunucu taraflı eşleşmesi kara
kutu olur; yerelde yapınca hangi kuralın neden eşleştiği görünür ve test
edilebilir.

Bilinen sınırlamalar (rapora da yazılır):
  * Dağıtım backport'ları: Ubuntu/Debian/RHEL eski sürüm numarasını koruyup
    güvenlik yamalarını geri taşır. "OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13"
    birçok CVE'ye karşı yamalı olabilir. Sürüm tabanlı eşleme bunu göremez;
    sonuçlar "olası" kabul edilmeli ve dağıtımın güvenlik bültenleriyle
    doğrulanmalı.
  * AND düğümleri (ör. "sadece şu işletim sisteminde") değerlendirilmez;
    ürün eşleşmesi yeterli sayılır.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import __version__
from ..core.models import Finding

MODULE = "vuln"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
CACHE_TTL = 24 * 3600

JsonFetcher = Callable[[str, dict[str, str]], dict]


class VulnError(RuntimeError):
    pass


# ------------------------------------------------------------------ sürüm karşılaştırma
_TOKEN_RE = re.compile(r"\d+|[a-z]+")


def version_key(v: str) -> tuple:
    """'6.6.1p1' -> ((0,6),(0,6),(0,1),(1,'p'),(0,1)).

    Sayılar sayısal, harfler alfabetik karşılaştırılır. Sayı < harf, böylece
    6.6.1 < 6.6.1p1 < 6.6.2 olur (OpenSSH portable sürüm düzeni).
    """
    return tuple((0, int(t)) if t.isdigit() else (1, t) for t in _TOKEN_RE.findall(v.lower()))


def cmp_version(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


def cmp_bound(v: str, bound: str) -> int:
    """Aralık sınırıyla karşılaştırma. Sınırda harf eki yoksa ve sürüm 'sınır + ek' ise
    eşit sayılır: 6.6.1p1 vs sınır 6.6.1 -> 0. OpenSSH'ta 6.6.1p1, 6.6.1'in taşınabilir
    sürümüdür; "<= 6.6.1" onu da kapsamalı, "< 7.4" ise 7.4p1'i kapsamamalı.
    """
    kv, kb = version_key(v), version_key(bound)
    if len(kv) > len(kb) and kv[: len(kb)] == kb and kv[len(kb)][0] == 1:
        return 0
    return (kv > kb) - (kv < kb)


def normalize_version(raw: str) -> str:
    """Nmap sürüm alanından karşılaştırılabilir sürüm: '6.6.1p1 Ubuntu 2ubuntu2.13' -> '6.6.1p1'."""
    first = raw.strip().split(" ")[0] if raw.strip() else ""
    m = re.match(r"^v?(\d+(?:\.\d+)*[a-z0-9.\-]*)", first, re.I)
    return m.group(1).rstrip(".-") if m else ""


# ------------------------------------------------------------------ CPE
@dataclass(frozen=True)
class Product:
    part: str      # a (uygulama) | o (işletim sistemi) | h (donanım)
    vendor: str
    product: str
    version: str

    @property
    def match_string(self) -> str:
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:*:*:*:*:*:*:*:*"

    @property
    def label(self) -> str:
        return f"{self.vendor}:{self.product} {self.version}"


def product_from_service(cpes: list[str], version_field: str) -> Product | None:
    """Nmap CPE listesinden (2.2 formatı: cpe:/a:vendor:product:version) uygulama CPE'sini seçer."""
    for c in cpes:
        if not c.startswith("cpe:/a:"):
            continue  # işletim sistemi CPE'leri (cpe:/o:linux:linux_kernel) sürümsüz gelir, atla
        parts = c[len("cpe:/"):].split(":")
        if len(parts) < 3:
            continue
        part, vendor, product = parts[0], parts[1], parts[2]
        version = parts[3] if len(parts) > 3 and parts[3] else normalize_version(version_field)
        version = normalize_version(version) or version
        if vendor and product and version:
            return Product(part, vendor.lower(), product.lower(), version)
    return None


def _cpe_fields(criteria: str) -> list[str]:
    # cpe:2.3:part:vendor:product:version:update:...  (kaçışlı ':' içermeyen yaygın durum)
    return criteria.split(":")


def match_criteria(cm: dict, prod: Product) -> bool:
    """Tek bir cpeMatch girdisinin ürün sürümünü kapsayıp kapsamadığı."""
    if not cm.get("vulnerable", False):
        return False
    f = _cpe_fields(cm.get("criteria", ""))
    if len(f) < 7 or f[3].lower() != prod.vendor or f[4].lower() != prod.product:
        return False
    cv, cu = f[5], f[6]
    has_range = any(k in cm for k in ("versionStartIncluding", "versionStartExcluding",
                                       "versionEndIncluding", "versionEndExcluding"))
    if not has_range:
        if cv in ("*", "-"):
            return cv == "*"   # tüm sürümler
        # NVD bazen 6.6p1'i version=6.6, update=p1 olarak yazar: birleştirip karşılaştır
        target = cv + (cu if cu not in ("*", "-", "") else "")
        return cmp_version(prod.version, target) == 0
    v = prod.version
    if "versionStartIncluding" in cm and cmp_bound(v, cm["versionStartIncluding"]) < 0:
        return False
    if "versionStartExcluding" in cm and cmp_bound(v, cm["versionStartExcluding"]) <= 0:
        return False
    if "versionEndIncluding" in cm and cmp_bound(v, cm["versionEndIncluding"]) > 0:
        return False
    if "versionEndExcluding" in cm and cmp_bound(v, cm["versionEndExcluding"]) >= 0:
        return False
    return True


def _iter_cpe_matches(cve: dict):
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            if node.get("negate"):
                continue
            yield from node.get("cpeMatch", [])


# ------------------------------------------------------------------ CVE özetleri
@dataclass
class CveInfo:
    id: str
    score: float | None
    severity: str          # CRITICAL/HIGH/MEDIUM/LOW/NONE/UNKNOWN
    cvss_version: str
    description: str
    kev: bool
    published: str

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "score": self.score, "severity": self.severity,
                "cvss": self.cvss_version, "kev": self.kev, "published": self.published,
                "description": self.description[:300]}


def _score(metrics: dict) -> tuple[float | None, str, str]:
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        items = metrics.get(key) or []
        if items:
            primary = next((m for m in items if m.get("type") == "Primary"), items[0])
            data = primary.get("cvssData", {})
            return data.get("baseScore"), str(data.get("baseSeverity", "UNKNOWN")).upper(), ver
    items = metrics.get("cvssMetricV2") or []
    if items:
        m = items[0]
        return m.get("cvssData", {}).get("baseScore"), str(m.get("baseSeverity", "UNKNOWN")).upper(), "2.0"
    return None, "UNKNOWN", ""


def summarize(cve: dict) -> CveInfo:
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, sev, ver = _score(cve.get("metrics", {}))
    return CveInfo(cve.get("id", ""), score, sev, ver, desc, bool(cve.get("cisaExploitAdd")),
                   cve.get("published", "")[:10])


def matching_cves(vulns: list[dict], prod: Product) -> list[CveInfo]:
    out: list[CveInfo] = []
    for item in vulns:
        cve = item.get("cve", item)
        if cve.get("vulnStatus", "").lower() == "rejected":
            continue
        if any(match_criteria(cm, prod) for cm in _iter_cpe_matches(cve)):
            out.append(summarize(cve))
    out.sort(key=lambda c: (not c.kev, -(c.score or 0), c.id))
    return out


# ------------------------------------------------------------------ NVD istemcisi
def http_json(url: str, headers: dict[str, str], timeout: int = 60) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": f"surfacewatch/{__version__}", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (sabit https)
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            raise VulnError("NVD istek sınırı aşıldı; biraz bekle ya da NVD_API_KEY tanımla") from exc
        raise VulnError(f"NVD HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise VulnError(f"NVD'ye ulaşılamadı: {exc}") from exc


class NvdClient:
    """NVD CVE API 2.0 istemcisi: sayfalama, hız sınırı, disk önbelleği."""

    def __init__(self, cache_dir: Path | None = None, api_key: str | None = None,
                 fetch: JsonFetcher | None = None, ttl: int = CACHE_TTL, sleep: Callable[[float], None] = time.sleep):
        self.cache_dir = cache_dir or Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "surfacewatch" / "nvd"
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY", "")
        self.fetch = fetch or http_json
        self.ttl = ttl
        self.sleep = sleep
        # Anahtarsız: 30 sn'de 5 istek -> istek başı ~6 sn. Anahtarla 30 sn'de 50.
        self.delay = 0.7 if self.api_key else 6.5
        self._last = 0.0
        self.requests = 0

    def _cache_path(self, prod: Product) -> Path:
        safe = re.sub(r"[^a-z0-9_.-]", "_", f"{prod.part}_{prod.vendor}_{prod.product}")
        return self.cache_dir / f"{safe}.json"

    def _throttle(self) -> None:
        wait = self._last + self.delay - time.monotonic()
        if self._last and wait > 0:
            self.sleep(wait)
        self._last = time.monotonic()

    def product_cves(self, prod: Product, refresh: bool = False) -> tuple[list[dict], bool]:
        """(vulnerabilities listesi, önbellekten mi geldi)"""
        path = self._cache_path(prod)
        if not refresh and path.exists():
            try:
                cached = json.loads(path.read_text(encoding="utf-8"))
                if time.time() - cached.get("fetched_at", 0) < self.ttl:
                    return cached["vulnerabilities"], True
            except (json.JSONDecodeError, KeyError):
                pass

        headers = {"apiKey": self.api_key} if self.api_key else {}
        vulns: list[dict] = []
        start = 0
        while True:
            params = {"virtualMatchString": prod.match_string, "resultsPerPage": str(PAGE_SIZE),
                      "startIndex": str(start)}
            url = f"{NVD_URL}?{urllib.parse.urlencode(params)}&noRejected"
            self._throttle()
            data = self.fetch(url, headers)
            self.requests += 1
            page = data.get("vulnerabilities", [])
            vulns.extend(page)
            total = int(data.get("totalResults", len(vulns)))
            start += len(page)
            if not page or start >= total:
                break

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"fetched_at": time.time(), "match": prod.match_string,
                                    "vulnerabilities": vulns}), encoding="utf-8")
        return vulns, False


# ------------------------------------------------------------------ bulgular
_SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

BACKPORT_NOTE = ("Sürüm tabanlı eşleşme: dağıtımlar (Ubuntu/Debian/RHEL) güvenlik yamalarını eski sürüm numarasını "
                 "koruyarak geri taşır (backport). Her CVE'yi dağıtımın güvenlik bülteniyle doğrula.")

_DISTRO_RE = re.compile(r"ubuntu|debian|deb\d|el\d|centos|rhel|red hat|fedora|suse", re.I)


def to_finding(target: str, port_key: str, service: dict, prod: Product, cves: list[CveInfo]) -> Finding:
    banner = " ".join(x for x in (service.get("product"), service.get("version")) if x)
    distro = bool(_DISTRO_RE.search(f"{service.get('version', '')} {service.get('extrainfo', '')}"))
    data: dict[str, Any] = {
        "product": prod.label, "port": port_key, "banner": banner, "count": len(cves),
        "kev": [c.id for c in cves if c.kev],
        "cves": [c.to_dict() for c in cves[:50]], "truncated": len(cves) > 50,
        "distro_build": distro,
    }
    if not cves:
        return Finding(target, MODULE, f"cve/{port_key}", f"{banner or prod.label}: bilinen CVE bulunamadı",
                       "info", data)
    top = max((c.score or 0) for c in cves)
    worst = next((c.severity for c in cves if (c.score or 0) == top), "UNKNOWN")
    sev = _SEV_MAP.get(worst, "medium")
    if data["kev"] and sev != "critical":
        sev = "critical" if sev == "high" else "high"   # aktif istismar edilen açık: bir kademe yükselt
    title = f"{banner or prod.label}: {len(cves)} bilinen CVE (en yüksek CVSS {top}"
    title += f", {len(data['kev'])} aktif istismar/KEV)" if data["kev"] else ")"
    note = BACKPORT_NOTE if distro else ("Sürüm tabanlı eşleşme; yapılandırmaya bağlı CVE'ler "
                                         "her ortamda geçerli olmayabilir.")
    data["note"] = note
    return Finding(
        target, MODULE, f"cve/{port_key}", title, sev, data, ["T1190", "T1210"],
        f"{prod.product} yazılımını desteklenen son sürüme güncelle. Önce KEV listesindeki ve CVSS 9+ "
        "açıkları kapat; güncelleme hemen mümkün değilse servisi dışarıya kapat ya da IP ile kısıtla.",
    )


@dataclass
class VulnResult:
    findings: list[Finding] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    cache_hits: int = 0


def run(services: list[tuple[str, str, dict]], client: NvdClient, refresh: bool = False,
        progress: Callable[[str], None] | None = None) -> VulnResult:
    """services: [(target_ip, port_key, network_finding.data)]"""
    res = VulnResult()
    cache: dict[Product, tuple[list[dict], bool]] = {}
    for target, port_key, svc in services:
        prod = product_from_service(svc.get("cpe", []), svc.get("version", ""))
        if prod is None:
            res.skipped.append(f"{target} {port_key} {svc.get('service', '')}: sürüm/CPE bilgisi yok")
            continue
        key = Product(prod.part, prod.vendor, prod.product, "")
        try:
            if key not in cache:
                if progress:
                    progress(f"NVD: {prod.vendor}:{prod.product}")
                cache[key] = client.product_cves(prod, refresh=refresh)
                if cache[key][1]:
                    res.cache_hits += 1
        except VulnError as exc:
            res.errors.append(f"{prod.label}: {exc}")
            continue
        vulns, _ = cache[key]
        res.findings.append(to_finding(target, port_key, svc, prod, matching_cves(vulns, prod)))
    return res

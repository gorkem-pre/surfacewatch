"""Web modülü: HTTP/HTTPS yapılandırma kontrolleri.

Kontroller (hepsi düşük yoğunluklu; hedef başına ~10 istek):
  * HTTP -> HTTPS yönlendirmesi
  * Güvenlik header'ları (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy)
  * Bilgi ifşası (Server / X-Powered-By sürüm bilgisi)
  * Cookie bayrakları (Secure, HttpOnly, SameSite)
  * TLS: sertifika geçerliliği ve kalan gün, eski protokol (TLS 1.0/1.1) kabulü
  * Açıkta kalan hassas dosyalar (.git, .env, server-status, phpinfo ...);
    "soft 404" yanlış pozitiflerini önlemek için içerik doğrulanır
  * robots.txt içindeki gizli yollar (bilgi)

Bağlantılar kapsam kontrolünde çözülen IP'ye yapılır (TOCTOU koruması);
Host header'ı ve TLS SNI ise orijinal hostname ile gönderilir.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import time
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from .. import __version__
from ..core.models import Finding

MODULE = "web"
MAX_BODY = 64 * 1024
USER_AGENT = f"surfacewatch/{__version__} (+authorized scan)"


class WebError(RuntimeError):
    pass


@dataclass(frozen=True)
class WebTarget:
    scheme: str   # http | https
    host: str     # Host header / SNI için isim (IP de olabilir)
    ip: str       # bağlanılacak, kapsamda doğrulanmış IP
    port: int

    @property
    def url(self) -> str:
        default = {"http": 80, "https": 443}[self.scheme]
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{h}" + ("" if self.port == default else f":{self.port}")

    @property
    def host_is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False


@dataclass
class Response:
    status: int
    headers: list[tuple[str, str]]
    body: bytes = b""

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), None)

    def all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]


@dataclass
class TlsInfo:
    version: str = ""
    verified: bool = False
    verify_error: str = ""
    not_after: datetime | None = None
    issuer: str = ""
    subject: str = ""
    legacy: str | None = None      # kabul edilen eski sürüm ("TLSv1", "TLSv1.1") ya da None
    legacy_tested: bool = False
    error: str = ""


class Transport(Protocol):
    def get(self, target: WebTarget, path: str) -> Response: ...
    def tls(self, target: WebTarget) -> TlsInfo: ...


# ------------------------------------------------------------------ gerçek transport
class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """IP'ye bağlanır ama TLS SNI olarak hostname gönderir."""

    def __init__(self, ip: str, port: int, sni: str | None, context: ssl.SSLContext, timeout: float):
        super().__init__(ip, port, context=context, timeout=timeout)
        self._sni = sni

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._sni)


class HttpTransport:
    def __init__(self, timeout: float = 10.0, delay: float = 0.2) -> None:
        self.timeout = timeout
        self.delay = delay  # istekler arası bekleme: hedefi yormamak için

    def _unverified_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # sertifika kontrolü ayrıca tls() içinde yapılıyor
        return ctx

    def get(self, target: WebTarget, path: str) -> Response:
        time.sleep(self.delay)
        if target.scheme == "https":
            sni = None if target.host_is_ip else target.host
            conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
                target.ip, target.port, sni, self._unverified_ctx(), self.timeout)
        else:
            conn = http.client.HTTPConnection(target.ip, target.port, timeout=self.timeout)
        host_hdr = f"[{target.host}]" if ":" in target.host else target.host
        default = {"http": 80, "https": 443}[target.scheme]
        if target.port != default:
            host_hdr += f":{target.port}"
        try:
            conn.request("GET", path, headers={"Host": host_hdr, "User-Agent": USER_AGENT,
                                                "Accept": "*/*", "Connection": "close"})
            resp = conn.getresponse()
            body = resp.read(MAX_BODY)
            return Response(resp.status, resp.getheaders(), body)
        except (OSError, http.client.HTTPException) as exc:
            raise WebError(f"{target.url}{path}: {exc.__class__.__name__}: {exc}") from exc
        finally:
            conn.close()

    def tls(self, target: WebTarget) -> TlsInfo:
        info = TlsInfo()
        sni = None if target.host_is_ip else target.host

        ctx = ssl.create_default_context()
        if target.host_is_ip:
            ctx.check_hostname = False  # IP hedefte isim doğrulaması anlamsız; geçerlilik yine kontrol edilir
        try:
            with socket.create_connection((target.ip, target.port), self.timeout) as raw, \
                    ctx.wrap_socket(raw, server_hostname=sni) as s:
                info.version = s.version() or ""
                cert = s.getpeercert() or {}
                info.verified = True
                if cert.get("notAfter"):
                    info.not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]),
                                                            tz=timezone.utc)
                info.issuer = _dn(cert.get("issuer", ()), "organizationName")
                info.subject = _dn(cert.get("subject", ()), "commonName")
        except ssl.SSLCertVerificationError as exc:
            info.verify_error = exc.verify_message or str(exc)
            try:
                with socket.create_connection((target.ip, target.port), self.timeout) as raw, \
                        self._unverified_ctx().wrap_socket(raw, server_hostname=sni) as s:
                    info.version = s.version() or ""
            except (OSError, ssl.SSLError):
                pass
        except (OSError, ssl.SSLError) as exc:
            info.error = f"{exc.__class__.__name__}: {exc}"
            return info

        # Eski protokol testi: sadece TLS 1.0-1.1 ile el sıkışmayı dene
        legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        legacy.check_hostname = False
        legacy.verify_mode = ssl.CERT_NONE
        try:
            with warnings.catch_warnings():  # eski sürümleri bilerek kullanıyoruz: test bu
                warnings.simplefilter("ignore", DeprecationWarning)
                legacy.minimum_version = ssl.TLSVersion.TLSv1
                legacy.maximum_version = ssl.TLSVersion.TLSv1_1
            legacy.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            return info  # yerel OpenSSL eski sürümleri hiç desteklemiyor: test edilemedi
        info.legacy_tested = True
        try:
            with socket.create_connection((target.ip, target.port), self.timeout) as raw, \
                    legacy.wrap_socket(raw, server_hostname=sni) as s:
                info.legacy = s.version()
        except (OSError, ssl.SSLError):
            info.legacy = None
        return info


def _dn(seq: tuple, key: str) -> str:
    for rdn in seq:
        for k, v in rdn:
            if k == key:
                return v
    return ""


# ------------------------------------------------------------------ kontroller
def _f(t: WebTarget, key: str, title: str, sev: str, data: dict | None = None,
       mitre: list[str] | None = None, rem: str = "") -> Finding:
    return Finding(t.url, MODULE, key, title, sev, data or {}, mitre or [], rem)


def check_redirect(t: WebTarget, r: Response) -> Finding:
    loc = r.header("location") or ""
    data = {"status": r.status, "location": loc}
    if r.status in (301, 302, 303, 307, 308) and loc.lower().startswith("https://"):
        sev = "info" if r.status in (301, 308) else "low"
        rem = "" if sev == "info" else "Kalıcı yönlendirme (301/308) kullan; tarayıcı ve arama motorları önbelleğe alır."
        return _f(t, "http/redirect", f"HTTP -> HTTPS yönlendirmesi ({r.status})", sev, data, [], rem)
    return _f(t, "http/redirect", "HTTP şifresiz servis ediliyor, HTTPS'e yönlendirme yok", "medium", data,
              ["T1557", "T1040"],
              "Tüm HTTP isteklerini 301 ile HTTPS'e yönlendir ve HSTS ekle. Şifresiz trafik aynı ağdaki "
              "biri tarafından okunabilir ve değiştirilebilir.")


# (header, https gerektirir mi, eksikse önem, MITRE, düzeltme)
HEADER_RULES: list[tuple[str, bool, str, list[str], str]] = [
    ("strict-transport-security", True, "medium", ["T1557"],
     "Strict-Transport-Security: max-age=31536000; includeSubDomains ekle. Yoksa ilk istek HTTP ile "
     "yapılabilir ve SSL stripping saldırısına açık kalır."),
    ("content-security-policy", False, "low", ["T1059.007"],
     "Content-Security-Policy tanımla (en az default-src 'self'). XSS'in etkisini ciddi ölçüde azaltır."),
    ("x-content-type-options", False, "low", [],
     "X-Content-Type-Options: nosniff ekle; tarayıcının içerik tipini tahmin etmesini engeller."),
    ("referrer-policy", False, "info", [],
     "Referrer-Policy: strict-origin-when-cross-origin ekle; URL'deki hassas veriler üçüncü taraflara sızmaz."),
    ("permissions-policy", False, "info", [],
     "Permissions-Policy ile kamera, mikrofon, konum gibi API'leri kapat."),
]


def check_headers(t: WebTarget, r: Response) -> list[Finding]:
    out: list[Finding] = []
    for name, https_only, sev, mitre, rem in HEADER_RULES:
        if https_only and t.scheme != "https":
            continue
        value = r.header(name)
        key = f"header/{name}"
        if value is None:
            out.append(_f(t, key, f"Eksik header: {name}", sev, {"present": False}, mitre, rem))
            continue
        data = {"present": True, "value": value}
        if name == "strict-transport-security":
            m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
            age = int(m.group(1)) if m else 0
            data["max_age"] = age
            if age < 15552000:  # 180 gün
                out.append(_f(t, key, f"HSTS max-age kısa ({age} sn)", "low", data, mitre,
                              "max-age en az 15552000 (180 gün), tercihen 31536000 olmalı."))
                continue
        out.append(_f(t, key, f"{name}: {value[:80]}", "info", data))

    # Clickjacking: X-Frame-Options ya da CSP frame-ancestors
    csp = r.header("content-security-policy") or ""
    xfo = r.header("x-frame-options")
    if xfo or "frame-ancestors" in csp.lower():
        out.append(_f(t, "header/clickjacking", "Clickjacking koruması var", "info",
                      {"x-frame-options": xfo or "", "frame-ancestors": "frame-ancestors" in csp.lower()}))
    else:
        out.append(_f(t, "header/clickjacking", "Clickjacking koruması yok (X-Frame-Options / frame-ancestors)",
                      "low", {}, ["T1185"],
                      "X-Frame-Options: DENY ya da CSP'ye frame-ancestors 'none' ekle."))
    return out


_VERSION_RE = re.compile(r"\d+\.\d+")


def check_disclosure(t: WebTarget, r: Response) -> list[Finding]:
    out: list[Finding] = []
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        v = r.header(name)
        if not v:
            continue
        if _VERSION_RE.search(v) or name != "server":
            out.append(_f(t, f"disclosure/{name}", f"Sürüm bilgisi ifşa ediliyor: {name}: {v}", "low",
                          {"header": name, "value": v}, ["T1592.002"],
                          "Sürüm bilgisini gizle (Apache: ServerTokens Prod + ServerSignature Off; "
                          "nginx: server_tokens off; PHP: expose_php = Off). Saldırgan bu bilgiyle "
                          "doğrudan bilinen açıkları arar."))
        else:
            out.append(_f(t, f"disclosure/{name}", f"{name}: {v}", "info", {"header": name, "value": v}))
    return out


def check_cookies(t: WebTarget, r: Response) -> list[Finding]:
    out: list[Finding] = []
    for raw in r.all("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower() for a in raw.split(";")[1:]}
        missing = []
        if t.scheme == "https" and "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        data = {"cookie": name, "missing": missing}
        if not missing:
            out.append(_f(t, f"cookie/{name}", f"Cookie {name}: bayraklar tamam", "info", data))
            continue
        sensitive = bool(re.search(r"sess|auth|token|jwt|sid|login", name, re.I))
        sev = "medium" if sensitive and ("HttpOnly" in missing or "Secure" in missing) else "low"
        out.append(_f(t, f"cookie/{name}", f"Cookie {name}: eksik bayrak {', '.join(missing)}", sev, data,
                      ["T1539"],
                      "Oturum cookie'lerine Secure (sadece HTTPS), HttpOnly (JavaScript erişemez) ve "
                      "SameSite=Lax/Strict (CSRF) ekle."))
    return out


def check_tls(t: WebTarget, info: TlsInfo, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    if info.error:
        return [_f(t, "tls/handshake", f"TLS el sıkışması başarısız: {info.error}", "info", {"error": info.error})]
    out: list[Finding] = []
    data = {"version": info.version, "issuer": info.issuer, "subject": info.subject}

    if not info.verified:
        data["error"] = info.verify_error
        sev = "high" if "expired" in info.verify_error.lower() else "medium"
        out.append(_f(t, "tls/cert", f"Sertifika doğrulanamadı: {info.verify_error}", sev, data, ["T1557"],
                      "Güvenilir bir CA'dan (ör. Let's Encrypt) hostname ile eşleşen geçerli bir sertifika al. "
                      "Geçersiz sertifika kullanıcıları uyarıyı geçmeye alıştırır; MITM'i fark edilmez kılar."))
    elif info.not_after:
        days = (info.not_after - now).days
        data.update(not_after=info.not_after.isoformat(), days_left=days)
        if days < 0:
            sev, title = "high", f"Sertifikanın süresi dolmuş ({-days} gün önce)"
        elif days < 14:
            sev, title = "medium", f"Sertifika {days} gün içinde bitiyor"
        elif days < 30:
            sev, title = "low", f"Sertifika {days} gün içinde bitiyor"
        else:
            sev, title = "info", f"Sertifika geçerli, {days} gün kaldı ({info.issuer})"
        out.append(_f(t, "tls/cert", title, sev, data, [],
                      "" if sev == "info" else "Sertifikayı yenile; otomatik yenileme (certbot timer) kur."))

    if info.legacy:
        out.append(_f(t, "tls/legacy", f"Eski TLS sürümü kabul ediliyor: {info.legacy}", "medium",
                      {"accepted": info.legacy}, ["T1557"],
                      "TLS 1.0 ve 1.1'i kapat, sadece TLS 1.2 ve 1.3 kullan "
                      "(Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3; nginx: ssl_protocols TLSv1.2 TLSv1.3)."))
    elif info.legacy_tested:
        out.append(_f(t, "tls/legacy", "TLS 1.0/1.1 kabul edilmiyor", "info", {"accepted": None}))
    if info.version:
        out.append(_f(t, "tls/version", f"Anlaşılan protokol: {info.version}", "info", {"version": info.version}))
    return out


# (yol, önem, başlık, doğrulayıcı, MITRE, düzeltme)
SENSITIVE_FILES: list[tuple[str, str, str, re.Pattern[bytes], list[str], str]] = [
    ("/.git/HEAD", "high", "Git deposu açıkta (.git)",
     re.compile(rb"^ref: refs/|^[0-9a-f]{40}\s*$"), ["T1213.003", "T1592"],
     "Web kök dizinindeki .git klasörünü kaldır ya da erişimi engelle. Saldırgan tüm kaynak kodu "
     "ve commit geçmişindeki parolaları indirebilir (git-dumper)."),
    ("/.env", "critical", "Ortam değişkenleri dosyası açıkta (.env)",
     re.compile(rb"^\s*[A-Z][A-Z0-9_]{2,}\s*=", re.M), ["T1552.001"],
     ".env dosyasını web kökünden çıkar, erişimi engelle ve içindeki TÜM anahtar/parolaları değiştir."),
    ("/.DS_Store", "low", "macOS .DS_Store dosyası açıkta (dizin listesi sızar)",
     re.compile(rb"^\x00\x00\x00\x01Bud1"), ["T1083"],
     ".DS_Store dosyalarını sunucudan sil ve deploy sürecinde hariç tut."),
    ("/server-status", "medium", "Apache server-status açık",
     re.compile(rb"Apache Server Status"), ["T1592.002"],
     "mod_status'u kapat ya da 'Require local' ile sadece localhost'a aç."),
    ("/phpinfo.php", "medium", "phpinfo() sayfası açık",
     re.compile(rb"<title>PHP [\d.]+ - phpinfo\(\)</title>|phpinfo\(\)"), ["T1592.002"],
     "phpinfo dosyasını sil; sunucu yolları, modüller ve ortam değişkenleri sızıyor."),
    ("/.svn/entries", "high", "Subversion deposu açıkta (.svn)",
     re.compile(rb"^\d+\s*$|^dir$", re.M), ["T1213.003"],
     ".svn klasörünü web kökünden kaldır."),
]


def check_files(t: WebTarget, transport: Transport) -> list[Finding]:
    out: list[Finding] = []
    for path, sev, title, validator, mitre, rem in SENSITIVE_FILES:
        try:
            r = transport.get(t, path)
        except WebError:
            continue
        # 200 + içerik doğrulaması: "her şeye 200 dönen" sunucularda yanlış pozitif olmaz
        if r.status == 200 and validator.search(r.body[:4096]):
            out.append(_f(t, f"file{path}", f"{title}: {t.url}{path}", sev,
                          {"path": path, "status": r.status, "size": len(r.body)}, mitre, rem))
    return out


def check_robots(t: WebTarget, transport: Transport) -> list[Finding]:
    try:
        r = transport.get(t, "/robots.txt")
    except WebError:
        return []
    if r.status != 200 or b"disallow" not in r.body.lower():
        return []
    paths = sorted({m.decode("utf-8", "replace").strip()
                    for m in re.findall(rb"(?im)^\s*disallow\s*:\s*(\S+)", r.body)} - {"/"})
    if not paths:
        return []
    return [_f(t, "file/robots.txt", f"robots.txt {len(paths)} gizli yol listeliyor", "info",
               {"disallow": paths[:50]}, ["T1595.003"],
               "robots.txt bir güvenlik önlemi değildir; burada listelenen yollar herkese açıktır. "
               "Hassas yolları kimlik doğrulamayla koru.")]


# ------------------------------------------------------------------ ana giriş
@dataclass
class WebResult:
    target: WebTarget
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    status: int | None = None


def run(t: WebTarget, transport: Transport, check_files_enabled: bool = True) -> WebResult:
    res = WebResult(t)
    try:
        root = transport.get(t, "/")
    except WebError as exc:
        res.error = str(exc)
        return res
    res.status = root.status

    if t.scheme == "http":
        res.findings.append(check_redirect(t, root))
    res.findings += check_headers(t, root)
    res.findings += check_disclosure(t, root)
    res.findings += check_cookies(t, root)
    if t.scheme == "https":
        res.findings += check_tls(t, transport.tls(t))
    if check_files_enabled:
        res.findings += check_files(t, transport)
        res.findings += check_robots(t, transport)
    return res


# ------------------------------------------------------------------ hedef ayrıştırma
_URL_RE = re.compile(r"^(?:(?P<scheme>https?)://)?(?P<host>\[[^\]]+\]|[^:/\s]+)(?::(?P<port>\d+))?/?$", re.I)


def parse_target(raw: str) -> list[tuple[str, str, int]]:
    """'https://x', 'x:8080', 'x' -> [(scheme, host, port)].

    Şema ve port yoksa hem http:80 hem https:443 denenir.
    """
    m = _URL_RE.match(raw.strip())
    if not m:
        raise ValueError(f"Geçersiz web hedefi: {raw!r} (ör. ornek.com, https://ornek.com, 10.0.0.5:8080)")
    host = m.group("host").strip("[]").lower()
    scheme = (m.group("scheme") or "").lower()
    port = int(m.group("port")) if m.group("port") else None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"Geçersiz port: {port}")
    if scheme:
        return [(scheme, host, port or {"http": 80, "https": 443}[scheme])]
    if port is not None:
        return [("https" if port in (443, 8443, 9443) else "http", host, port)]
    return [("http", host, 80), ("https", host, 443)]

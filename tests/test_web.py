import shutil
import ssl
import subprocess
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from surfacewatch import cli
from surfacewatch.cli import main
from surfacewatch.core import Finding, Storage
from surfacewatch.modules import web
from surfacewatch.modules.web import Response, TlsInfo, WebTarget

HTTP = WebTarget("http", "lab.example", "192.168.56.10", 80)
HTTPS = WebTarget("https", "lab.example", "192.168.56.10", 443)


def keys(findings):
    return {f.key: f for f in findings}


# ------------------------------------------------------------ hedef ayrıştırma
@pytest.mark.parametrize("raw,expected", [
    ("lab.example", [("http", "lab.example", 80), ("https", "lab.example", 443)]),
    ("https://Lab.Example/", [("https", "lab.example", 443)]),
    ("http://lab.example:8080", [("http", "lab.example", 8080)]),
    ("10.0.0.5:8443", [("https", "10.0.0.5", 8443)]),
    ("10.0.0.5:8000", [("http", "10.0.0.5", 8000)]),
    ("[2600:3c01::1]:443", [("https", "2600:3c01::1", 443)]),
])
def test_parse_target(raw, expected):
    assert web.parse_target(raw) == expected


@pytest.mark.parametrize("bad", ["ftp://x", "http://x/path", "x:99999", "a b", ""])
def test_parse_target_invalid(bad):
    with pytest.raises(ValueError):
        web.parse_target(bad)


def test_url_property():
    assert HTTPS.url == "https://lab.example"
    assert WebTarget("http", "10.0.0.1", "10.0.0.1", 8080).url == "http://10.0.0.1:8080"
    assert WebTarget("https", "2600::1", "2600::1", 443).url == "https://[2600::1]"


# ------------------------------------------------------------ yönlendirme / header
def test_redirect():
    assert web.check_redirect(HTTP, Response(301, [("Location", "https://lab.example/")])).severity == "info"
    assert web.check_redirect(HTTP, Response(302, [("Location", "https://lab.example/")])).severity == "low"
    bad = web.check_redirect(HTTP, Response(200, []))
    assert bad.severity == "medium" and "T1557" in bad.mitre
    assert web.check_redirect(HTTP, Response(301, [("Location", "http://other/")])).severity == "medium"


def test_headers_missing_on_https():
    f = keys(web.check_headers(HTTPS, Response(200, [])))
    assert f["header/strict-transport-security"].severity == "medium"
    assert f["header/content-security-policy"].severity == "low"
    assert f["header/clickjacking"].severity == "low"


def test_hsts_not_checked_on_http():
    assert "header/strict-transport-security" not in keys(web.check_headers(HTTP, Response(200, [])))


def test_headers_present_and_case_insensitive():
    r = Response(200, [("strict-transport-security", "max-age=31536000; includeSubDomains"),
                       ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                       ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
                       ("Permissions-Policy", "camera=()")])
    f = web.check_headers(HTTPS, r)
    assert all(x.severity == "info" for x in f)


def test_hsts_short_max_age():
    r = Response(200, [("Strict-Transport-Security", "max-age=300")])
    hsts = keys(web.check_headers(HTTPS, r))["header/strict-transport-security"]
    assert hsts.severity == "low" and hsts.data["max_age"] == 300


def test_xfo_counts_as_clickjacking_protection():
    f = keys(web.check_headers(HTTP, Response(200, [("X-Frame-Options", "DENY")])))
    assert f["header/clickjacking"].severity == "info"


# ------------------------------------------------------------ ifşa / cookie
def test_disclosure():
    r = Response(200, [("Server", "Apache/2.4.7 (Ubuntu)"), ("X-Powered-By", "PHP/5.5.9")])
    f = keys(web.check_disclosure(HTTP, r))
    assert f["disclosure/server"].severity == "low" and "T1592.002" in f["disclosure/server"].mitre
    assert f["disclosure/x-powered-by"].severity == "low"
    assert keys(web.check_disclosure(HTTP, Response(200, [("Server", "nginx")])))[
        "disclosure/server"].severity == "info"


def test_cookies():
    r = Response(200, [("Set-Cookie", "PHPSESSID=abc; path=/"),
                       ("Set-Cookie", "theme=dark; Secure; HttpOnly; SameSite=Lax"),
                       ("Set-Cookie", "pref=1; HttpOnly; SameSite=Strict")])
    f = keys(web.check_cookies(HTTPS, r))
    assert f["cookie/PHPSESSID"].severity == "medium"
    assert set(f["cookie/PHPSESSID"].data["missing"]) == {"Secure", "HttpOnly", "SameSite"}
    assert f["cookie/theme"].severity == "info"
    assert f["cookie/pref"].data["missing"] == ["Secure"] and f["cookie/pref"].severity == "low"
    # HTTP'de Secure eksikliği raporlanmaz (zaten gönderilemez)
    assert web.check_cookies(HTTP, Response(200, [("Set-Cookie", "a=1; HttpOnly; SameSite=Lax")]))[0].severity == "info"


# ------------------------------------------------------------ TLS analizi
NOW = datetime(2026, 11, 21, tzinfo=timezone.utc)


@pytest.mark.parametrize("days,sev", [(-3, "high"), (5, "medium"), (20, "low"), (80, "info")])
def test_tls_expiry(days, sev):
    info = TlsInfo(version="TLSv1.3", verified=True, not_after=NOW + timedelta(days=days, hours=1),
                   issuer="Let's Encrypt", legacy_tested=True)
    f = keys(web.check_tls(HTTPS, info, now=NOW))
    assert f["tls/cert"].severity == sev
    assert f["tls/legacy"].severity == "info" and f["tls/version"].data["version"] == "TLSv1.3"


def test_tls_verify_errors():
    f = keys(web.check_tls(HTTPS, TlsInfo(verify_error="self-signed certificate"), now=NOW))
    assert f["tls/cert"].severity == "medium"
    f = keys(web.check_tls(HTTPS, TlsInfo(verify_error="certificate has expired"), now=NOW))
    assert f["tls/cert"].severity == "high"


def test_tls_legacy_and_untested():
    f = keys(web.check_tls(HTTPS, TlsInfo(verified=True, legacy="TLSv1", legacy_tested=True), now=NOW))
    assert f["tls/legacy"].severity == "medium"
    f = keys(web.check_tls(HTTPS, TlsInfo(verified=True, legacy_tested=False), now=NOW))
    assert "tls/legacy" not in f   # test edilemediyse "güvenli" demiyoruz


def test_tls_handshake_error():
    (f,) = web.check_tls(HTTPS, TlsInfo(error="ConnectionRefusedError"), now=NOW)
    assert f.key == "tls/handshake" and f.severity == "info"


# ------------------------------------------------------------ hassas dosyalar (sahte transport)
class FakeTransport:
    def __init__(self, routes, default=None, tls_info=None):
        self.routes = routes
        self.default = default
        self.tls_info = tls_info or TlsInfo(verified=True, version="TLSv1.3", legacy_tested=True,
                                            not_after=datetime.now(timezone.utc) + timedelta(days=60))
        self.requests = []

    def get(self, target, path):
        self.requests.append((target.url, path))
        if path in self.routes:
            r = self.routes[path]
            if isinstance(r, Exception):
                raise r
            return r
        if self.default is not None:
            return self.default
        return Response(404, [], b"not found")

    def tls(self, target):
        return self.tls_info


def test_sensitive_files_detected():
    t = FakeTransport({
        "/.git/HEAD": Response(200, [], b"ref: refs/heads/main\n"),
        "/.env": Response(200, [], b"APP_KEY=base64:xxx\nDB_PASSWORD=secret\n"),
        "/server-status": Response(200, [], b"<html><h1>Apache Server Status for lab</h1>"),
        "/.DS_Store": Response(200, [], b"\x00\x00\x00\x01Bud1\x00\x00"),
    })
    f = keys(web.check_files(HTTP, t))
    assert f["file/.git/HEAD"].severity == "high"
    assert f["file/.env"].severity == "critical" and "T1552.001" in f["file/.env"].mitre
    assert "file/server-status" in f and "file/.DS_Store" in f
    assert "file/phpinfo.php" not in f


def test_soft_404_no_false_positives():
    # Her yola 200 + aynı HTML dönen sunucu (SPA / catch-all)
    t = FakeTransport({}, default=Response(200, [], b"<!doctype html><html><body>Welcome</body></html>"))
    assert web.check_files(HTTP, t) == []


def test_robots():
    t = FakeTransport({"/robots.txt": Response(200, [], b"User-agent: *\nDisallow: /admin/\nDisallow: /backup\nDisallow: /\n")})
    (f,) = web.check_robots(HTTP, t)
    assert f.data["disallow"] == ["/admin/", "/backup"]


def test_run_http_and_https():
    t = FakeTransport({"/": Response(200, [("Server", "Apache/2.4.7 (Ubuntu)")], b"hi")})
    res = web.run(HTTP, t)
    k = keys(res.findings)
    assert res.status == 200 and "http/redirect" in k and "tls/cert" not in k
    res = web.run(HTTPS, t, check_files_enabled=False)
    k = keys(res.findings)
    assert "tls/cert" in k and "http/redirect" not in k
    assert all(p == "/" for _, p in t.requests[-1:])


def test_run_connection_error():
    t = FakeTransport({"/": web.WebError("ConnectionRefusedError")})
    res = web.run(HTTP, t)
    assert res.error and res.findings == []


# ------------------------------------------------------------ gerçek HttpTransport (yerel sunucu)
class _Handler(BaseHTTPRequestHandler):
    seen_hosts: list = []

    def do_GET(self):  # noqa: N802
        _Handler.seen_hosts.append(self.headers.get("Host"))
        if self.path == "/":
            self.send_response(200)
            self.send_header("Server", "Apache/2.4.7 (Ubuntu)")
            self.send_header("Set-Cookie", "sessionid=x; path=/")
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/.git/HEAD":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main\n")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def local_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield srv.server_address[1]
    srv.shutdown()


def test_real_transport_pins_ip_and_sends_host(local_server):
    _Handler.seen_hosts.clear()
    t = WebTarget("http", "lab.example", "127.0.0.1", local_server)
    res = web.run(t, web.HttpTransport(delay=0))
    k = keys(res.findings)
    assert res.status == 200
    assert "file/.git/HEAD" in k and "disclosure/server" in k and k["cookie/sessionid"].severity == "medium"
    # 127.0.0.1'e bağlandı ama Host header'ı hostname ile gitti (DNS'e hiç sorulmadı)
    assert _Handler.seen_hosts[0] == f"lab.example:{local_server}"


def test_real_transport_connection_refused():
    t = WebTarget("http", "127.0.0.1", "127.0.0.1", 1)
    with pytest.raises(web.WebError):
        web.HttpTransport(delay=0, timeout=2).get(t, "/")


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl yok")
def test_real_tls_self_signed(tmp_path):
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=lab.example", "-keyout", str(key), "-out", str(crt)],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        t = WebTarget("https", "lab.example", "127.0.0.1", srv.server_address[1])
        tr = web.HttpTransport(delay=0, timeout=5)
        info = tr.tls(t)
        assert not info.verified and "self" in info.verify_error.lower()
        assert info.version.startswith("TLSv1.")
        assert tr.get(t, "/").status == 200   # içerik kontrolleri yine de çalışır
        f = keys(web.check_tls(t, info))
        assert f["tls/cert"].severity == "medium"
    finally:
        srv.shutdown()


# ------------------------------------------------------------ CLI
@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    scope = tmp_path / "scope.yml"
    scope.write_text("name: lab\ntargets:\n  hosts: [45.33.32.156, '2600:3c01::f03c:91ff:fe18:bb2f']\n  networks: [192.168.56.0/24]\n"
                     "  domains:\n    - {name: scanme.nmap.org, include_subdomains: false}\n", encoding="utf-8")
    from surfacewatch.core import scope as scope_mod
    monkeypatch.setattr(scope_mod, "resolve_host",
                        lambda h: ["45.33.32.156", "2600:3c01::f03c:91ff:fe18:bb2f"])
    fake = FakeTransport({"/": Response(200, [("Server", "Apache/2.4.7 (Ubuntu)")], b"x"),
                          "/.git/HEAD": Response(200, [], b"ref: refs/heads/master\n")})
    monkeypatch.setattr(cli, "make_transport", lambda: fake)
    return scope, tmp_path / "sw.db", fake


def test_cli_web(cli_env, capsys):
    scope, db, fake = cli_env
    rc = main(["-s", str(scope), "--db", str(db), "web", "http://scanme.nmap.org", "https://google.com"])
    assert rc == 0
    out, err = capsys.readouterr()
    assert "ATLANDI https://google.com" in err
    assert "Git deposu açıkta" in out and "HTTPS'e yönlendirme yok" in out
    assert fake.requests[0][0] == "http://scanme.nmap.org"
    with Storage(db) as s:
        assert s.list_scans()[0].modules == ["web"]


def test_cli_web_from_scan(cli_env, capsys):
    scope, db, fake = cli_env
    with Storage(db) as s:
        sid = s.start_scan("lab", ["network"], ["45.33.32.156"])
        s.add_findings(sid, [
            Finding("45.33.32.156", "network", "tcp/80", "http", "info",
                    {"port": 80, "service": "http", "hostname": "scanme.nmap.org"}),
            Finding("45.33.32.156", "network", "tcp/22", "ssh", "info", {"port": 22, "service": "ssh"}),
        ])
        s.finish_scan(sid)
    assert main(["-s", str(scope), "--db", str(db), "web", "--from-scan"]) == 0
    err = capsys.readouterr().err
    assert "1 web servisi" in err
    assert [u for u, p in fake.requests if p == "/"] == ["http://scanme.nmap.org"]


def test_cli_web_nothing(cli_env):
    scope, db, _ = cli_env
    assert main(["-s", str(scope), "--db", str(db), "web"]) == 2
    assert main(["-s", str(scope), "--db", str(db), "web", "8.8.8.8"]) == 2

from pathlib import Path

import pytest

from surfacewatch import cli
from surfacewatch.cli import main
from surfacewatch.core import Scope, Storage
from surfacewatch.modules import osint
from surfacewatch.modules.dnsclient import FakeDns

CRTSH = (Path(__file__).parent / "fixtures" / "crtsh_lab.json").read_text(encoding="utf-8")
D = "lab.example"


def lab_dns(**overrides) -> FakeDns:
    records = {
        (D, "A"): ["192.168.56.10"],
        (D, "MX"): ["10 mail.lab.example"],
        (D, "NS"): ["ns2.registrar.example", "ns1.registrar.example"],
        (D, "TXT"): ["google-site-verification=abc", "v=spf1 mx ~all"],
        (f"_dmarc.{D}", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@lab.example"],
        (f"www.{D}", "A"): ["192.168.56.10"],
        (f"dev.{D}", "A"): ["192.168.56.20"],
        (f"docs.{D}", "CNAME"): ["lab-docs.github.io"],
        (f"old-blog.{D}", "CNAME"): ["oldblog.someprovider.net"],
        (f"cdn.{D}", "A"): ["104.16.1.1"],
    }
    records.update(overrides.pop("records", {}))
    nx = {"lab-docs.github.io", "oldblog.someprovider.net", f"legacy.{D}"} | overrides.pop("nx", set())
    return FakeDns(records, nxdomain=nx, **overrides)


def lab_scope() -> Scope:
    return Scope.from_dict({"name": "lab", "targets": {"networks": ["192.168.56.0/24"],
                                                       "domains": [D]}})


def run_lab(**kw):
    scope = lab_scope()
    return osint.run(D, kw.pop("dns", lab_dns()),
                     scope_check=lambda n, ips: scope.check(n, active=True, resolver=lambda _h: ips),
                     fetch=kw.pop("fetch", lambda url: CRTSH), **kw)


def by_key(res):
    return {f.key: f for f in res.findings}


# ------------------------------------------------------------ crt.sh
def test_parse_crtsh_filters_and_normalizes():
    names = osint.parse_crtsh(CRTSH, D)
    assert names == {D, f"www.{D}", f"dev.{D}", f"docs.{D}", f"old-blog.{D}", f"legacy.{D}", f"cdn.{D}"}
    # e-posta, sonek hilesi, başka domain, geçersiz karakter elendi; wildcard ve büyük harf normalize


def test_parse_crtsh_bad_json():
    with pytest.raises(osint.OsintError):
        osint.parse_crtsh("<html>502 Bad Gateway</html>", D)
    assert osint.parse_crtsh("", D) == set()


def test_crtsh_url_is_encoded():
    seen = []
    osint.crtsh_subdomains(D, fetch=lambda u: seen.append(u) or "[]")
    assert seen == ["https://crt.sh/?q=%25.lab.example&output=json"]


# ------------------------------------------------------------ subdomain analizi
def test_subdomain_classification():
    f = by_key(run_lab())
    docs = f[f"subdomain/docs.{D}"]
    assert docs.severity == "high" and "takeover" in docs.title and "T1584.001" in docs.mitre
    old = f[f"subdomain/old-blog.{D}"]
    assert old.severity == "medium" and "Dangling" in old.title
    dev = f[f"subdomain/dev.{D}"]
    assert dev.severity == "low" and dev.data["active_scan"] is True
    cdn = f[f"subdomain/cdn.{D}"]
    assert cdn.severity == "info" and cdn.data["active_scan"] is False
    assert "kapsam dışı" in cdn.data["scope_reason"]
    legacy = f[f"subdomain/legacy.{D}"]
    assert legacy.data["status"] == "nxdomain" and legacy.data["active_scan"] is None
    www = f[f"subdomain/www.{D}"]
    assert www.severity == "info" and www.data["ips"] == ["192.168.56.10"]


@pytest.mark.parametrize("label,interesting", [
    ("dev", True), ("staging-api", True), ("jenkins", True), ("test2", True), ("db.internal", True),
    ("www", False), ("developer-docs", False), ("contest", False), ("shop", False),
])
def test_interesting_names(label, interesting):
    assert bool(osint.INTERESTING_RE.search(label)) is interesting


def test_ct_failure_still_runs_dns_checks():
    def broken(url):
        raise osint.OsintError("crt.sh'e ulaşılamadı")
    res = run_lab(fetch=broken)
    assert res.ct_error
    keys = by_key(res)
    assert "email/spf" in keys and f"subdomain/{D}" in keys
    assert not any(k.startswith("subdomain/dev.") for k in keys)


def test_no_ct_and_max():
    res = run_lab(use_ct=False)
    assert [s.name for s in res.subdomains] == [D]
    res = run_lab(max_subdomains=3)
    assert res.truncated and len(res.subdomains) == 3
    assert res.subdomains[0].name == D  # en kısa isim önce


def test_dns_error_on_subdomain():
    res = run_lab(dns=lab_dns(errors={f"www.{D}"}))
    assert by_key(res)[f"subdomain/www.{D}"].data["status"] == "error"


# ------------------------------------------------------------ SPF
@pytest.mark.parametrize("txt,sev,fragment", [
    (["v=spf1 include:_spf.google.com -all"], "info", "-all"),
    (["v=spf1 mx ~all"], "low", "softfail"),
    (["v=spf1 mx ?all"], "medium", "?all"),
    (["v=spf1 +all"], "high", "+all"),
    (["v=spf1 all"], "high", "+all"),
    (["v=spf1 mx"], "medium", "'all' mekanizması yok"),
    (["v=spf1 mx -all", "v=spf1 a -all"], "medium", "Birden fazla"),
    (["some-other-txt"], "medium", "SPF kaydı yok"),
    ([], "medium", "SPF kaydı yok"),
])
def test_spf(txt, sev, fragment):
    f = osint.check_spf(D, txt, has_mx=True)
    assert f.severity == sev and fragment in f.title


def test_spf_no_mx_recommends_reject_all():
    assert "v=spf1 -all" in osint.check_spf(D, [], has_mx=False).remediation


def test_spf_dns_error():
    assert osint.check_spf(D, None, has_mx=True).severity == "info"


# ------------------------------------------------------------ DMARC / CAA
@pytest.mark.parametrize("txt,sev,fragment", [
    (["v=DMARC1; p=reject; rua=mailto:a@b"], "info", "p=reject"),
    (["v=DMARC1; p=quarantine; pct=50"], "info", "quarantine"),
    (["v=DMARC1; p=none"], "low", "p=none"),
    (["v=DMARC1; p=yes"], "medium", "geçersiz"),
    (["v=DMARC1;p=reject"], "info", "p=reject"),
    ([], "medium", "DMARC kaydı yok"),
])
def test_dmarc(txt, sev, fragment):
    f = osint.check_dmarc(D, txt)
    assert f.severity == sev and fragment in f.title


def test_dmarc_tags():
    f = osint.check_dmarc(D, ["v=DMARC1; p=quarantine; pct=50; rua=mailto:x@y"])
    assert f.data["pct"] == "50" and f.data["rua"] == "mailto:x@y"


def test_caa():
    assert osint.check_caa(D, []).severity == "low"
    assert osint.check_caa(D, ['0 issue "letsencrypt.org"']).severity == "info"


def test_inventory_sorted_for_stable_diff():
    f = by_key(run_lab(use_ct=False))
    assert f["dns/ns"].data["records"] == ["ns1.registrar.example", "ns2.registrar.example"]
    assert f["email/spf"].severity == "low" and f["email/dmarc"].severity == "low"
    assert f["dns/caa"].severity == "low"


# ------------------------------------------------------------ CLI
@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    scope = tmp_path / "scope.yml"
    scope.write_text("name: lab\ntargets:\n  networks: [192.168.56.0/24]\n  domains: [lab.example]\n",
                     encoding="utf-8")
    dns = lab_dns()
    monkeypatch.setattr(cli, "make_dns", lambda: dns)
    monkeypatch.setattr(osint, "http_get", lambda url, **kw: CRTSH)
    return scope, tmp_path / "sw.db", dns


def test_cli_osint(cli_env, capsys):
    scope, db, _ = cli_env
    assert main(["-s", str(scope), "--db", str(db), "osint", "lab.example", "other.com", "10.0.0.1"]) == 0
    out, err = capsys.readouterr()
    assert "ATLANDI other.com" in err and "ATLANDI 10.0.0.1" in err
    assert "takeover" in out and "cdn.lab.example" in out
    assert "legacy.lab.example" not in out and "gizlendi" in out   # -v olmadan çözülmeyenler gizli
    with Storage(db) as s:
        (scan,) = s.list_scans()
        assert scan.modules == ["osint"]
        assert len(s.findings(scan.id)) == 5 + 7   # spf, dmarc, caa, ns, mx + 7 isim


def test_cli_osint_verbose_and_show(cli_env, capsys):
    scope, db, _ = cli_env
    main(["-s", str(scope), "--db", str(db), "osint", "lab.example", "-v"])
    out = capsys.readouterr().out
    assert "legacy.lab.example" in out and "düzelt" in out
    assert main(["-s", str(scope), "--db", str(db), "show"]) == 0
    assert "Subdomain'ler" in capsys.readouterr().out


def test_cli_osint_out_of_scope_only(cli_env):
    scope, db, _ = cli_env
    assert main(["-s", str(scope), "--db", str(db), "osint", "google.com"]) == 2


def test_cli_osint_does_not_reresolve_for_scope(cli_env):
    scope, db, dns = cli_env
    main(["-s", str(scope), "--db", str(db), "osint", "lab.example", "--no-ct"])
    # Kapsam kontrolü önceden çözülen IP'leri kullanmalı; aynı isim için ek A sorgusu olmamalı
    a_queries = [c for c in dns.calls if c == (D, "A")]
    assert len(a_queries) == 1

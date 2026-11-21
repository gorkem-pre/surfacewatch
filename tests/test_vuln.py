"""Zafiyet modülü testleri.

fixtures/nvd_openssh_synthetic.json SENTETİKTİR: CVE-2099-xxxx kimlikleri gerçek
değildir, sadece NVD 2.0 JSON yapısını ve eşleşme kurallarını test eder.
"""

import json
import time
from pathlib import Path

import pytest

from surfacewatch import cli
from surfacewatch.cli import main
from surfacewatch.core import Storage
from surfacewatch.modules import network, vuln

FIX = Path(__file__).parent / "fixtures"
NVD = json.loads((FIX / "nvd_openssh_synthetic.json").read_text(encoding="utf-8"))
SSH = vuln.Product("a", "openbsd", "openssh", "6.6.1p1")


# ------------------------------------------------------------ sürüm karşılaştırma
@pytest.mark.parametrize("a,b,expected", [
    ("6.6.1", "6.6.1p1", -1), ("6.6.1p1", "6.6.2", -1), ("7.4", "7.10", -1),
    ("2.4.7", "2.4.7", 0), ("9.8p1", "9.8p2", -1), ("1.0", "1.0.0", -1), ("10.0", "9.9", 1),
])
def test_cmp_version(a, b, expected):
    assert vuln.cmp_version(a, b) == expected


@pytest.mark.parametrize("v,bound,expected", [
    ("6.6.1p1", "6.6.1", 0),   # taşınabilir sürüm, sınırla eşit sayılır
    ("7.4p1", "7.4", 0),
    ("6.6.1p1", "6.6.2", -1),
    ("6.6.1", "6.6.1p1", -1),
    ("2.4.10", "2.4.9", 1),
])
def test_cmp_bound(v, bound, expected):
    assert vuln.cmp_bound(v, bound) == expected


@pytest.mark.parametrize("raw,expected", [
    ("6.6.1p1 Ubuntu 2ubuntu2.13", "6.6.1p1"), ("2.4.7", "2.4.7"), ("v1.18.0", "1.18.0"),
    ("", ""), ("Ubuntu", ""),
])
def test_normalize_version(raw, expected):
    assert vuln.normalize_version(raw) == expected


# ------------------------------------------------------------ CPE
def test_product_from_nmap_cpe():
    p = vuln.product_from_service(["cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:linux:linux_kernel"],
                                  "6.6.1p1 Ubuntu 2ubuntu2.13")
    assert p == SSH
    assert p.match_string == "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"


def test_product_version_fallback_and_missing():
    p = vuln.product_from_service(["cpe:/a:apache:http_server"], "2.4.7")
    assert p == vuln.Product("a", "apache", "http_server", "2.4.7")
    assert vuln.product_from_service(["cpe:/o:linux:linux_kernel"], "") is None
    assert vuln.product_from_service([], "1.0") is None
    assert vuln.product_from_service(["cpe:/a:x:y"], "") is None


# ------------------------------------------------------------ eşleşme
def test_matching_cves_against_synthetic_feed():
    found = vuln.matching_cves(NVD["vulnerabilities"], SSH)
    ids = [c.id for c in found]
    assert set(ids) == {"CVE-2099-0001", "CVE-2099-0004", "CVE-2099-0007", "CVE-2099-0008", "CVE-2099-0012"}
    assert ids[0] == "CVE-2099-0008"          # KEV önce
    assert ids[1] == "CVE-2099-0001"          # sonra en yüksek skor


def test_newer_version_matches_less():
    found = {c.id for c in vuln.matching_cves(NVD["vulnerabilities"], vuln.Product("a", "openbsd", "openssh", "9.0p1"))}
    assert found == {"CVE-2099-0002"}         # 8.5p1 <= 9.0p1 < 9.8p1


def test_scoring_versions():
    by_id = {c.id: c for c in vuln.matching_cves(NVD["vulnerabilities"], SSH)}
    assert (by_id["CVE-2099-0001"].score, by_id["CVE-2099-0001"].cvss_version) == (7.5, "3.1")
    assert by_id["CVE-2099-0004"].severity == "MEDIUM" and by_id["CVE-2099-0004"].cvss_version == "2.0"
    assert by_id["CVE-2099-0012"].score is None and by_id["CVE-2099-0012"].severity == "UNKNOWN"
    assert by_id["CVE-2099-0008"].kev
    assert by_id["CVE-2099-0001"].description.startswith("Sentetik")   # İngilizce açıklama seçildi


# ------------------------------------------------------------ bulgu
SVC = {"service": "ssh", "product": "OpenSSH", "version": "6.6.1p1 Ubuntu 2ubuntu2.13",
       "extrainfo": "Ubuntu Linux; protocol 2.0", "cpe": ["cpe:/a:openbsd:openssh:6.6.1p1"]}


def test_finding_kev_bumps_and_distro_note():
    f = vuln.to_finding("45.33.32.156", "tcp/22", SVC, SSH, vuln.matching_cves(NVD["vulnerabilities"], SSH))
    assert f.severity == "critical" and f.key == "cve/tcp/22"
    assert f.data["count"] == 5 and f.data["kev"] == ["CVE-2099-0008"]
    assert f.data["distro_build"] and "backport" in f.data["note"]
    assert "5 bilinen CVE" in f.title and "KEV" in f.title


def test_finding_kev_bumps_high_to_critical():
    cves = [vuln.CveInfo("CVE-2099-1", 7.5, "HIGH", "3.1", "", True, "")]
    assert vuln.to_finding("h", "tcp/1", {}, SSH, cves).severity == "critical"
    cves = [vuln.CveInfo("CVE-2099-1", 5.0, "MEDIUM", "3.1", "", True, "")]
    assert vuln.to_finding("h", "tcp/1", {}, SSH, cves).severity == "high"


def test_finding_without_cves():
    f = vuln.to_finding("h", "tcp/22", SVC, SSH, [])
    assert f.severity == "info" and "bulunamadı" in f.title


# ------------------------------------------------------------ NVD istemcisi
class FakeFetch:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        return self.pages[len(self.calls) - 1]


def test_client_paginates_and_caches(tmp_path):
    v = NVD["vulnerabilities"]
    fetch = FakeFetch([{"totalResults": 12, "vulnerabilities": v[:7]},
                       {"totalResults": 12, "vulnerabilities": v[7:]}])
    sleeps = []
    c = vuln.NvdClient(cache_dir=tmp_path, api_key="", fetch=fetch, sleep=sleeps.append)
    got, cached = c.product_cves(SSH)
    assert len(got) == 12 and not cached and len(fetch.calls) == 2
    assert "virtualMatchString=cpe%3A2.3%3Aa%3Aopenbsd%3Aopenssh%3A%2A" in fetch.calls[0][0]
    assert "startIndex=7" in fetch.calls[1][0] and fetch.calls[0][1] == {}
    assert sleeps and sleeps[0] > 5   # anahtarsız: ~6 sn bekleme

    got2, cached2 = c.product_cves(vuln.Product("a", "openbsd", "openssh", "9.0p1"))
    assert cached2 and len(got2) == 12 and len(fetch.calls) == 2   # aynı ürün: önbellek


def test_client_ttl_and_refresh(tmp_path):
    fetch = FakeFetch([{"totalResults": 0, "vulnerabilities": []}] * 3)
    c = vuln.NvdClient(cache_dir=tmp_path, api_key="k", fetch=fetch, sleep=lambda s: None)
    c.product_cves(SSH)
    c.product_cves(SSH, refresh=True)
    assert len(fetch.calls) == 2 and fetch.calls[0][1] == {"apiKey": "k"}
    path = next(tmp_path.iterdir())
    data = json.loads(path.read_text())
    data["fetched_at"] = time.time() - vuln.CACHE_TTL - 1
    path.write_text(json.dumps(data))
    c.product_cves(SSH)
    assert len(fetch.calls) == 3   # süresi dolan önbellek yenilendi


def test_run_groups_products_and_skips(tmp_path):
    fetch = FakeFetch([NVD, {"totalResults": 0, "vulnerabilities": []}])
    c = vuln.NvdClient(cache_dir=tmp_path, api_key="k", fetch=fetch, sleep=lambda s: None)
    services = [
        ("10.0.0.1", "tcp/22", SVC),
        ("10.0.0.2", "tcp/22", SVC),                                    # aynı ürün: tek NVD isteği
        ("10.0.0.1", "tcp/80", {"service": "http", "version": "2.4.7", "cpe": ["cpe:/a:apache:http_server:2.4.7"]}),
        ("10.0.0.1", "tcp/9929", {"service": "nping-echo", "cpe": []}),
    ]
    res = vuln.run(services, c)
    assert len(fetch.calls) == 2
    assert [f.key for f in res.findings] == ["cve/tcp/22", "cve/tcp/22", "cve/tcp/80"]
    assert len(res.skipped) == 1 and "nping-echo" in res.skipped[0]


def test_run_reports_errors(tmp_path):
    def boom(url, headers):
        raise vuln.VulnError("NVD istek sınırı aşıldı")
    c = vuln.NvdClient(cache_dir=tmp_path, api_key="k", fetch=boom, sleep=lambda s: None)
    res = vuln.run([("h", "tcp/22", SVC)], c)
    assert res.findings == [] and "sınırı" in res.errors[0]


# ------------------------------------------------------------ CLI uçtan uca
def test_cli_vuln_from_network_scan(tmp_path, monkeypatch, capsys):
    scope = tmp_path / "scope.yml"
    scope.write_text("name: lab\ntargets:\n  hosts: [45.33.32.156]\n", encoding="utf-8")
    db = tmp_path / "sw.db"
    hosts = network.parse_xml((FIX / "nmap_scanme.xml").read_text(encoding="utf-8"))
    with Storage(db) as s:
        sid = s.start_scan("lab", ["network"], ["45.33.32.156"])
        s.add_findings(sid, network.to_findings(hosts))
        s.finish_scan(sid)

    empty = {"totalResults": 0, "vulnerabilities": []}
    fetch = FakeFetch([NVD, empty])    # openssh, apache
    monkeypatch.setattr(cli, "make_nvd", lambda: vuln.NvdClient(cache_dir=tmp_path / "c", api_key="k",
                                                                fetch=fetch, sleep=lambda s: None))
    assert main(["-s", str(scope), "--db", str(db), "vuln"]) == 0
    out, err = capsys.readouterr()
    assert "Kaynak: ağ taraması #1, 4 servis" in err
    assert "Atlandı" in err and "nping-echo" in err
    assert "CVE-2099-0008" in out and "KEV" in out and "backport" in out
    assert "bilinen CVE bulunamadı" in out    # apache, boş sonuç

    assert main(["-s", str(scope), "--db", str(db), "show"]) == 0
    assert "CVE-2099-0001" in capsys.readouterr().out


def test_cli_vuln_without_network_scan(tmp_path, monkeypatch):
    scope = tmp_path / "scope.yml"
    scope.write_text("name: lab\ntargets:\n  hosts: [10.0.0.1]\n", encoding="utf-8")
    monkeypatch.setattr(cli, "make_nvd", lambda: vuln.NvdClient(cache_dir=tmp_path, api_key="k",
                                                                fetch=lambda u, h: {}, sleep=lambda s: None))
    assert main(["-s", str(scope), "--db", str(tmp_path / "x.db"), "vuln"]) == 2

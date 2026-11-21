from pathlib import Path

import pytest

from surfacewatch.cli import main
from surfacewatch.core import Finding, Storage
from surfacewatch.core.diff import diff_findings, diff_scans, find_previous
from surfacewatch.core.storage import ScanRecord
from surfacewatch.modules import network
from surfacewatch.report import render_html

FIX = Path(__file__).parent / "fixtures"
SCANME = (FIX / "nmap_scanme.xml").read_text(encoding="utf-8")


def rec(i, targets, modules=("network",)):
    return ScanRecord(i, "lab", f"2026-11-2{i}T10:00:00+00:00", None, list(modules), list(targets), "done")


def f(target="10.0.0.1", key="tcp/22", sev="info", **data):
    return Finding(target, "network", key, f"{key} açık", sev, data or {"version": "1.0"})


# ------------------------------------------------------------ diff mantığı
def test_new_resolved_changed_unchanged():
    old = [f(key="tcp/22", version="6.6"), f(key="tcp/80"), f(key="tcp/21", sev="medium")]
    new = [f(key="tcp/22", version="9.6"), f(key="tcp/80"), f(key="tcp/3306", sev="high")]
    d = diff_findings(rec(1, ["10.0.0.1"]), old, rec(2, ["10.0.0.1"]), new)
    assert [x.key for x in d.new] == ["tcp/3306"]
    assert [x.key for x in d.resolved] == ["tcp/21"]
    (ch,) = d.changed
    assert ch.fields == {"version": ("6.6", "9.6")}
    assert d.unchanged == 1 and d.worst_new() == "high"


def test_severity_change_is_reported():
    d = diff_findings(rec(1, ["10.0.0.1"]), [f(sev="low")], rec(2, ["10.0.0.1"]), [f(sev="high")])
    (ch,) = d.changed
    assert ch.fields["severity"] == ("low", "high") and ch.severity_delta > 0
    assert d.worst_new() == "high"


def test_improvement_does_not_trigger_worst_new():
    d = diff_findings(rec(1, ["10.0.0.1"]), [f(sev="high")], rec(2, ["10.0.0.1"]), [f(sev="low")])
    assert d.changed and d.worst_new() is None


def test_not_rescanned_targets_are_not_resolved():
    old = [f(target="10.0.0.1"), f(target="10.0.0.2")]
    new = [f(target="10.0.0.1")]
    d = diff_findings(rec(1, ["10.0.0.0/24"]), old, rec(2, ["10.0.0.1"]), new)
    assert d.resolved == [] and d.not_rescanned == 1


def test_cidr_scan_covers_ips():
    old = [f(target="10.0.0.1"), f(target="10.0.0.2")]
    d = diff_findings(rec(1, ["10.0.0.0/24"]), old, rec(2, ["10.0.0.0/24"]), [f(target="10.0.0.1")])
    assert [x.target for x in d.resolved] == ["10.0.0.2"]


def test_no_changes():
    d = diff_findings(rec(1, ["10.0.0.1"]), [f()], rec(2, ["10.0.0.1"]), [f()])
    assert not d.has_changes and d.unchanged == 1


# ------------------------------------------------------------ önceki taramayı bulma
def test_find_previous_matches_scope_modules_and_targets(tmp_path):
    with Storage(tmp_path / "db") as db:
        def add(scope, mods, targets, status="done"):
            i = db.start_scan(scope, list(mods), list(targets))
            db.finish_scan(i, status)
            return i
        a = add("lab", ["network"], ["10.0.0.1"])
        add("lab", ["osint"], ["lab.example"])           # farklı modül
        add("other", ["network"], ["10.0.0.1"])           # farklı kapsam
        add("lab", ["network"], ["10.9.9.9"])             # örtüşmeyen hedef
        add("lab", ["network"], ["10.0.0.1"], "failed")   # başarısız
        b = add("lab", ["network"], ["10.0.0.0/24"])      # CIDR, önceki IP'yi kapsıyor
        assert find_previous(db, db.get_scan(b)).id == a
        assert find_previous(db, db.get_scan(a)) is None
        assert diff_scans(db, a) is None
        with pytest.raises(ValueError):
            diff_scans(db, 999)


# ------------------------------------------------------------ CLI: watch / diff
@pytest.fixture
def env(tmp_path, monkeypatch):
    scope = tmp_path / "scope.yml"
    scope.write_text("name: lab\ntargets:\n  hosts: [45.33.32.156]\n", encoding="utf-8")
    outputs = []
    monkeypatch.setattr(network, "run_nmap", lambda cmd, timeout=900: outputs.pop(0))
    base = ["-s", str(scope), "--db", str(tmp_path / "sw.db")]
    return base, outputs, tmp_path


# 2. tarama: 3306 açıldı, SSH güncellendi, 9929 kapandı
CHANGED = (SCANME
           .replace('version="6.6.1p1 Ubuntu 2ubuntu2.13"', 'version="9.6p1 Ubuntu 3ubuntu13.5"')
           .replace('<cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe>', '<cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>')
           .replace('<port protocol="tcp" portid="9929"><state state="open"',
                    '<port protocol="tcp" portid="9929"><state state="closed"')
           .replace('</ports>', '<port protocol="tcp" portid="3306"><state state="open"/>'
                                '<service name="mysql" product="MySQL" version="5.5.62"/></port></ports>'))


def test_watch_first_run_then_changes(env, capsys):
    base, outputs, _ = env
    outputs += [SCANME, SCANME, CHANGED]
    assert main(base + ["watch", "45.33.32.156", "-q"]) == 0
    assert "İlk tarama" in capsys.readouterr().out

    assert main(base + ["watch", "45.33.32.156", "-q"]) == 0
    assert "Değişiklik yok" in capsys.readouterr().out

    rc = main(base + ["watch", "45.33.32.156", "-q"])
    out = capsys.readouterr().out
    assert rc == 1   # mysql yeni ve high -> --fail-on medium tetiklendi
    assert "YENİ" in out and "3306" in out
    assert "DEĞİŞTİ" in out and "9.6p1" in out
    assert "KAPANDI" in out and "9929" in out
    assert "1 yeni, 1 değişen, 1 kapanan" in out


def test_diff_command_and_fail_on(env, capsys):
    base, outputs, _ = env
    outputs += [SCANME, CHANGED]
    main(base + ["scan", "45.33.32.156"])
    main(base + ["scan", "45.33.32.156"])
    capsys.readouterr()
    assert main(base + ["diff"]) == 0                         # --fail-on yoksa her zaman 0
    assert "3306" in capsys.readouterr().out
    assert main(base + ["diff", "--fail-on", "high"]) == 1
    assert main(base + ["diff", "--fail-on", "critical"]) == 0
    assert main(base + ["diff", "2", "1"]) == 0
    assert main(base + ["diff", "1"]) == 0
    assert "önceki tarama yok" in capsys.readouterr().out
    assert main(base + ["diff", "99"]) == 2


# ------------------------------------------------------------ rapor
XSS = '<script>alert(1)</script>'


def test_report_html_contents_and_escaping(env, capsys):
    base, outputs, tmp_path = env
    evil = SCANME.replace('product="Apache httpd"', f'product="Apache {XSS.replace("<", "&lt;").replace(">", "&gt;")}"')
    outputs += [SCANME, evil]
    main(base + ["scan", "45.33.32.156"])
    main(base + ["scan", "45.33.32.156"])
    with Storage(tmp_path / "sw.db") as db:
        sid = db.start_scan("lab", ["vuln"], ["45.33.32.156"])
        db.add_findings(sid, [Finding("45.33.32.156", "vuln", "cve/tcp/22", "OpenSSH: 2 bilinen CVE", "critical",
                                      {"port": "tcp/22", "count": 2, "note": "backport notu",
                                       "cves": [{"id": "CVE-2099-0001", "score": 9.8, "kev": True,
                                                 "description": f"satır\nsonu {XSS}"}]},
                                      ["T1190"], "Güncelle")])
        db.finish_scan(sid)
    out = tmp_path / "r.html"
    assert main(base + ["report", "-o", str(out)]) == 0
    html = out.read_text(encoding="utf-8")
    assert XSS not in html and "&lt;script&gt;" in html
    assert "default-src 'none'" in html and "<script" not in html.lower()
    assert "CVE-2099-0001" in html and "KEV" in html and "backport notu" in html
    assert "Değişiklikler: tarama #1" in html            # iki ağ taraması arasında diff bölümü
    assert "attack.mitre.org/techniques/T1190/" in html
    assert "Bilinen zafiyetler" in html and "Ağ servisleri" in html


def test_report_specific_scans_and_errors(env):
    base, outputs, tmp_path = env
    outputs += [SCANME]
    main(base + ["scan", "45.33.32.156"])
    out = tmp_path / "x.html"
    assert main(base + ["report", "--scans", "1", "-o", str(out), "--include-info"]) == 0
    assert "OpenSSH" in out.read_text(encoding="utf-8")
    assert main(base + ["report", "--scans", "42", "-o", str(out)]) == 2


def test_report_empty_scope(tmp_path):
    scope = tmp_path / "s.yml"
    scope.write_text("name: empty\ntargets:\n  hosts: [10.0.0.1]\n", encoding="utf-8")
    assert main(["-s", str(scope), "--db", str(tmp_path / "x.db"), "report", "-o", str(tmp_path / "r.html")]) == 2


def test_render_html_direct():
    sc = rec(1, ["10.0.0.1"])
    html = render_html("lab", [(sc, [f(sev="high")])], [])
    assert "Öncelikli bulgular" in html and "tcp/22 açık" in html

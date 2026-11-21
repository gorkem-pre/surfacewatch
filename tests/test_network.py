from pathlib import Path

import pytest

from surfacewatch.cli import main
from surfacewatch.core import Storage
from surfacewatch.modules import network

FIXTURE = (Path(__file__).parent / "fixtures" / "nmap_scanme.xml").read_text(encoding="utf-8")


# ------------------------------------------------------------ komut
def test_command_basic(monkeypatch):
    monkeypatch.setattr(network, "is_root", lambda: False)
    cmd = network.build_command("45.33.32.156", max_rate=50)
    assert cmd[:3] == ["nmap", "-sT", "-sV"]
    assert ["--max-rate", "50"] == cmd[cmd.index("--max-rate"):cmd.index("--max-rate") + 2]
    assert "--top-ports" in cmd and cmd[-1] == "45.33.32.156"
    assert "-6" not in cmd


def test_command_root_uses_syn(monkeypatch):
    monkeypatch.setattr(network, "is_root", lambda: True)
    assert network.build_command("10.0.0.1")[1] == "-sS"


def test_command_ipv6_ports_noping(monkeypatch):
    monkeypatch.setattr(network, "is_root", lambda: False)
    cmd = network.build_command("2600:3c01::1", ports="22,80,8000-8100", no_ping=True)
    assert "-6" in cmd and "-Pn" in cmd
    assert cmd[cmd.index("-p") + 1] == "22,80,8000-8100"
    assert "--top-ports" not in cmd


def test_command_cidr():
    assert network.build_command("192.168.56.0/28")[-1] == "192.168.56.0/28"


@pytest.mark.parametrize("bad", [
    "scanme.nmap.org",          # hostname yok: IP sabitlenmeli (TOCTOU)
    "-oN /tmp/x",               # seçenek enjeksiyonu
    "1.2.3.4; rm -rf /",        # komut enjeksiyonu
])
def test_command_rejects_non_ip(bad):
    with pytest.raises(ValueError):
        network.build_command(bad)


@pytest.mark.parametrize("bad", ["0", "70000", "22,abc", "1-2-3", "22;id", ""])
def test_command_rejects_bad_ports(bad):
    with pytest.raises(ValueError):
        network.build_command("10.0.0.1", ports=bad)


def test_unknown_profile():
    with pytest.raises(ValueError):
        network.build_command("10.0.0.1", profile="insane")


# ------------------------------------------------------------ parse
def test_parse_xml():
    (host,) = network.parse_xml(FIXTURE)
    assert host.address == "45.33.32.156" and host.state == "up"
    ssh = next(s for s in host.services if s.port == 22)
    assert ssh.name == "ssh" and ssh.product == "OpenSSH"
    assert ssh.version.startswith("6.6.1p1")
    assert "cpe:/a:openbsd:openssh:6.6.1p1" in ssh.cpe


def test_parse_invalid_xml():
    with pytest.raises(network.NmapError):
        network.parse_xml("<nmaprun><host>")


def test_findings_only_open_ports_with_knowledge():
    findings = network.to_findings(network.parse_xml(FIXTURE), hostname="scanme.nmap.org")
    keys = {f.key for f in findings}
    assert keys == {"tcp/22", "tcp/80", "tcp/9929", "tcp/31337"}  # filtered 25 yok
    ssh = next(f for f in findings if f.key == "tcp/22")
    assert "T1046" in ssh.mitre and "T1021.004" in ssh.mitre
    assert "PasswordAuthentication" in ssh.remediation
    assert ssh.data["hostname"] == "scanme.nmap.org"
    unknown = next(f for f in findings if f.key == "tcp/9929")
    assert unknown.severity == "low" and unknown.mitre == ["T1046"]


def test_https_from_ssl_tunnel():
    xml = ('<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
           '<port protocol="tcp" portid="443"><state state="open"/>'
           '<service name="http" tunnel="ssl" product="nginx"/></port></ports></host></nmaprun>')
    (f,) = network.to_findings(network.parse_xml(xml))
    assert f.data["service"] == "https"


def test_run_nmap_missing_binary():
    with pytest.raises(network.NmapError, match="bulunamadı"):
        network.run_nmap(["nmap-kesinlikle-yok", "-V"])


# ------------------------------------------------------------ CLI uçtan uca (nmap taklit)
@pytest.fixture
def scope_file(tmp_path):
    p = tmp_path / "scope.yml"
    p.write_text(
        "name: t\n"
        "targets:\n  hosts: [45.33.32.156, '2600:3c01::f03c:91ff:fe18:bb2f']\n"
        "  domains:\n    - {name: scanme.nmap.org, include_subdomains: false}\n"
        "options:\n  max_rate: 50\n", encoding="utf-8")
    return p


def test_cli_scan_end_to_end(tmp_path, scope_file, monkeypatch, capsys):
    calls = []

    def fake_run(cmd, timeout=900):
        calls.append(cmd)
        return FIXTURE

    monkeypatch.setattr(network, "run_nmap", fake_run)
    db = tmp_path / "sw.db"
    rc = main(["-s", str(scope_file), "--db", str(db), "scan", "45.33.32.156", "8.8.8.8", "-v"])
    assert rc == 0
    assert len(calls) == 1                         # 8.8.8.8 kapsam dışı → hiç taranmadı
    assert calls[0][-1] == "45.33.32.156"
    assert "50" in calls[0]                        # scope max_rate uygulandı
    out, err = capsys.readouterr()
    assert "ATLANDI 8.8.8.8" in err
    assert "tcp/22" in out and "PasswordAuthentication" in out

    with Storage(db) as s:
        (scan,) = s.list_scans()
        assert scan.status == "done"
        assert len(s.findings(scan.id)) == 4

    assert main(["-s", str(scope_file), "--db", str(db), "show"]) == 0
    assert "OpenSSH" in capsys.readouterr().out


def test_cli_scan_domain_uses_resolved_ip(tmp_path, scope_file, monkeypatch):
    from surfacewatch.core import scope as scope_mod
    monkeypatch.setattr(scope_mod, "resolve_host",
                        lambda h: ["45.33.32.156", "2600:3c01::f03c:91ff:fe18:bb2f"])
    calls = []
    monkeypatch.setattr(network, "run_nmap", lambda cmd, timeout=900: calls.append(cmd) or FIXTURE)
    db = str(tmp_path / "sw.db")

    assert main(["-s", str(scope_file), "--db", db, "scan", "scanme.nmap.org"]) == 0
    assert [c[-1] for c in calls] == ["45.33.32.156"]        # hostname değil IP; IPv6 varsayılan atlanır

    calls.clear()
    assert main(["-s", str(scope_file), "--db", db, "scan", "scanme.nmap.org", "--ipv6"]) == 0
    assert len(calls) == 2 and "-6" in calls[1]


def test_cli_scan_nothing_in_scope(tmp_path, scope_file):
    assert main(["-s", str(scope_file), "--db", str(tmp_path / "x.db"), "scan", "8.8.8.8"]) == 2


def test_cli_scan_nmap_failure_marks_failed(tmp_path, scope_file, monkeypatch):
    def boom(cmd, timeout=900):
        raise network.NmapError("Failed to resolve")
    monkeypatch.setattr(network, "run_nmap", boom)
    db = tmp_path / "sw.db"
    assert main(["-s", str(scope_file), "--db", str(db), "scan", "45.33.32.156"]) == 2
    with Storage(db) as s:
        assert s.list_scans()[0].status == "failed"


# ------------------------------------------------------------ -Pn varsayılanı ve şüpheli sonuç
def test_single_ip_defaults_to_no_ping():
    assert "-Pn" in network.build_command("45.33.32.156")
    assert "-Pn" not in network.build_command("45.33.32.156", no_ping=False)


def test_cidr_keeps_host_discovery():
    assert "-Pn" not in network.build_command("192.168.56.0/28")
    assert "-Pn" in network.build_command("192.168.56.0/28", no_ping=True)


# VirtualBox NAT senaryosu: keşif NAT'tan 190 µs'de cevap aldı, portlar filtered göründü
NAT_FALSE_NEGATIVE = (
    '<nmaprun><host><status state="up" reason="conn-refused"/>'
    '<address addr="45.33.32.156" addrtype="ipv4"/>'
    '<ports><extraports state="filtered" count="998"/>'
    '<port protocol="tcp" portid="22"><state state="filtered"/><service name="ssh" method="table"/></port>'
    '<port protocol="tcp" portid="80"><state state="filtered"/><service name="http" method="table"/></port>'
    '</ports><times srtt="190" rttvar="5000" to="100000"/></host></nmaprun>'
)


def test_suspicious_nat_rtt():
    (h,) = network.parse_xml(NAT_FALSE_NEGATIVE)
    assert h.count("filtered") == 1000 and h.count("open") == 0
    assert h.rtt_us == 190
    assert "NAT" in h.suspicious and "--no-ping" in h.suspicious


def test_suspicious_host_down():
    xml = '<nmaprun><host><status state="down"/><address addr="10.0.0.9" addrtype="ipv4"/></host></nmaprun>'
    (h,) = network.parse_xml(xml)
    assert "yanıt vermedi" in h.suspicious


def test_not_suspicious_when_ports_open():
    (h,) = network.parse_xml(FIXTURE)
    assert h.suspicious is None and h.count("closed") == 996


def test_cli_prints_host_summary_and_warning(tmp_path, scope_file, monkeypatch, capsys):
    monkeypatch.setattr(network, "run_nmap", lambda cmd, timeout=900: NAT_FALSE_NEGATIVE)
    assert main(["-s", str(scope_file), "--db", str(tmp_path / "x.db"), "scan", "45.33.32.156"]) == 0
    err = capsys.readouterr().err
    assert "0 açık, 1000 filtreli" in err
    assert "[!]" in err and "NAT" in err


def test_cli_ping_flags(tmp_path, scope_file, monkeypatch):
    calls = []
    monkeypatch.setattr(network, "run_nmap", lambda cmd, timeout=900: calls.append(cmd) or FIXTURE)
    db = str(tmp_path / "x.db")
    main(["-s", str(scope_file), "--db", db, "scan", "45.33.32.156"])
    main(["-s", str(scope_file), "--db", db, "scan", "45.33.32.156", "--ping"])
    assert "-Pn" in calls[0] and "-Pn" not in calls[1]

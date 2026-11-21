import pytest

from surfacewatch.core import Finding, Storage


def f(key="tcp/22", **kw) -> Finding:
    base = dict(target="192.168.56.10", module="network", key=key, title="SSH açık",
                data={"service": "ssh", "version": "OpenSSH 9.6"}, mitre=["T1021.004"],
                remediation="Parola girişini kapat")
    base.update(kw)
    return Finding(**base)


def test_roundtrip(tmp_path):
    with Storage(tmp_path / "db.sqlite") as db:
        sid = db.start_scan("lab", ["network"], ["192.168.56.0/24"])
        db.add_findings(sid, [f(), f("tcp/80", title="HTTP açık", data={"service": "http"})])
        db.finish_scan(sid)

        scan = db.get_scan(sid)
        assert scan.status == "done" and scan.finished_at
        got = db.findings(sid)
        assert [x.key for x in got] == ["tcp/22", "tcp/80"]
        assert got[0].data["version"] == "OpenSSH 9.6"
        assert got[0].mitre == ["T1021.004"]


def test_last_completed_ignores_running_and_other_scopes(tmp_path):
    with Storage(tmp_path / "db.sqlite") as db:
        a = db.start_scan("lab", [], []); db.finish_scan(a)
        b = db.start_scan("lab", [], []); db.finish_scan(b)
        db.start_scan("lab", [], [])                     # bitmemiş
        o = db.start_scan("other", [], []); db.finish_scan(o)
        assert [s.id for s in db.last_completed("lab")] == [b, a]


def test_duplicate_finding_in_same_scan_is_replaced(tmp_path):
    with Storage(tmp_path / "db.sqlite") as db:
        sid = db.start_scan("lab", [], [])
        db.add_findings(sid, [f(), f(data={"service": "ssh", "version": "OpenSSH 9.7"})])
        (only,) = db.findings(sid)
        assert only.data["version"] == "OpenSSH 9.7"


def test_fingerprint_tracks_data_changes():
    assert f().fingerprint == f().fingerprint
    assert f().fingerprint != f(data={"service": "ssh", "version": "OpenSSH 9.7"}).fingerprint


def test_invalid_severity():
    with pytest.raises(ValueError):
        f(severity="urgent")

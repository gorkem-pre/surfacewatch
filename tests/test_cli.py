from surfacewatch.cli import main


def test_init_show_check(tmp_path, capsys):
    scope = str(tmp_path / "scope.yml")
    assert main(["-s", scope, "init"]) == 0
    assert main(["-s", scope, "init"]) == 2          # üzerine yazmaz
    assert main(["-s", scope, "init", "--force"]) == 0

    assert main(["-s", scope, "scope", "show"]) == 0
    assert "192.168.56.0/24" in capsys.readouterr().out

    assert main(["-s", scope, "scope", "check", "192.168.56.10"]) == 0
    assert main(["-s", scope, "scope", "check", "192.168.56.10", "8.8.8.8"]) == 1
    out = capsys.readouterr().out
    assert "İZİN" in out and "RED" in out


def test_missing_scope(tmp_path, capsys):
    assert main(["-s", str(tmp_path / "yok.yml"), "scope", "show"]) == 2
    assert "surfacewatch init" in capsys.readouterr().err


def test_scans_empty(tmp_path, capsys):
    assert main(["--db", str(tmp_path / "x.db"), "scans"]) == 0
    assert "Henüz tarama yok" in capsys.readouterr().out

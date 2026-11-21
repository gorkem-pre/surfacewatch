"""Diff motoru (blue modu): iki tarama arasında ne değişti?

Bulgular (target, module, key) kimliğiyle eşleştirilir:
  * new       : yeni taramada var, eskide yok     -> ör. yeni açılan port
  * resolved  : eskide var, yenide yok            -> ör. kapatılan port, düzeltilen header
  * changed   : ikisinde de var ama içerik farklı -> ör. sürüm değişti, NS kayıtları değişti
  * unchanged : aynı

"resolved" için bir kural: eski bulgunun hedefi yeni taramada hiç
taranmadıysa bulgu kapanmış SAYILMAZ. Aksi halde sadece bir IP'yi tekrar
taramak, diğer tüm IP'lerin bulgularını "düzeltildi" gösterirdi.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from .models import SEVERITIES, Finding
from .storage import ScanRecord, Storage

_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Change:
    old: Finding
    new: Finding
    fields: dict[str, tuple[Any, Any]]   # alan -> (eski, yeni)

    @property
    def severity_delta(self) -> int:
        return _ORDER[self.new.severity] - _ORDER[self.old.severity]


@dataclass
class DiffResult:
    old_scan: ScanRecord
    new_scan: ScanRecord
    new: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    changed: list[Change] = field(default_factory=list)
    unchanged: int = 0
    not_rescanned: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.resolved or self.changed)

    def worst_new(self) -> str | None:
        """Yeni ya da kötüleşen bulgular içinde en yüksek önem."""
        pool = [f.severity for f in self.new] + [c.new.severity for c in self.changed if c.severity_delta > 0]
        return max(pool, key=_ORDER.__getitem__) if pool else None


def _covered(target: str, scanned: list[str]) -> bool:
    if target in scanned:
        return True
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False
    for s in scanned:
        try:
            if ip in ipaddress.ip_network(s, strict=False):
                return True
        except ValueError:
            continue
    return False


def _data_changes(old: dict, new: dict) -> dict[str, tuple[Any, Any]]:
    return {k: (old.get(k), new.get(k)) for k in sorted(set(old) | set(new)) if old.get(k) != new.get(k)}


def diff_findings(old_scan: ScanRecord, old: list[Finding], new_scan: ScanRecord,
                  new: list[Finding]) -> DiffResult:
    res = DiffResult(old_scan, new_scan)
    old_map = {f.identity: f for f in old}
    new_map = {f.identity: f for f in new}

    for ident, f in new_map.items():
        o = old_map.get(ident)
        if o is None:
            res.new.append(f)
        elif o.fingerprint != f.fingerprint or o.severity != f.severity:
            fields = _data_changes(o.data, f.data)
            if o.severity != f.severity:
                fields["severity"] = (o.severity, f.severity)
            res.changed.append(Change(o, f, fields))
        else:
            res.unchanged += 1

    for ident, o in old_map.items():
        if ident in new_map:
            continue
        if _covered(o.target, new_scan.targets):
            res.resolved.append(o)
        else:
            res.not_rescanned += 1

    key = lambda f: (-_ORDER[f.severity], f.target, f.module, f.key)  # noqa: E731
    res.new.sort(key=key)
    res.resolved.sort(key=key)
    res.changed.sort(key=lambda c: (-c.severity_delta, key(c.new)))
    return res


def find_previous(db: Storage, scan: ScanRecord) -> ScanRecord | None:
    """Aynı kapsam ve modüllerle yapılmış, hedefleri örtüşen bir önceki başarılı tarama."""
    for cand in db.list_scans(scope_name=scan.scope_name, limit=200):
        if cand.id >= scan.id or cand.status != "done" or sorted(cand.modules) != sorted(scan.modules):
            continue
        if set(cand.targets) & set(scan.targets) or any(_covered(t, scan.targets) for t in cand.targets):
            return cand
    return None


def diff_scans(db: Storage, new_id: int, old_id: int | None = None) -> DiffResult | None:
    new_scan = db.get_scan(new_id)
    if new_scan is None:
        raise ValueError(f"Tarama #{new_id} bulunamadı")
    old_scan = db.get_scan(old_id) if old_id is not None else find_previous(db, new_scan)
    if old_scan is None:
        return None
    return diff_findings(old_scan, db.findings(old_scan.id), new_scan, db.findings(new_scan.id))

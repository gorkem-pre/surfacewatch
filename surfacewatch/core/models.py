"""Tüm modüllerin ürettiği ortak bulgu modeli."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    """Bir tarama modülünün tek bulgusu.

    `key`, aynı bulgunun farklı taramalarda tanınmasını sağlar: ör. port
    modülü için "tcp/22". Diff motoru (target, module, key) üçlüsüyle iki
    taramayı karşılaştırır; `data` değişmişse bulgu "değişti" sayılır.
    """

    target: str
    module: str
    key: str
    title: str
    severity: str = "info"
    data: dict[str, Any] = field(default_factory=dict)
    mitre: list[str] = field(default_factory=list)   # red: saldırgan ne yapabilir
    remediation: str = ""                            # blue: nasıl kapatılır

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"Geçersiz severity: {self.severity}")

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.target, self.module, self.key)

    @property
    def fingerprint(self) -> str:
        """data içeriğinin hash'i; sürüm/banner değişimini yakalar."""
        blob = json.dumps(self.data, sort_keys=True, default=str).encode()
        return hashlib.sha256(blob).hexdigest()[:16]

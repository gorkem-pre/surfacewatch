"""Kapsam (scope) kontrolü.

Aracın en önemli güvenlik katmanı: scope.yml içinde açıkça izin verilmeyen
hiçbir hedefe aktif tarama yapılmaz.

Kurallar:
  1. `exclude` her şeyi ezer. Hariç tutulan IP/ağ/domain asla taranmaz.
  2. IP adresi, `networks` içindeki bir ağa veya `hosts` listesine düşmeli.
  3. Domain, `domains` listesinde olmalı. `include_subdomains: true` ise alt
     alan adları da kapsamdadır.
  4. Domain kapsamda olsa bile AKTİF tarama (port tarama vb.) için çözümlenen
     IP'lerin de kapsamda olması gerekir. Sebep: alt alan adları sıklıkla
     üçüncü taraf sunuculara (CDN, SaaS, hosting) işaret eder. O sunucular
     senin değildir; domain'in sana ait olması o IP'yi taramana izin vermez.
     Bu kontrolü kapatmak için `allow_unscoped_resolution: true` gerekir.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str], list[str]]


class ScopeError(ValueError):
    """scope.yml geçersiz."""


class TargetType(str, Enum):
    IP = "ip"
    NETWORK = "network"
    DOMAIN = "domain"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    target: str
    reason: str
    resolved: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.allowed


@dataclass
class DomainRule:
    name: str
    include_subdomains: bool = True

    def matches(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if host == self.name:
            return True
        return self.include_subdomains and host.endswith("." + self.name)


@dataclass
class Scope:
    networks: list[IPNetwork] = field(default_factory=list)
    domains: list[DomainRule] = field(default_factory=list)
    exclude_networks: list[IPNetwork] = field(default_factory=list)
    exclude_domains: list[DomainRule] = field(default_factory=list)
    allow_unscoped_resolution: bool = False
    max_rate: int = 100          # nmap --max-rate (paket/sn); hedefi yormamak için
    name: str = "default"

    # ----------------------------------------------------------- yükleme
    @classmethod
    def from_dict(cls, data: dict) -> Scope:
        if not isinstance(data, dict):
            raise ScopeError("scope.yml bir sözlük (mapping) olmalı")
        targets = data.get("targets") or {}
        exclude = data.get("exclude") or []
        options = data.get("options") or {}

        nets: list[IPNetwork] = []
        for raw in list(targets.get("networks") or []) + list(targets.get("hosts") or []):
            nets.append(_parse_network(raw))

        domains = [_parse_domain(d) for d in targets.get("domains") or []]

        ex_nets: list[IPNetwork] = []
        ex_domains: list[DomainRule] = []
        for raw in exclude:
            kind = classify(str(raw))
            if kind in (TargetType.IP, TargetType.NETWORK):
                ex_nets.append(_parse_network(raw))
            else:
                ex_domains.append(DomainRule(_norm_domain(str(raw)), include_subdomains=True))

        scope = cls(
            networks=nets,
            domains=domains,
            exclude_networks=ex_nets,
            exclude_domains=ex_domains,
            allow_unscoped_resolution=bool(options.get("allow_unscoped_resolution", False)),
            max_rate=int(options.get("max_rate", 100)),
            name=str(data.get("name", "default")),
        )
        if not 1 <= scope.max_rate <= 5000:
            raise ScopeError("options.max_rate 1-5000 arasında olmalı")
        if not scope.networks and not scope.domains:
            raise ScopeError("Kapsamda hiç hedef yok (targets.networks / hosts / domains)")
        for net in scope.networks:
            if net.num_addresses > 65536:
                raise ScopeError(
                    f"{net} çok geniş (>{65536} adres). Lab için /16'dan küçük ağ kullan."
                )
        return scope

    @classmethod
    def load(cls, path: Path) -> Scope:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ScopeError(f"Kapsam dosyası bulunamadı: {path} (surfacewatch init)") from exc
        except yaml.YAMLError as exc:
            raise ScopeError(f"scope.yml YAML hatası: {exc}") from exc
        return cls.from_dict(data)

    # ----------------------------------------------------------- kontrol
    def _ip_excluded(self, ip: IPAddress) -> bool:
        return any(ip in n for n in self.exclude_networks)

    def _ip_in_scope(self, ip: IPAddress) -> bool:
        return any(ip in n for n in self.networks) and not self._ip_excluded(ip)

    def _domain_excluded(self, host: str) -> bool:
        return any(r.matches(host) for r in self.exclude_domains)

    def _domain_in_scope(self, host: str) -> bool:
        return any(r.matches(host) for r in self.domains) and not self._domain_excluded(host)

    def check(self, target: str, active: bool = True, resolver: Resolver | None = None) -> Decision:
        """Hedefin taranıp taranamayacağına karar verir.

        active=False: pasif işlemler (CT log, DNS sorgusu). Sadece domain kuralı.
        active=True : hedefe paket gönderen işlemler. IP kapsamı da zorunlu.
        """
        target = target.strip()
        kind = classify(target)

        if kind == TargetType.IP:
            ip = ipaddress.ip_address(target)
            if self._ip_excluded(ip):
                return Decision(False, target, "exclude listesinde")
            if self._ip_in_scope(ip):
                return Decision(True, target, "IP kapsamda")
            return Decision(False, target, "IP hiçbir kapsam ağında değil")

        if kind == TargetType.NETWORK:
            net = ipaddress.ip_network(target, strict=False)
            if any(net.overlaps(x) for x in self.exclude_networks):
                return Decision(False, target, "ağ, exclude edilen bir aralıkla çakışıyor")
            if any(net.subnet_of(n) for n in self.networks if n.version == net.version):
                return Decision(True, target, "ağ tamamen kapsamda")
            return Decision(False, target, "ağın tamamı kapsamda değil")

        host = _norm_domain(target)
        if self._domain_excluded(host):
            return Decision(False, host, "domain exclude listesinde")
        if not self._domain_in_scope(host):
            return Decision(False, host, "domain kapsamda değil")
        if not active:
            return Decision(True, host, "domain kapsamda (pasif)")

        resolve = resolver or resolve_host
        try:
            ips = resolve(host)
        except OSError as exc:
            return Decision(False, host, f"çözümlenemedi: {exc}")
        if not ips:
            return Decision(False, host, "DNS kaydı yok")
        if self.allow_unscoped_resolution:
            return Decision(True, host, "domain kapsamda (IP kontrolü kapalı)", tuple(ips))

        outside = [ip for ip in ips if not self._ip_in_scope(ipaddress.ip_address(ip))]
        if outside:
            return Decision(
                False, host,
                f"domain kapsamda ama çözümlenen IP kapsam dışı: {', '.join(outside)} "
                "(üçüncü taraf sunucu olabilir)",
                tuple(ips),
            )
        return Decision(True, host, "domain ve çözümlenen IP'ler kapsamda", tuple(ips))


# --------------------------------------------------------------- yardımcılar
def classify(target: str) -> TargetType:
    try:
        ipaddress.ip_address(target)
        return TargetType.IP
    except ValueError:
        pass
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return TargetType.NETWORK
        except ValueError:
            pass
    return TargetType.DOMAIN


def resolve_host(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def _parse_network(raw: object) -> IPNetwork:
    try:
        return ipaddress.ip_network(str(raw).strip(), strict=False)
    except ValueError as exc:
        raise ScopeError(f"Geçersiz IP/ağ: {raw!r}") from exc


def _norm_domain(raw: str) -> str:
    d = raw.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if "://" in d:
        raise ScopeError(f"Domain'e şema yazma, sadece ad: {raw!r}")
    if not d or " " in d or "/" in d:
        raise ScopeError(f"Geçersiz domain: {raw!r}")
    return d


def _parse_domain(raw: object) -> DomainRule:
    if isinstance(raw, str):
        return DomainRule(_norm_domain(raw), include_subdomains=True)
    if isinstance(raw, dict) and "name" in raw:
        return DomainRule(_norm_domain(str(raw["name"])),
                          include_subdomains=bool(raw.get("include_subdomains", True)))
    raise ScopeError(f"Geçersiz domain girdisi: {raw!r}")

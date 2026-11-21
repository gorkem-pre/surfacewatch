"""Ağ modülü: Nmap ile port ve servis tespiti.

Akış:
  1. Komutu Python listesi olarak kur (shell=True YOK → komut enjeksiyonu yok).
  2. Hedef olarak kapsam kontrolünün çözdüğü IP'yi ver, hostname'i değil.
     Neden? Kapsam kontrolü ile Nmap'in kendi DNS sorgusu arasında DNS kaydı
     değişebilir (TOCTOU / DNS rebinding). IP'yi sabitlemek, kontrol ettiğimiz
     adresin taradığımız adres olmasını garanti eder.
  3. Nmap'in XML çıktısını (-oX -) stdout'tan oku ve parse et.
  4. Her açık port → Finding (servis bilgi tabanından MITRE + remediation).
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from ..core.models import Finding
from .knowledge import lookup

MODULE = "network"

PROFILES: dict[str, list[str]] = {
    "quick": ["--top-ports", "100"],
    "default": ["--top-ports", "1000"],
    "full": ["-p-"],
}


class NmapError(RuntimeError):
    pass


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    cpe: list[str] = field(default_factory=list)

    @property
    def banner(self) -> str:
        return " ".join(x for x in (self.product, self.version, self.extrainfo and f"({self.extrainfo})") if x)


@dataclass
class HostResult:
    address: str
    state: str
    hostnames: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    extra: dict[str, int] = field(default_factory=dict)   # <extraports>: {"filtered": 998, ...}
    rtt_us: int | None = None                              # <times srtt> mikro saniye

    def count(self, state: str) -> int:
        return self.extra.get(state, 0) + sum(1 for s in self.services if s.state == state)

    @property
    def suspicious(self) -> str | None:
        """Sonuç yanlış negatif olabilir mi? Kullanıcıya gösterilecek uyarı."""
        if self.state != "up":
            return "Host yanıt vermedi (kapalı ya da ping'i engelliyor). --no-ping ile tekrar dene."
        if self.count("open") == 0 and self.count("filtered") > 0:
            msg = f"Açık port yok, {self.count('filtered')} port filtreli."
            if self.rtt_us is not None and self.rtt_us < 1000:
                msg += (f" RTT {self.rtt_us} µs: uzak bir host için gerçekçi değil; NAT/proxy cevap "
                        "veriyor olabilir ve zaman aşımları çok kısa ayarlanmış olabilir. --no-ping dene.")
            return msg
        return None


# ------------------------------------------------------------------ komut
def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def build_command(ip: str, profile: str = "default", ports: str | None = None,
                  max_rate: int = 100, no_ping: bool | None = None, nmap: str = "nmap") -> list[str]:
    """Nmap komutunu liste olarak döndürür.

    -sS (SYN) root ister; root değilsek -sT (tam TCP bağlantısı) kullanılır.
    -sV servis/sürüm tespiti. NSE script'leri kasıtlı olarak çalıştırılmaz.

    no_ping=None (varsayılan): tek IP'de -Pn, ağ aralığında host keşfi açık.
      Tek hedef zaten kapsam kontrolünden geçmiş ve "var" kabul ediliyor.
      Host keşfi VirtualBox NAT gibi ortamlarda sahte cevap alıp zaman
      aşımlarını yanlış (çok kısa) ayarlayabiliyor → portlar yanlışlıkla
      "filtered" görünür. Ağ aralığında ise keşif, boş IP'leri tek tek
      tam taramamak için gerekli.
    """
    # IP veya CIDR olmalı; hostname kabul edilmez (ValueError)
    addr = ipaddress.ip_network(ip, strict=False)
    if profile not in PROFILES:
        raise ValueError(f"Bilinmeyen profil: {profile}")

    cmd = [nmap, "-sS" if is_root() else "-sT", "-sV", "--version-light",
           "-T3", "--max-rate", str(max_rate), "-n", "-oX", "-"]
    if addr.version == 6:
        cmd.append("-6")
    if no_ping is None:
        no_ping = addr.num_addresses == 1
    if no_ping:
        cmd.append("-Pn")
    if ports is not None:
        _validate_ports(ports)
        cmd += ["-p", ports]
    else:
        cmd += PROFILES[profile]
    target = str(addr.network_address) if addr.num_addresses == 1 else str(addr)
    # target ipaddress ile doğrulandı: "-" ile başlayamaz, seçenek enjeksiyonu olmaz
    cmd.append(target)
    return cmd


def _validate_ports(ports: str) -> None:
    for part in ports.split(","):
        bounds = part.split("-")
        if len(bounds) > 2 or not all(b.isdigit() and 1 <= int(b) <= 65535 for b in bounds):
            raise ValueError(f"Geçersiz port tanımı: {ports!r} (ör. 22,80,443 veya 1-1024)")


# ------------------------------------------------------------------ çalıştırma
def run_nmap(cmd: list[str], timeout: int = 900) -> str:
    if shutil.which(cmd[0]) is None:
        raise NmapError("nmap bulunamadı (sudo apt install nmap)")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise NmapError(f"nmap {timeout} sn içinde bitmedi") from exc
    if proc.returncode != 0:
        raise NmapError(proc.stderr.strip() or f"nmap çıkış kodu {proc.returncode}")
    return proc.stdout


# ------------------------------------------------------------------ parse
def parse_xml(xml_text: str) -> list[HostResult]:
    """Nmap -oX çıktısını parse eder.

    Banner'lar uzak sunucudan gelir (saldırgan kontrolünde olabilir) ama Nmap
    XML'e yazarken kaçırır; yine de değerleri sadece string olarak kullanıyoruz.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapError(f"nmap XML çıktısı okunamadı: {exc}") from exc

    hosts: list[HostResult] = []
    for h in root.iter("host"):
        addr_el = next((a for a in h.iter("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if addr_el is None:
            continue
        status = h.find("status")
        host = HostResult(
            address=addr_el.get("addr", ""),
            state=status.get("state", "unknown") if status is not None else "unknown",
            hostnames=[n.get("name", "") for n in h.iter("hostname")],
        )
        for ep in h.iter("extraports"):
            st_name = ep.get("state", "")
            host.extra[st_name] = host.extra.get(st_name, 0) + int(ep.get("count", "0"))
        times = h.find("times")
        if times is not None and times.get("srtt", "").isdigit():
            host.rtt_us = int(times.get("srtt"))
        for p in h.iter("port"):
            st = p.find("state")
            svc = p.find("service")
            host.services.append(Service(
                port=int(p.get("portid", "0")),
                protocol=p.get("protocol", "tcp"),
                state=st.get("state", "") if st is not None else "",
                name=svc.get("name", "") if svc is not None else "",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
                extrainfo=svc.get("extrainfo", "") if svc is not None else "",
                tunnel=svc.get("tunnel", "") if svc is not None else "",
                cpe=[c.text or "" for c in svc.iter("cpe")] if svc is not None else [],
            ))
        hosts.append(host)
    return hosts


# ------------------------------------------------------------------ bulgular
def to_findings(hosts: list[HostResult], hostname: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for h in hosts:
        for s in h.services:
            if s.state != "open":
                continue
            name = s.name or "unknown"
            if s.tunnel == "ssl" and name == "http":
                name = "https"
            info = lookup(name)
            title = f"{s.port}/{s.protocol} açık: {name}"
            if s.banner:
                title += f" ({s.banner})"
            findings.append(Finding(
                target=h.address,
                module=MODULE,
                key=f"{s.protocol}/{s.port}",
                title=title,
                severity=info.severity,
                data={
                    "port": s.port, "protocol": s.protocol, "service": name,
                    "product": s.product, "version": s.version, "extrainfo": s.extrainfo,
                    "cpe": s.cpe, "hostname": hostname or "",
                    "note": info.note,
                },
                mitre=sorted(set(["T1046", *info.mitre])),
                remediation=info.remediation,
            ))
    return findings


@dataclass
class ScanResult:
    hosts: list[HostResult]
    findings: list[Finding]
    command: list[str]


def scan(ip: str, hostname: str | None = None, **kwargs) -> ScanResult:
    """IP/CIDR tarar. Kapsam kontrolü ÇAĞIRAN tarafın sorumluluğundadır (cli)."""
    timeout = kwargs.pop("timeout", 900)
    cmd = build_command(ip, **kwargs)
    hosts = parse_xml(run_nmap(cmd, timeout=timeout))
    return ScanResult(hosts=hosts, findings=to_findings(hosts, hostname=hostname), command=cmd)

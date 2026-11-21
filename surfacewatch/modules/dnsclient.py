"""DNS sorgu katmanı.

Modüller doğrudan dnspython'a değil bu arayüze bağlıdır. Böylece testler
gerçek DNS'e çıkmadan sahte bir istemciyle (FakeDns) çalışır.

Tüm sonuçlar düz string olarak normalize edilir:
  A/AAAA  -> "93.184.216.34"
  CNAME   -> "target.example.net"         (sondaki nokta yok)
  MX      -> "10 mail.example.com"
  NS      -> "ns1.example.com"
  TXT     -> "v=spf1 include:_spf.google.com ~all"  (parçalar birleştirilmiş)
  CAA     -> '0 issue "letsencrypt.org"'
"""

from __future__ import annotations

from typing import Protocol


class DnsNXDomain(Exception):
    """İsim hiç yok (NXDOMAIN)."""


class DnsError(Exception):
    """Zaman aşımı, sunucuya ulaşılamadı vb. Sonuç bilinmiyor."""


class DnsClient(Protocol):
    def query(self, name: str, rdtype: str) -> list[str]:
        """Kayıt yoksa [] döner; isim yoksa DnsNXDomain, hata varsa DnsError fırlatır."""
        ...


class DnspythonClient:
    """dnspython tabanlı gerçek istemci (sistemin resolver'ını kullanır)."""

    def __init__(self, lifetime: float = 5.0) -> None:
        try:
            import dns.resolver
        except ImportError as exc:  # pragma: no cover
            raise DnsError("dnspython gerekli: pip install dnspython") from exc

        self._resolver = dns.resolver.Resolver()
        self._lifetime = lifetime

    def query(self, name: str, rdtype: str) -> list[str]:  # pragma: no cover - ağ gerektirir
        import dns.exception
        import dns.resolver

        try:
            answer = self._resolver.resolve(name, rdtype, lifetime=self._lifetime)
        except dns.resolver.NXDOMAIN as exc:
            raise DnsNXDomain(name) from exc
        except dns.resolver.NoAnswer:
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            raise DnsError(f"{name} {rdtype}: {exc.__class__.__name__}") from exc

        out: list[str] = []
        for r in answer:
            if rdtype in ("A", "AAAA"):
                out.append(r.address)
            elif rdtype in ("CNAME", "NS"):
                out.append(r.target.to_text().rstrip("."))
            elif rdtype == "MX":
                out.append(f"{r.preference} {r.exchange.to_text().rstrip('.')}")
            elif rdtype == "TXT":
                out.append(b"".join(r.strings).decode("utf-8", "replace"))
            elif rdtype == "CAA":
                out.append(f'{r.flags} {r.tag.decode()} "{r.value.decode()}"')
            else:
                out.append(r.to_text())
        return out


class FakeDns:
    """Testler için: {(isim, tip): [kayıtlar]} ve NXDOMAIN isim kümesi."""

    def __init__(self, records: dict[tuple[str, str], list[str]] | None = None,
                 nxdomain: set[str] | None = None, errors: set[str] | None = None) -> None:
        self.records = {(n.lower(), t): v for (n, t), v in (records or {}).items()}
        self.nxdomain = {n.lower() for n in (nxdomain or set())}
        self.errors = {n.lower() for n in (errors or set())}
        self.calls: list[tuple[str, str]] = []

    def query(self, name: str, rdtype: str) -> list[str]:
        name = name.lower().rstrip(".")
        self.calls.append((name, rdtype))
        if name in self.errors:
            raise DnsError(f"{name}: timeout")
        if name in self.nxdomain:
            raise DnsNXDomain(name)
        return list(self.records.get((name, rdtype), []))

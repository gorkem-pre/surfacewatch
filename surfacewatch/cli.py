"""SurfaceWatch CLI.

    surfacewatch init                     scope.yml şablonu oluştur
    surfacewatch scope show               kapsamı göster
    surfacewatch scope check <hedef>      hedef taranabilir mi?
    surfacewatch scans                    geçmiş taramalar

    surfacewatch scan <hedef>...          ağ taraması (red)
    surfacewatch osint <domain>...        pasif OSINT: subdomain, SPF/DMARC, DNS
    surfacewatch web <url>... | --from-scan   web yapılandırma kontrolleri
    surfacewatch show [scan_id]           tarama bulgularını göster

watch (blue / diff) komutu Modül 6'da eklenecek.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .core import SEVERITIES, Finding, Scope, ScopeError, Storage, TargetType, classify
from .modules import network, osint, web
from .modules.dnsclient import DnsClient, DnsError, DnspythonClient

SCOPE_TEMPLATE = """\
# SurfaceWatch kapsam dosyası
# Burada olmayan hiçbir hedef taranmaz. Sadece sahibi olduğun ya da
# yazılı izin aldığın sistemleri ekle.

name: home-lab

targets:
  networks:
    - 192.168.56.0/24        # VirtualBox host-only ağı (kendininkine göre düzenle)
  hosts: []                  # tek IP'ler, ör. 10.10.10.5
  domains: []
    # - name: ornek-domainim.com
    #   include_subdomains: true

exclude:
  - 192.168.56.1             # host makinenin kendisi / gateway

options:
  # Kapsamdaki bir domain kapsam dışı bir IP'ye çözülürse (CDN, SaaS)
  # aktif tarama reddedilir. Bunu kapatmak bilinçli bir karar olmalı.
  allow_unscoped_resolution: false
  # Saniyede gönderilecek en fazla paket. Düşük tutmak hem hedefe saygı
  # hem de IDS/IPS'e takılmamak için. scanme.nmap.org için 100 yeterli.
  max_rate: 100
"""


def _load_scope(args: argparse.Namespace) -> Scope:
    return Scope.load(Path(args.scope))


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.scope)
    if path.exists() and not args.force:
        print(f"[!] {path} zaten var (üzerine yazmak için --force)", file=sys.stderr)
        return 2
    path.write_text(SCOPE_TEMPLATE, encoding="utf-8")
    print(f"[+] {path} oluşturuldu. Hedeflerini düzenle, sonra: surfacewatch scope show")
    return 0


def cmd_scope_show(args: argparse.Namespace) -> int:
    s = _load_scope(args)
    print(f"Kapsam: {s.name}")
    for n in s.networks:
        print(f"  + ağ     {n}  ({n.num_addresses} adres)")
    for d in s.domains:
        print(f"  + domain {d.name}{'  (+ alt alan adları)' if d.include_subdomains else ''}")
    for n in s.exclude_networks:
        print(f"  - hariç  {n}")
    for d in s.exclude_domains:
        print(f"  - hariç  {d.name}")
    print(f"  çözümlenen IP kontrolü: {'KAPALI' if s.allow_unscoped_resolution else 'açık'}")
    return 0


def cmd_scope_check(args: argparse.Namespace) -> int:
    s = _load_scope(args)
    color = sys.stdout.isatty()
    worst = 0
    for target in args.targets:
        d = s.check(target, active=not args.passive)
        label = "İZİN" if d.allowed else "RED "
        if color:
            label = f"\033[{'32' if d.allowed else '31'}m{label}\033[0m"
        extra = f"  [{', '.join(d.resolved)}]" if d.resolved else ""
        print(f"{label}  {d.target:<35} {d.reason}{extra}")
        if not d.allowed:
            worst = 1
    return worst


def cmd_scans(args: argparse.Namespace) -> int:
    with Storage(args.db) as db:
        scans = db.list_scans(limit=args.limit)
    if not scans:
        print("Henüz tarama yok.")
        return 0
    print(f"{'ID':>4}  {'KAPSAM':<14} {'BAŞLANGIÇ':<26} {'DURUM':<8} MODÜLLER")
    for sc in scans:
        print(f"{sc.id:>4}  {sc.scope_name:<14} {sc.started_at:<26} {sc.status:<8} {','.join(sc.modules)}")
    return 0


# ---------------------------------------------------------------- scan / show
_SEV_COLOR = {"critical": "1;97;41", "high": "1;91", "medium": "1;93", "low": "94", "info": "90"}


def _sev(sev: str, color: bool) -> str:
    text = f"{sev.upper():<8}"
    return f"\033[{_SEV_COLOR.get(sev, '0')}m{text}\033[0m" if color else text


def _print_network(findings: list[Finding], verbose: bool, color: bool) -> None:
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings = sorted(findings, key=lambda f: (f.target, -order[f.severity], f.data.get("port", 0)))
    print(f"{'ÖNEM':<8}  {'HEDEF':<18} {'PORT':<10} {'SERVİS':<14} SÜRÜM")
    for f in findings:
        d = f.data
        banner = " ".join(x for x in (d.get("product"), d.get("version")) if x)
        print(f"{_sev(f.severity, color)}  {f.target:<18} {f.key:<10} {d.get('service', ''):<14} {banner}")
        _print_details(f, verbose)


def _print_osint(findings: list[Finding], verbose: bool, color: bool) -> None:
    order = {s: i for i, s in enumerate(SEVERITIES)}
    checks = [f for f in findings if not f.key.startswith("subdomain/")]
    subs = [f for f in findings if f.key.startswith("subdomain/")]
    if checks:
        print("E-posta ve DNS")
        for f in sorted(checks, key=lambda f: (f.target, -order[f.severity], f.key)):
            print(f"{_sev(f.severity, color)}  {f.key:<12} {f.title}")
            _print_details(f, verbose)
    if subs:
        live = [f for f in subs if f.data.get("ips")]
        print(f"\nSubdomain'ler ({len(subs)} bulundu, {len(live)} çözülüyor)")
        print(f"{'ÖNEM':<8}  {'İSİM':<38} {'IP':<34} AKTİF TARAMA")
        for f in sorted(subs, key=lambda f: (-order[f.severity], not f.data.get("ips"), f.data["name"])):
            d = f.data
            if not verbose and f.severity == "info" and not d.get("ips"):
                continue  # çözülmeyen eski kayıtlar sadece -v ile
            ips = ", ".join(d.get("ips", [])) or d.get("status", "")
            if len(ips) > 34:
                ips = ips[:31] + "..."
            active = {True: "izin", False: "RED", None: "-"}[d.get("active_scan")]
            print(f"{_sev(f.severity, color)}  {d['name']:<38} {ips:<34} {active}")
            if f.severity != "info" or verbose:
                _print_details(f, verbose, show_title=f.severity != "info")
        hidden = sum(1 for f in subs if f.severity == "info" and not f.data.get("ips"))
        if hidden and not verbose:
            print(f"          (+{hidden} çözülmeyen eski kayıt gizlendi; görmek için -v)")


def _print_web(findings: list[Finding], verbose: bool, color: bool) -> None:
    order = {s: i for i, s in enumerate(SEVERITIES)}
    for target in sorted({f.target for f in findings}):
        group = sorted((f for f in findings if f.target == target), key=lambda f: (-order[f.severity], f.key))
        shown = group if verbose else [f for f in group if f.severity != "info"]
        print(f"{target}  ({len(group)} kontrol, {len(group) - len(shown)} gizli bilgi)" if not verbose
              else target)
        for f in shown:
            print(f"{_sev(f.severity, color)}  {f.title}")
            _print_details(f, verbose)
        if not shown:
            print("          Sorun bulunmadı.")
        print()


def _print_details(f: Finding, verbose: bool, show_title: bool = False) -> None:
    if show_title:
        print(f"          {f.title}")
    if not verbose:
        return
    if f.data.get("note"):
        print(f"          risk   : {f.data['note']}")
    if f.mitre:
        print(f"          MITRE  : {', '.join(f.mitre)}")
    if f.remediation:
        print(f"          düzelt : {f.remediation}")


def print_findings(findings: list[Finding], verbose: bool = False) -> None:
    color = sys.stdout.isatty()
    if not findings:
        print("Bulgu yok.")
        return
    printers = [(network.MODULE, _print_network), (osint.MODULE, _print_osint), (web.MODULE, _print_web)]
    first = True
    for module, printer in printers:
        part = [f for f in findings if f.module == module]
        if part:
            if not first:
                print()
            printer(part, verbose, color)
            first = False
    counts = {s: sum(1 for f in findings if f.severity == s) for s in reversed(SEVERITIES)}
    print("\n" + f"{len(findings)} bulgu  " + "  ".join(f"{k}: {v}" for k, v in counts.items() if v))


def _plan_targets(scope: Scope, targets: list[str], ipv6: bool) -> list[tuple[str, str | None]]:
    """Kapsam kontrolü + taranacak (IP/CIDR, hostname) listesi."""
    plan: list[tuple[str, str | None]] = []
    for t in targets:
        d = scope.check(t, active=True)
        if not d.allowed:
            print(f"[-] ATLANDI {d.target}: {d.reason}", file=sys.stderr)
            continue
        if classify(t) == TargetType.DOMAIN:
            pairs = [(ip, d.target) for ip in d.resolved]
        else:
            pairs = [(d.target, None)]
        for ip, host in pairs:
            if ":" in ip and not ipv6:
                print(f"[i] IPv6 atlandı {ip} (dahil etmek için --ipv6)", file=sys.stderr)
                continue
            plan.append((ip, host))
    return plan


def cmd_scan(args: argparse.Namespace) -> int:
    scope = _load_scope(args)
    plan = _plan_targets(scope, args.targets, args.ipv6)
    if not plan:
        print("[!] Taranacak kapsam içi hedef yok.", file=sys.stderr)
        return 2

    with Storage(args.db) as db:
        scan_id = db.start_scan(scope.name, [network.MODULE], [ip for ip, _ in plan])
        all_findings: list[Finding] = []
        errors = 0
        for ip, host in plan:
            label = f"{host} ({ip})" if host else ip
            print(f"[*] Taranıyor: {label}  profil={args.profile}  max_rate={scope.max_rate}", file=sys.stderr)
            try:
                result = network.scan(ip, hostname=host, profile=args.profile, ports=args.ports,
                                      max_rate=scope.max_rate, no_ping=args.ping_mode)
            except (network.NmapError, ValueError) as exc:
                print(f"[!] {label}: {exc}", file=sys.stderr)
                errors += 1
                continue
            if args.verbose:
                print(f"    $ {' '.join(result.command)}", file=sys.stderr)
            if not result.hosts:
                print(f"[!] {label}: Nmap hiç host raporlamadı (hepsi kapalı/yanıtsız).", file=sys.stderr)
            for h in result.hosts:
                rtt = f", RTT {h.rtt_us / 1000:.1f} ms" if h.rtt_us is not None else ""
                print(f"    {h.address}: {h.state}, {h.count('open')} açık, "
                      f"{h.count('filtered')} filtreli, {h.count('closed')} kapalı{rtt}", file=sys.stderr)
                if h.suspicious:
                    print(f"    [!] {h.suspicious}", file=sys.stderr)
            db.add_findings(scan_id, result.findings)
            all_findings.extend(result.findings)
        status = "failed" if errors == len(plan) else "done"
        db.finish_scan(scan_id, status)

    print(f"\nTarama #{scan_id} ({status})\n")
    print_findings(all_findings, verbose=args.verbose)
    return 2 if status == "failed" else 0


def make_dns() -> DnsClient:
    return DnspythonClient()


def cmd_osint(args: argparse.Namespace) -> int:
    scope = _load_scope(args)
    domains: list[str] = []
    for t in args.domains:
        if classify(t) != TargetType.DOMAIN:
            print(f"[-] ATLANDI {t}: osint domain ister", file=sys.stderr)
            continue
        d = scope.check(t, active=False)
        if not d.allowed:
            print(f"[-] ATLANDI {d.target}: {d.reason}", file=sys.stderr)
            continue
        domains.append(d.target)
    if not domains:
        print("[!] Kapsam içi domain yok.", file=sys.stderr)
        return 2

    try:
        dns = make_dns()
    except DnsError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    def scope_check(name: str, ips: list[str]):
        # Zaten çözülmüş IP'leri kullan; aynı ismi tekrar DNS'e sorma
        return scope.check(name, active=True, resolver=lambda _h: ips)

    with Storage(args.db) as db:
        scan_id = db.start_scan(scope.name, [osint.MODULE], domains)
        all_findings: list[Finding] = []
        for domain in domains:
            print(f"[*] Pasif OSINT: {domain}  (CT: {'kapalı' if args.no_ct else 'crt.sh'})",
                  file=sys.stderr)
            res = osint.run(domain, dns, scope_check=scope_check, use_ct=not args.no_ct,
                            max_subdomains=args.max)
            if res.ct_error:
                print(f"    [!] {res.ct_error} (DNS kontrolleri yine de yapıldı)", file=sys.stderr)
            if res.truncated:
                print(f"    [i] İlk {args.max} isim işlendi (--max ile artır)", file=sys.stderr)
            # Kapsam dışı domain kayıtları (include_subdomains: false) raporda kalır ama
            # aktif tarama izni RED görünür; böylece neyin bulunup neyin taranamayacağı net.
            db.add_findings(scan_id, res.findings)
            all_findings.extend(res.findings)
        db.finish_scan(scan_id)

    print(f"\nTarama #{scan_id} (done)\n")
    print_findings(all_findings, verbose=args.verbose)
    return 0


def make_transport() -> web.HttpTransport:
    return web.HttpTransport()


def _web_targets_from_scan(db: Storage, scan_id: int | None) -> list[tuple[str, str, int, str | None]]:
    """Ağ taramasında bulunan http/https servislerinden web hedefleri üretir."""
    if scan_id is None or scan_id < 0:
        scans = [s for s in db.list_scans(limit=50) if network.MODULE in s.modules and s.status == "done"]
        if not scans:
            raise ScopeError("Ağ taraması bulunamadı; önce: surfacewatch scan <hedef>")
        scan_id = scans[0].id
    out = []
    for f in db.findings(scan_id):
        if f.module != network.MODULE:
            continue
        svc = f.data.get("service", "")
        if svc in ("http", "https", "http-proxy", "https-alt") or svc.startswith("http"):
            scheme = "https" if svc.startswith("https") or f.data.get("tunnel") == "ssl" else "http"
            out.append((scheme, f.data.get("hostname") or f.target, int(f.data["port"]), f.target))
    return out


def cmd_web(args: argparse.Namespace) -> int:
    scope = _load_scope(args)
    planned: list[tuple[str, str, int, str | None]] = []  # scheme, host, port, bilinen ip
    if args.from_scan is not None:
        with Storage(args.db) as db:
            planned += _web_targets_from_scan(db, args.from_scan)
        print(f"[i] Ağ taramasından {len(planned)} web servisi alındı", file=sys.stderr)
    for raw in args.targets:
        try:
            planned += [(sch, h, p, None) for sch, h, p in web.parse_target(raw)]
        except ValueError as exc:
            print(f"[-] {exc}", file=sys.stderr)
    if not planned:
        print("[!] Web hedefi yok (URL ver ya da --from-scan kullan).", file=sys.stderr)
        return 2

    targets: list[web.WebTarget] = []
    for scheme, host, port, known_ip in planned:
        d = scope.check(host, active=True)
        if not d.allowed:
            print(f"[-] ATLANDI {scheme}://{host}:{port}: {d.reason}", file=sys.stderr)
            continue
        if classify(host) == TargetType.IP:
            ip = host
        else:
            ips = [i for i in d.resolved if ":" not in i] or (list(d.resolved) if args.ipv6 else [])
            if known_ip and known_ip in d.resolved:
                ip = known_ip
            elif ips:
                ip = ips[0]
            else:
                print(f"[-] ATLANDI {host}: IPv4 adresi yok (--ipv6)", file=sys.stderr)
                continue
        t = web.WebTarget(scheme, host, ip, port)
        if t not in targets:
            targets.append(t)
    if not targets:
        print("[!] Taranacak kapsam içi web hedefi yok.", file=sys.stderr)
        return 2

    transport = make_transport()
    with Storage(args.db) as db:
        scan_id = db.start_scan(scope.name, [web.MODULE], [t.url for t in targets])
        all_findings: list[Finding] = []
        ok = 0
        for t in targets:
            print(f"[*] Web: {t.url}  (IP {t.ip})", file=sys.stderr)
            res = web.run(t, transport, check_files_enabled=not args.no_files)
            if res.error:
                print(f"    [!] Bağlanılamadı: {res.error}", file=sys.stderr)
                continue
            ok += 1
            print(f"    HTTP {res.status}, {len(res.findings)} kontrol", file=sys.stderr)
            db.add_findings(scan_id, res.findings)
            all_findings.extend(res.findings)
        status = "done" if ok else "failed"
        db.finish_scan(scan_id, status)

    print(f"\nTarama #{scan_id} ({status})\n")
    print_findings(all_findings, verbose=args.verbose)
    return 0 if ok else 2


def cmd_show(args: argparse.Namespace) -> int:
    with Storage(args.db) as db:
        if args.scan_id is None:
            scans = db.list_scans(limit=1)
            if not scans:
                print("Henüz tarama yok.")
                return 0
            scan = scans[0]
        else:
            scan = db.get_scan(args.scan_id)
            if scan is None:
                print(f"[!] Tarama #{args.scan_id} bulunamadı", file=sys.stderr)
                return 2
        findings = db.findings(scan.id)
    print(f"Tarama #{scan.id}  {scan.scope_name}  {scan.started_at}  {scan.status}\n")
    print_findings(findings, verbose=args.verbose)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="surfacewatch",
                                description="Kapsam kontrollü saldırı yüzeyi tarama ve izleme")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-s", "--scope", default="scope.yml", help="Kapsam dosyası (varsayılan: scope.yml)")
    p.add_argument("--db", default="surfacewatch.db", help="SQLite veritabanı")
    sub = p.add_subparsers(dest="command", required=True)

    i = sub.add_parser("init", help="scope.yml şablonu oluştur")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)

    sc = sub.add_parser("scope", help="Kapsam işlemleri")
    scsub = sc.add_subparsers(dest="scope_cmd", required=True)
    show = scsub.add_parser("show", help="Kapsamı göster")
    show.set_defaults(func=cmd_scope_show)
    chk = scsub.add_parser("check", help="Hedef(ler) taranabilir mi?")
    chk.add_argument("targets", nargs="+")
    chk.add_argument("--passive", action="store_true",
                     help="Pasif işlem kontrolü (DNS çözümlemesi gerektirmez)")
    chk.set_defaults(func=cmd_scope_check)

    scn = sub.add_parser("scan", help="Kapsam içi hedeflerde ağ taraması (nmap)")
    scn.add_argument("targets", nargs="+", help="IP, CIDR veya domain")
    scn.add_argument("--profile", choices=list(network.PROFILES), default="default",
                     help="quick=top100, default=top1000, full=tüm portlar")
    scn.add_argument("-p", "--ports", help="Port listesi (ör. 22,80,443 veya 1-1024); profili ezer")
    ping = scn.add_mutually_exclusive_group()
    ping.add_argument("--no-ping", dest="ping_mode", action="store_const", const=True,
                      help="Host keşfini her zaman atla (-Pn). Tek IP'de zaten varsayılan.")
    ping.add_argument("--ping", dest="ping_mode", action="store_const", const=False,
                      help="Host keşfini tek IP'de de zorla")
    scn.set_defaults(ping_mode=None)
    scn.add_argument("--ipv6", action="store_true", help="Çözümlenen IPv6 adreslerini de tara")
    scn.add_argument("-v", "--verbose", action="store_true", help="MITRE ve düzeltme önerilerini göster")
    scn.set_defaults(func=cmd_scan)

    osi = sub.add_parser("osint", help="Pasif OSINT: crt.sh subdomain, SPF/DMARC/CAA, NS/MX")
    osi.add_argument("domains", nargs="+")
    osi.add_argument("--no-ct", action="store_true", help="crt.sh sorgusunu atla (sadece DNS)")
    osi.add_argument("--max", type=int, default=300, help="İşlenecek en fazla subdomain (varsayılan 300)")
    osi.add_argument("-v", "--verbose", action="store_true")
    osi.set_defaults(func=cmd_osint)

    wb = sub.add_parser("web", help="Web yapılandırma kontrolleri (header, TLS, açık dosyalar)")
    wb.add_argument("targets", nargs="*", help="ornek.com, https://ornek.com, 10.0.0.5:8080")
    wb.add_argument("--from-scan", nargs="?", type=int, const=-1, metavar="SCAN_ID",
                    help="Ağ taramasında bulunan http/https servislerini kullan (varsayılan: son tarama)")
    wb.add_argument("--no-files", action="store_true", help="Hassas dosya ve robots.txt kontrolünü atla")
    wb.add_argument("--ipv6", action="store_true")
    wb.add_argument("-v", "--verbose", action="store_true")
    wb.set_defaults(func=cmd_web)

    shw = sub.add_parser("show", help="Bir taramanın bulgularını göster (varsayılan: son)")
    shw.add_argument("scan_id", nargs="?", type=int)
    shw.add_argument("-v", "--verbose", action="store_true")
    shw.set_defaults(func=cmd_show)

    ls = sub.add_parser("scans", help="Geçmiş taramaları listele")
    ls.add_argument("--limit", type=int, default=20)
    ls.set_defaults(func=cmd_scans)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ScopeError as exc:
        print(f"[!] Kapsam hatası: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
